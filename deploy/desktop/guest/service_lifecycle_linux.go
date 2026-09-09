//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

var applianceServices struct {
	sync.Mutex
	mode          string
	identity      string
	states        map[string]string
	checked       time.Time
	monitorCancel context.CancelFunc
}

func serviceHealth(h *health) {
	applianceServices.Lock()
	defer applianceServices.Unlock()
	h.ServiceMode = applianceServices.mode
	h.ServiceIdentity = applianceServices.identity
	h.IngressEnabled = applianceServices.mode == "active" || applianceServices.mode == "activating"
	for name, state := range applianceServices.states {
		if time.Since(applianceServices.checked) > 20*time.Second {
			state = "unavailable"
		}
		h.Services[name] = state
	}
}

func setServiceMode(mode string) {
	applianceServices.Lock()
	defer applianceServices.Unlock()
	if applianceServices.monitorCancel != nil {
		applianceServices.monitorCancel()
		applianceServices.monitorCancel = nil
	}
	applianceServices.mode, applianceServices.states = mode, map[string]string{}
}

// One job owns all deployment mutation. It shares admission with bounded builds
// and runtime preparation; ordinary status remains responsive over virtio.
func startServiceJob(c configuration, activate bool) error {
	if _, err := status(c); err != nil {
		return err
	}
	if len(c.ServiceImages) != len(imageNames) {
		return errors.New("service release unavailable")
	}
	runtimeJob.Lock()
	if runtimeJob.state != nil && runtimeJob.state.State == "running" {
		runtimeJob.Unlock()
		return errors.New("appliance job already running")
	}
	if activate {
		applianceServices.Lock()
		mode := applianceServices.mode
		verified := candidateServicesReady(applianceServices.states) && time.Since(applianceServices.checked) <= 20*time.Second
		applianceServices.Unlock()
		if mode == "active" {
			runtimeJob.Unlock()
			return nil
		}
		if mode != "candidate" || !verified {
			runtimeJob.Unlock()
			return errors.New("candidate has not been verified")
		}
	}
	operation := "prepareServices"
	if activate {
		operation = "activateServices"
	}
	runtimeJob.state = &jobState{Operation: operation, State: "running", Step: "validating installed service release"}
	runtimeJob.Unlock()
	setServiceMode("preparing")
	_ = recordOperation(dataRoot, c.ReleaseID, operation, "started")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		var err error
		if activate {
			err = activateServiceAppliance(ctx, c)
		} else {
			err = prepareServiceAppliance(ctx, c)
		}
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 70*time.Second)
			stopErr := stopServiceContainers(cleanup)
			cancel()
			if stopErr == nil {
				setServiceMode("failed")
			} // Otherwise retain possible-ingress state.
			// Closed infrastructure descriptions only; no raw command/configuration.
			_ = os.WriteFile(dataRoot+"/staging/buildLog.tar", []byte("Appliance service job failed: "+err.Error()+"\n"), 0600)
		}
		runtimeJob.Lock()
		runtimeJob.state = &jobState{Operation: operation, State: "succeeded", Step: "installed service checks complete"}
		if err != nil {
			runtimeJob.state.State = "failed"
			runtimeJob.state.Step = "service setup failed; private appliance log available"
		}
		state := runtimeJob.state.State
		runtimeJob.Unlock()
		_ = recordOperation(dataRoot, c.ReleaseID, operation, state)
	}()
	return nil
}

func prepareServiceAppliance(ctx context.Context, c configuration) error {
	// No old ingress or background activity may survive an agent restart into
	// candidate preparation. On a cold VM boot every workload has restart=no.
	if err := stopServiceContainers(ctx); err != nil {
		return err
	}
	release, err := prepareServiceKit(c)
	if err != nil {
		return err
	}
	images, err := importServiceImages(ctx, release)
	if err != nil {
		return err
	}
	if err = ensureVolumeInventory(dataRoot, c.InstallationID, dockerVolumes{ctx}); err != nil {
		return err
	}
	identity, err := writeServiceConfiguration(ctx, c, images, true)
	if err != nil {
		return err
	}
	if err = validateServiceRecipes(ctx, images); err != nil {
		return err
	}
	for _, project := range []string{deviceProject, sharedProject} {
		databases := []string{"postgres"}
		if project == deviceProject {
			databases = append(databases, "box-postgres")
		}
		if _, err = composeCommand(ctx, project, append([]string{"up", "--detach", "--no-build", "--no-deps", "--wait", "--wait-timeout", "45"}, databases...)...); err != nil {
			return fmt.Errorf("appliance database startup: %w", err)
		}
	}
	controller, err := initializeController(ctx, identity, images["box-controller"])
	if err != nil {
		return err
	}
	if err = retainRunningIdentity(identity, controller); err != nil {
		return err
	}
	if err = startApplicationContainers(ctx, true); err != nil {
		return err
	}
	if err = verifyControllerManagement(ctx, identity); err != nil {
		return err
	}
	states, err := currentServiceHealth(ctx, images, true)
	if err != nil {
		return err
	}
	if !candidateServicesReady(states) {
		return errors.New("candidate service readiness incomplete")
	}
	if err = writeJSONFile(dataRoot+"/service-activation.json", serviceActivation{Version: 1, InstallationID: c.InstallationID, ReleaseID: c.ReleaseID, Phase: "candidate"}); err != nil {
		return err
	}
	startServiceHealthMonitor(images, true, states)
	// A normal cold boot was already authorized by initial installation or a
	// prior activation persisted in this working system. A fresh candidate seed
	// always sets ActivationPending, even when reusing an existing release ID.
	if !c.ActivationPending {
		return activateServiceAppliance(ctx, c)
	}
	return nil
}

func activateServiceAppliance(ctx context.Context, c configuration) error {
	// Authorization is durable before any process starts normal background work.
	// A crash from here can only roll forward, never rewind accepted client data.
	if err := writeJSONFile(dataRoot+"/service-activation.json", serviceActivation{Version: 1, InstallationID: c.InstallationID, ReleaseID: c.ReleaseID, Phase: "authorized"}); err != nil {
		return err
	}
	c.ActivationPending = false
	if err := writeJSONFile("/opt/fbd/installation.json", c); err != nil {
		return err
	}
	setServiceMode("activating")
	if err := stopServiceContainers(ctx); err != nil {
		return err
	}
	identity, err := writeServiceConfiguration(ctx, c, c.ServiceImages, false)
	if err != nil {
		return err
	}
	if err = validateServiceRecipes(ctx, c.ServiceImages); err != nil {
		return err
	}
	for _, project := range []string{deviceProject, sharedProject} {
		databases := []string{"postgres"}
		if project == deviceProject {
			databases = append(databases, "box-postgres")
		}
		if _, err = composeCommand(ctx, project, append([]string{"up", "--detach", "--no-build", "--no-deps", "--wait", "--wait-timeout", "45"}, databases...)...); err != nil {
			return err
		}
	}
	controller, err := initializeController(ctx, identity, c.ServiceImages["box-controller"])
	if err != nil {
		return err
	}
	if err = retainRunningIdentity(identity, controller); err != nil {
		return err
	}
	if err = startApplicationContainers(ctx, false); err != nil {
		return err
	}
	if err = verifyControllerManagement(ctx, identity); err != nil {
		return err
	}
	for _, project := range []string{deviceProject, sharedProject} {
		// Bootstrap is monitored as readiness; blocked Tor never triggers direct
		// fallback and does not prevent local controller administration.
		if _, err = composeCommand(ctx, project, "up", "--detach", "--no-build", "--no-deps", "tor"); err != nil {
			return err
		}
	}
	if err = writeJSONFile(dataRoot+"/service-activation.json", serviceActivation{Version: 1, InstallationID: c.InstallationID, ReleaseID: c.ReleaseID, Phase: "active"}); err != nil {
		return err
	}
	states, err := currentServiceHealth(ctx, c.ServiceImages, false)
	if err != nil {
		return err
	}
	startServiceHealthMonitor(c.ServiceImages, false, states)
	return nil
}

func retainRunningIdentity(identity applianceIdentity, controller controllerIdentity) error {
	fingerprint := serviceIdentityFingerprint(identity, controller)
	applianceServices.Lock()
	defer applianceServices.Unlock()
	if applianceServices.identity != "" && applianceServices.identity != fingerprint {
		return errors.New("service identity changed across activation")
	}
	applianceServices.identity = fingerprint
	return nil
}

func startApplicationContainers(ctx context.Context, candidate bool) error {
	for _, project := range []string{deviceProject, sharedProject} {
		services := []string{"server"}
		if project == deviceProject {
			services = append(services, "controller")
		}
		services = append(services, "onion-ingress")
		if _, err := composeCommand(ctx, project, append([]string{"up", "--detach", "--no-build", "--no-deps", "--wait", "--wait-timeout", "60"}, services...)...); err != nil {
			return err
		}
		if err := probeServiceMode(ctx, project, project, "/opt/fbd/service-kit", "/opt/fbd", candidate); err != nil {
			return err
		}
	}
	return nil
}

func startServiceHealthMonitor(images map[string]string, candidate bool, initial map[string]string) {
	setServiceMode("candidate")
	ctx, cancel := context.WithCancel(context.Background())
	applianceServices.Lock()
	if !candidate {
		applianceServices.mode = "active"
	}
	applianceServices.states, applianceServices.checked, applianceServices.monitorCancel = initial, time.Now(), cancel
	applianceServices.Unlock()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			check, finish := context.WithTimeout(ctx, 10*time.Second)
			states, err := currentServiceHealth(check, images, candidate)
			finish()
			applianceServices.Lock()
			if ctx.Err() == nil {
				if err != nil {
					states = map[string]string{}
					for _, name := range imageNames {
						states[name] = "unavailable"
					}
				}
				applianceServices.states, applianceServices.checked = states, time.Now()
			}
			applianceServices.Unlock()
		}
	}()
}

// The TLS leaf/hostname remain verified even for local Unix-socket access.
// This read-only health probe never handles an activation code or owner cookie.
func verifyControllerManagement(ctx context.Context, identity applianceIdentity) error {
	cert, err := boundedIdentityFile(dataRoot+"/configuration/device-sync/tls/server.crt", 16384)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cert) {
		return errors.New("controller TLS anchor unavailable")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: identity.DeviceSync.Onion, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", dataRoot+"/management/controller.sock")
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for path, want := range map[string]int{"/facetsbox/": 200, "/readyz": 404, "/facetsbox/device-sync/v1/relay/tenants/test": 404} {
		r, err := http.NewRequestWithContext(ctx, "GET", "https://"+identity.DeviceSync.Onion+path, nil)
		if err != nil {
			return errors.New("controller health request invalid")
		}
		response, err := client.Do(r)
		if err != nil {
			return errors.New("pinned controller HTTPS unavailable")
		}
		response.Body.Close()
		if response.StatusCode != want {
			return errors.New("controller management boundary check failed")
		}
	}
	return nil
}
