//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Real existing service recipes, new disposable identities and volumes, and no
// Tor or published ports. This is build acceptance, not an installed Box or
// client Spaces Sync acceptance. Only these unique fixture projects are removed.
func validateBuiltServiceRuntime(ctx context.Context, work string, images map[string]string) (result error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	for _, name := range imageNames {
		b, e := privateOutput(ctx, "/usr/bin/docker", "image", "inspect", "--format", "{{.Id}}", images[name])
		if e != nil {
			return fmt.Errorf("fixture image root %s: %w", name, e)
		}
		if strings.TrimSpace(string(b)) != images[name] {
			return fmt.Errorf("fixture image root %s differs from its verified manifest", name)
		}
	}
	root, kit := filepath.Join(work, "runtime-validation"), filepath.Join(work, "kit")
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	id, err := initializeApplianceIdentity(root, uuid.NewString(), strings.Repeat("a", 56)+".onion", strings.Repeat("b", 56)+".onion")
	if err != nil {
		return err
	}
	for _, service := range []string{"device-sync", "shared-spaces"} {
		for _, child := range []string{"keys", "policy", "state"} {
			if err := filepath.Walk(filepath.Join(root, "configuration", service, child), func(path string, info os.FileInfo, e error) error {
				if e != nil {
					return e
				}
				if info.Mode()&os.ModeSymlink != 0 {
					return errors.New("unexpected fixture link")
				}
				return os.Chown(path, 65532, 65532)
			}); err != nil {
				return err
			}
		}
	}
	if err = os.MkdirAll(filepath.Join(root, "management"), 0700); err != nil {
		return err
	}
	d, g, err := serviceEnvironment(root, kit, id, images, true)
	if err != nil {
		return err
	}
	for name, env := range map[string]map[string]string{"device-sync": d, "shared-spaces": g} {
		b, err := encodeEnvironment(env)
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(root, name+".env"), b, 0600); err != nil {
			return err
		}
	}
	projects := map[string]string{deviceProject: "fbd-validation-device-" + uuid.NewString(), sharedProject: "fbd-validation-group-" + uuid.NewString()}
	command := func(kind string, args ...string) ([]byte, error) {
		return composeCommandNamed(ctx, kind, projects[kind], kit, root, args...)
	}
	for _, kind := range []string{deviceProject, sharedProject} {
		b, e := command(kind, "config", "--format", "json")
		if e != nil {
			return e
		}
		if e = validateComposeBoundaryAt(b, kind, projects[kind], images, root, kit); e != nil {
			return e
		}
	}
	// Registered only after both exact rendered project definitions pass audit.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if e := reconcileInitializationContainer(cleanup, projects[deviceProject]+"-controller-initialize", id.InstallationID, "controller", images["box-controller"]); e != nil && result == nil {
			result = e
		}
		for _, kind := range []string{deviceProject, sharedProject} {
			if _, e := composeCommandNamed(cleanup, kind, projects[kind], kit, root, "down", "--volumes", "--timeout", "10"); e != nil && result == nil {
				result = errors.New("disposable service cleanup failed")
			}
		}
	}()
	for _, kind := range []string{deviceProject, sharedProject} {
		databases := []string{"postgres"}
		if kind == deviceProject {
			databases = append(databases, "box-postgres")
		}
		args := append([]string{"up", "--detach", "--no-build", "--no-deps", "--wait", "--wait-timeout", "45"}, databases...)
		if _, err = command(kind, args...); err != nil {
			return fmt.Errorf("fixture %s databases: %w", kind, err)
		}
	}
	first, err := initializeControllerAt(ctx, id, images["box-controller"], projects[deviceProject], kit, root, root)
	if err != nil {
		return fmt.Errorf("fixture controller initialization: %w", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		for _, kind := range []string{deviceProject, sharedProject} {
			services := []string{"server"}
			if kind == deviceProject {
				services = append(services, "controller")
			}
			services = append(services, "onion-ingress")
			args := append([]string{"up", "--detach", "--no-build", "--no-deps", "--wait", "--wait-timeout", "60"}, services...)
			if _, err = command(kind, args...); err != nil {
				return fmt.Errorf("fixture %s service readiness: %w", kind, err)
			}
		}
		retained, e := initializeControllerAt(ctx, id, images["box-controller"], projects[deviceProject], kit, root, root)
		if e != nil || retained != first {
			return errors.New("fixture controller identity was not retained")
		}
		if err = validateFixtureControllerHTTPS(ctx, root, id, attempt == 0); err != nil {
			return err
		}
		if attempt == 0 {
			for _, kind := range []string{deviceProject, sharedProject} {
				if _, err = command(kind, "stop", "--timeout", "10"); err != nil {
					return err
				}
				// Remove stopped containers only; Compose retains the same volumes.
				if _, err = command(kind, "rm", "--force"); err != nil {
					return err
				}
				services := []string{"postgres"}
				if kind == deviceProject {
					services = append(services, "box-postgres")
				}
				if _, err = command(kind, append([]string{"up", "--detach", "--no-build", "--no-deps", "--wait", "--wait-timeout", "45"}, services...)...); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateFixtureControllerHTTPS(ctx context.Context, root string, id applianceIdentity, claim bool) error {
	cert, err := os.ReadFile(filepath.Join(root, "configuration/device-sync/tls/server.crt"))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cert) {
		return errors.New("fixture TLS anchor invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: id.DeviceSync.Onion, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(root, "management/controller.sock"))
		}}
	defer transport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	origin := "https://" + id.DeviceSync.Onion
	get := func(path string) (int, []byte, error) {
		r, e := http.NewRequestWithContext(ctx, "GET", origin+path, nil)
		if e != nil {
			return 0, nil, e
		}
		response, e := client.Do(r)
		if e != nil {
			return 0, nil, errors.New("fixture pinned controller HTTPS failed")
		}
		defer response.Body.Close()
		b, e := io.ReadAll(io.LimitReader(response.Body, 256*1024))
		return response.StatusCode, b, e
	}
	code, body, err := get("/facetsbox/")
	if err != nil || code != 200 {
		return errors.New("fixture management page unavailable")
	}
	if claim {
		csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(body)
		if len(csrf) != 2 {
			return errors.New("fixture management CSRF unavailable")
		}
		values := url.Values{"csrf": {string(csrf[1])}, "activation_code": {id.Secrets["activation"]}, "display_name": {"Build acceptance Box"}, "password": {id.Secrets["device-sync-operator"]}, "password_confirmation": {id.Secrets["device-sync-operator"]}}
		r, err := http.NewRequestWithContext(ctx, "POST", origin+"/facetsbox/claim", strings.NewReader(values.Encode()))
		if err != nil {
			return err
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		response, err := client.Do(r)
		if err != nil {
			return errors.New("fixture private claim failed")
		}
		response.Body.Close()
		if response.StatusCode != http.StatusSeeOther {
			return errors.New("fixture claim was not accepted")
		}
	} else if !strings.Contains(string(body), "Log in") && !strings.Contains(string(body), "login") {
		return errors.New("fixture claimed state was not retained")
	}
	for _, path := range []string{"/facetsbox/device-sync/v1/relay/tenants/test", "/facetsbox/operator", "/v1/management", "/readyz"} {
		code, _, err := get(path)
		if err != nil || code != 404 {
			return errors.New("private management exposed a non-controller route")
		}
	}
	return nil
}
