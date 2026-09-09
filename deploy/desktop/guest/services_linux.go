//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type limitedOutput struct {
	bytes.Buffer
	remaining int
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	if len(p) > b.remaining {
		return 0, errors.New("command output exceeded budget")
	}
	b.remaining -= len(p)
	return b.Buffer.Write(p)
}

// No command arguments or raw stderr become a health/diagnostic error. Some
// fixed infrastructure calls carry generated setup credentials.
func privateOutput(ctx context.Context, program string, args ...string) ([]byte, error) {
	command := boundedCommand(ctx, program, args...)
	out := &limitedOutput{remaining: 1024 * 1024}
	stderr := &limitedOutput{remaining: 128 * 1024}
	command.Stdout, command.Stderr = out, stderr
	if err := command.Run(); err != nil {
		var exited *exec.ExitError
		if errors.As(err, &exited) {
			// Classification only: the original diagnostic can contain credentials
			// or generated environment values and must never be returned/logged.
			category := "unclassified"
			message := strings.ToLower(stderr.String())
			for _, entry := range [][2]string{{"no such image", "image unavailable"}, {"pull access denied", "image pull denied"}, {"is not running", "container not running"}, {"is unhealthy", "container unhealthy"}, {"dependency failed", "dependency failed"}, {"invalid reference format", "invalid image reference"}, {"permission denied", "permission denied"}, {"no space left", "storage full"}, {"already in use", "name or socket already in use"}, {"timeout", "operation timeout"}, {"unknown flag", "unsupported command option"}, {"has no container to start", "container unavailable"}} {
				if strings.Contains(message, entry[0]) {
					category = entry[1]
					break
				}
			}
			return nil, fmt.Errorf("private appliance operation failed (exit %d; %s)", exited.ExitCode(), category)
		}
		return nil, errors.New("private appliance operation failed")
	}
	return out.Bytes(), nil
}

func prepareServiceKit(c configuration) (serviceRelease, error) {
	var release serviceRelease
	expected := c.Artifacts["serviceKit.tar"]
	if !validHex(expected, 32) || len(c.ServiceImages) != len(imageNames) {
		return release, errors.New("service release evidence unavailable")
	}
	const destination = "/opt/fbd/service-kit"
	if _, err := os.Stat(destination); os.IsNotExist(err) {
		if err = os.MkdirAll("/run/fbd-seed", 0700); err != nil {
			return release, err
		}
		if err = run("/usr/bin/mount", "-t", "iso9660", "-o", "ro", "/dev/disk/by-id/virtio-fbd-seed", "/run/fbd-seed"); err != nil {
			return release, err
		}
		defer run("/usr/bin/umount", "/run/fbd-seed")
		path := "/run/fbd-seed/servicekit.tar"
		sum, size, err := fileHash(path)
		if err != nil || sum != expected || size <= 0 || size > 8*1024*1024*1024 {
			return release, errors.New("service kit verification failed")
		}
		f, err := os.Open(path)
		if err != nil {
			return release, err
		}
		defer f.Close()
		staging, err := os.MkdirTemp("/opt/fbd", "service-kit-")
		if err != nil {
			return release, err
		}
		if err = extractArchive(f, staging, 8*1024*1024*1024); err != nil {
			return release, err
		}
		if err = os.Rename(staging, destination); err != nil {
			return release, err
		}
	} else if err != nil {
		return release, err
	}
	release, err := verifyServiceKit(destination, c.ServiceImages)
	if err != nil {
		return release, err
	}
	if release.SourceRevision != c.ServiceSourceRevision || release.SourceTree != c.ServiceSourceTree {
		return release, errors.New("service source evidence mismatch")
	}
	return release, nil
}

func importServiceImages(ctx context.Context, release serviceRelease) (map[string]string, error) {
	images := map[string]string{}
	for _, name := range imageNames {
		image := release.Images[name]
		archive := "/opt/fbd/import-" + name + ".tar"
		if _, err := privateOutput(ctx, "/usr/bin/tar", "-cf", archive, "-C", "/opt/fbd/service-kit/images/"+name, "oci-layout", "index.json", "blobs"); err != nil {
			return nil, fmt.Errorf("archive verified %s image: %w", name, err)
		}
		if _, err := privateOutput(ctx, "/usr/bin/docker", "image", "load", "--input", archive); err != nil {
			return nil, fmt.Errorf("import verified %s image: %w", name, err)
		}
		// Only the exact verified manifest can be used in a deployment; tags in
		// the portable archive are never launch authority.
		b, err := privateOutput(ctx, "/usr/bin/docker", "image", "inspect", "--platform", "linux/arm64", "--format", "{{.Id}}", image.Digest)
		if err != nil || strings.TrimSpace(string(b)) != image.Digest {
			return nil, errors.New("imported image identity mismatch")
		}
		images[name] = image.Digest
		// This is an intermediate archive made above, not retained rollback data.
		if err = os.Remove(archive); err != nil {
			return nil, err
		}
	}
	return images, nil
}

func volumeDirectory(ctx context.Context, name string, allowCreate bool) (string, error) {
	b, err := privateOutput(ctx, "/usr/bin/docker", "volume", "inspect", "--format", "{{.Mountpoint}}", name)
	if err != nil && allowCreate {
		if _, err = privateOutput(ctx, "/usr/bin/docker", "volume", "create", name); err != nil {
			return "", err
		}
		b, err = privateOutput(ctx, "/usr/bin/docker", "volume", "inspect", "--format", "{{.Mountpoint}}", name)
	}
	if err != nil {
		return "", errors.New("expected persistent volume unavailable")
	}
	path := strings.TrimSpace(string(b))
	if path != filepath.Join(dataRoot, "docker/volumes", name, "_data") {
		return "", errors.New("volume is outside verified persistent storage")
	}
	return path, nil
}

func reconcileInitializationContainer(ctx context.Context, name, installation, role, image string) error {
	// A successful full name listing distinguishes absence from daemon failure.
	b, err := privateOutput(ctx, "/usr/bin/docker", "container", "ls", "--all", "--format", "{{.Names}}")
	if err != nil {
		return err
	}
	found := false
	for _, entry := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if entry == name {
			found = true
		}
	}
	if !found {
		return nil
	}
	b, err = privateOutput(ctx, "/usr/bin/docker", "container", "inspect", name)
	if err != nil {
		return err
	}
	if err = validateInitializationContainer(b, name, installation, role, image); err != nil {
		return err
	}
	if _, err = privateOutput(ctx, "/usr/bin/docker", "stop", "--time", "10", name); err != nil {
		return err
	}
	_, err = privateOutput(ctx, "/usr/bin/docker", "rm", name)
	return err
}

func prepareOnion(ctx context.Context, installation, project, volume, image string, existing bool) (string, error) {
	name := project + "-identity-initialization"
	if err := reconcileInitializationContainer(ctx, name, installation, "onion", image); err != nil {
		return "", err
	}
	root, err := volumeDirectory(ctx, project+"_"+volume, !existing)
	if err != nil {
		return "", err
	}
	read := func() (string, error) {
		id, e := readOnionIdentity(root)
		if e != nil {
			return "", e
		}
		if e = retainOnionIdentity(filepath.Join(dataRoot, project+"-onion-identity.json"), id, !existing); e != nil {
			return "", e
		}
		return id.Onion, nil
	}
	if onion, e := read(); e == nil {
		return onion, nil
	}
	entries, err := os.ReadDir(root)
	if err != nil || existing || len(entries) != 0 {
		return "", errors.New("inconsistent onion storage; identity was not replaced")
	}
	// The image's entrypoint is Tor. Network isolation and DisableNetwork both
	// prevent publishing the new identity before the activation transaction.
	if _, err = privateOutput(ctx, "/usr/bin/docker", "run", "--detach", "--name", name, "--label", "net.simplyformed.facets.box.installation="+installation, "--label", "net.simplyformed.facets.box.initialization=onion", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--log-driver", "none", "--tmpfs", "/tmp:size=32m,mode=1777", "--mount", "type=volume,src="+project+"_"+volume+",dst=/var/lib/tor/facets-onion", image, "--DisableNetwork", "1"); err != nil {
		return "", errors.New("offline onion initialization failed")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = privateOutput(cleanup, "/usr/bin/docker", "stop", "--time", "5", name)
		_, _ = privateOutput(cleanup, "/usr/bin/docker", "rm", name)
	}()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if onion, e := read(); e == nil {
			return onion, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return "", errors.New("offline onion initialization timed out")
}

func writeServiceConfiguration(ctx context.Context, c configuration, images map[string]string, candidate bool) (applianceIdentity, error) {
	var identity applianceIdentity
	_, err := os.Stat(dataRoot + "/configuration")
	existing := err == nil
	if err != nil && !os.IsNotExist(err) {
		return identity, err
	}
	box, err := prepareOnion(ctx, c.InstallationID, deviceProject, "facets-device-sync-onion", images["tor"], existing)
	if err != nil {
		return identity, err
	}
	group, err := prepareOnion(ctx, c.InstallationID, sharedProject, "facets-shared-spaces-onion", images["tor"], existing)
	if err != nil {
		return identity, err
	}
	identity, err = initializeApplianceIdentity(dataRoot, c.InstallationID, box, group)
	if err != nil {
		return identity, err
	}
	for _, service := range []string{"device-sync", "shared-spaces"} {
		for _, child := range []string{"keys", "policy", "state"} {
			if err = filepath.Walk(filepath.Join(dataRoot, "configuration", service, child), func(path string, info os.FileInfo, e error) error {
				if e != nil {
					return e
				}
				if info.Mode()&os.ModeSymlink != 0 {
					return errors.New("unexpected configuration link")
				}
				return os.Chown(path, 65532, 65532)
			}); err != nil {
				return identity, err
			}
		}
	}
	if err = os.MkdirAll(dataRoot+"/management", 0700); err != nil {
		return identity, err
	}
	d, g, err := serviceEnvironment(dataRoot, "/opt/fbd/service-kit", identity, images, candidate)
	if err != nil {
		return identity, err
	}
	for name, env := range map[string]map[string]string{"device-sync": d, "shared-spaces": g} {
		b, e := encodeEnvironment(env)
		if e != nil {
			return identity, e
		}
		if err = os.WriteFile("/opt/fbd/"+name+".env", b, 0600); err != nil {
			return identity, err
		}
	}
	return identity, nil
}

func composeCommand(ctx context.Context, project string, args ...string) ([]byte, error) {
	return composeCommandAt(ctx, project, "/opt/fbd/service-kit", "/opt/fbd", args...)
}

func composeCommandAt(ctx context.Context, project, kit, environmentDirectory string, args ...string) ([]byte, error) {
	return composeCommandNamed(ctx, project, project, kit, environmentDirectory, args...)
}

func composeCommandNamed(ctx context.Context, kindProject, project, kit, environmentDirectory string, args ...string) ([]byte, error) {
	kind := "device-sync"
	if kindProject == sharedProject {
		kind = "shared-spaces"
	} else if kindProject != deviceProject {
		return nil, errors.New("unknown deployment")
	}
	base := []string{"compose", "--project-name", project, "--env-file", filepath.Join(environmentDirectory, kind+".env")}
	for _, suffix := range []string{".compose.yaml", ".onion.yaml", ".desktop.yaml"} {
		base = append(base, "-f", filepath.Join(kit, "recipes", kind+suffix))
	}
	return privateOutput(ctx, "/usr/bin/docker", append(base, args...)...)
}

func validateServiceRecipes(ctx context.Context, images map[string]string) error {
	return validateRecipesAt(ctx, "/opt/fbd/service-kit", "/opt/fbd", images, images["caddy"])
}

func validateRecipesAt(ctx context.Context, kit, environmentDirectory string, images map[string]string, caddy string) error {
	for _, project := range []string{deviceProject, sharedProject} {
		b, err := composeCommandAt(ctx, project, kit, environmentDirectory, "config", "--format", "json")
		if err != nil {
			return fmt.Errorf("render %s: %w", project, err)
		}
		if err = validateComposeBoundary(b, project, images); err != nil {
			return err
		}
	}
	for _, name := range []string{"Box", "Group"} {
		// The pinned Caddy binary carries cap_net_bind_service in its file
		// capabilities. Its bounding set must retain that bit even for `adapt`,
		// otherwise Linux rejects exec. The validation container has no network
		// or published ports; this matches the existing ingress image's needs.
		b, err := privateOutput(ctx, "/usr/bin/docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges=true", "--entrypoint", "/usr/bin/caddy", "--env", "FACETS_ONION_INGRESS_TOKEN=validation-only", "--mount", "type=bind,src="+filepath.Join(kit, "recipes")+",dst=/etc/fbd,readonly", caddy, "adapt", "--config", "/etc/fbd/"+name+".Caddyfile", "--adapter", "caddyfile")
		if err != nil {
			return fmt.Errorf("validate %s ingress recipe: %w", name, err)
		}
		var config struct {
			Apps struct {
				HTTP struct {
					Servers map[string]struct{ Listen []string }
				}
			}
		}
		if json.Unmarshal(b, &config) != nil || len(config.Apps.HTTP.Servers) == 0 {
			return errors.New("invalid ingress configuration")
		}
		for _, server := range config.Apps.HTTP.Servers {
			for _, listener := range server.Listen {
				if !strings.HasPrefix(listener, "unix/") {
					return errors.New("IP application listener rejected")
				}
			}
		}
	}
	return nil
}

// Build-time validation uses disposable fixture identities and renders the
// exact kit recipes. It never creates real service volumes or deploys the Box.
func validateBuiltServiceKit(ctx context.Context, work string, release serviceRelease) error {
	root := filepath.Join(work, "validation")
	if e := os.MkdirAll(root, 0700); e != nil {
		return e
	}
	identity, e := initializeApplianceIdentity(root, "build-validation", strings.Repeat("a", 56)+".onion", strings.Repeat("b", 56)+".onion")
	if e != nil {
		return e
	}
	images := map[string]string{}
	for name, image := range release.Images {
		images[name] = image.Digest
	}
	d, g, e := serviceEnvironment(dataRoot, "/opt/fbd/service-kit", identity, images, true)
	if e != nil {
		return e
	}
	for name, env := range map[string]map[string]string{"device-sync": d, "shared-spaces": g} {
		b, e := encodeEnvironment(env)
		if e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(root, name+".env"), b, 0600); e != nil {
			return e
		}
	}
	// The fixed pulled reference was bound to its ARM64 manifest during export.
	// This validation container has no network, runtime socket or appliance data.
	if err := validateRecipesAt(ctx, filepath.Join(work, "kit"), root, images, "caddy:2.10.2-alpine"); err != nil {
		return err
	}
	if err := validateBuiltOnionIdentity(ctx, images["tor"]); err != nil {
		return err
	}
	return validateBuiltServiceRuntime(ctx, work, images)
}

// A disposable build acceptance test of the actual pinned Tor image. Both runs
// are network-disabled; this neither initializes nor publishes the real Box.
func validateBuiltOnionIdentity(ctx context.Context, image string) (result error) {
	name := "fbd-build-onion-" + uuid.NewString()
	root, err := volumeDirectory(ctx, name, true)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := reconcileInitializationContainer(cleanup, name, "build-validation", "onion", image); err != nil {
			if result == nil {
				result = err
			}
			return
		}
		// Only this test's freshly created, uniquely named volume is removed.
		if _, err := privateOutput(cleanup, "/usr/bin/docker", "volume", "rm", name); err != nil && result == nil {
			result = err
		}
	}()
	var first onionIdentity
	for attempt := 0; attempt < 2; attempt++ {
		if _, err = privateOutput(ctx, "/usr/bin/docker", "run", "--detach", "--name", name,
			"--label", "net.simplyformed.facets.box.installation=build-validation", "--label", "net.simplyformed.facets.box.initialization=onion",
			"--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--log-driver", "none",
			"--tmpfs", "/tmp:size=32m,mode=1777", "--mount", "type=volume,src="+name+",dst=/var/lib/tor/facets-onion", image, "--DisableNetwork", "1"); err != nil {
			return errors.New("offline Tor validation startup failed")
		}
		deadline := time.Now().Add(20 * time.Second)
		valid := false
		for time.Now().Before(deadline) {
			current, err := readOnionIdentity(root)
			if err == nil {
				if attempt == 0 {
					first = current
				} else if current != first {
					return errors.New("offline Tor restart changed identity")
				}
				valid = true
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
		if !valid {
			return errors.New("offline Tor did not produce a consistent identity")
		}
		// Allow the restarted process to finish reading the retained identity,
		// rather than treating pre-existing files alone as proof it started.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		state, err := privateOutput(ctx, "/usr/bin/docker", "container", "inspect", "--format", "{{.State.Running}}", name)
		if err != nil || strings.TrimSpace(string(state)) != "true" {
			return errors.New("offline Tor initialization process exited")
		}
		if err = reconcileInitializationContainer(ctx, name, "build-validation", "onion", image); err != nil {
			return err
		}
		after, err := readOnionIdentity(root)
		if err != nil || after != first {
			return errors.New("offline Tor stop changed identity")
		}
	}
	return nil
}
