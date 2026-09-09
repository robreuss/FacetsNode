//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var runtimeJob struct {
	sync.Mutex
	state *jobState
}

type boundedBuildLog struct {
	sync.Mutex
	file      *os.File
	remaining int
}

func (w *boundedBuildLog) Write(p []byte) (int, error) {
	w.Lock()
	defer w.Unlock()
	count := len(p)
	keep := count
	if keep > w.remaining {
		keep = w.remaining
	}
	if keep > 0 {
		if _, err := w.file.Write(p[:keep]); err != nil {
			return 0, err
		}
		w.remaining -= keep
	}
	return count, nil
}

// Cancel the whole command group, not just its shell wrapper. BuildKit itself
// is stopped by the fixed recipe's EXIT trap on ordinary failure.
func boundedCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, name, args...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		return unix.Kill(-command.Process.Pid, unix.SIGKILL)
	}
	command.WaitDelay = 5 * time.Second
	return command
}

func startRuntimeJob(c configuration) error {
	if _, err := status(c); err != nil {
		return err
	}
	runtimeJob.Lock()
	defer runtimeJob.Unlock()
	if runtimeJob.state != nil && runtimeJob.state.State == "running" {
		return errors.New("job already running")
	}
	if _, err := os.Stat("/opt/fbd/guest-runtime.sh"); err != nil {
		return errors.New("runtime recipe unavailable")
	}
	runtimeJob.state = &jobState{Operation: "prepareRuntime", State: "running", Step: "installing pinned runtime"}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		// This script is a verified release artifact, not a caller-supplied command.
		prepErr := prepareRuntimeKit(c)
		command := boundedCommand(ctx, "/bin/bash", "/opt/fbd/guest-runtime.sh", "prepare")
		log, err := os.OpenFile("/opt/fbd/runtime-build.log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err == nil && prepErr == nil {
			// Private build output is never included in status or diagnostic exports.
			output := &boundedBuildLog{file: log, remaining: 16 * 1024 * 1024}
			command.Stdout = output
			command.Stderr = output
			err = command.Run()
			log.Close()
		}
		if prepErr != nil {
			err = prepErr
			if log != nil {
				_, _ = log.WriteString("Runtime kit staging failed: " + prepErr.Error() + "\n")
				log.Close()
			}
			if console, e := os.OpenFile("/dev/hvc0", os.O_WRONLY, 0); e == nil {
				_, _ = console.WriteString("FBD runtime kit staging failed: " + prepErr.Error() + "\n")
				console.Close()
			}
		}
		// Build logs contain tool output, not setup/activation credentials. Export
		// only on an explicit developer request; never include them in diagnostics.
		_ = os.MkdirAll(dataRoot+"/staging", 0700)
		if b, e := os.ReadFile("/opt/fbd/runtime-build.log"); e == nil {
			if len(b) > 1024*1024 {
				b = b[len(b)-1024*1024:]
			}
			_ = os.WriteFile(dataRoot+"/staging/buildLog.tar", b, 0600)
		}
		runtimeJob.Lock()
		defer runtimeJob.Unlock()
		runtimeJob.state.State = "succeeded"
		runtimeJob.state.Step = "runtime prepared"
		if err != nil {
			runtimeJob.state.State = "failed"
			runtimeJob.state.Step = "runtime preparation failed; private build log available"
		}
	}()
	return nil
}

func prepareRuntimeKit(c configuration) error {
	expected, exists := c.Artifacts["runtimeKit.tar"]
	if !exists {
		return nil
	}
	if !validHex(expected, 32) {
		return errors.New("invalid runtime kit hash")
	}
	if _, e := os.Stat("/opt/fbd/runtime-kit"); e == nil {
		return nil
	}
	if e := os.MkdirAll("/run/fbd-seed", 0700); e != nil {
		return e
	}
	if e := run("/usr/bin/mount", "-t", "iso9660", "-o", "ro", "/dev/disk/by-id/virtio-fbd-seed", "/run/fbd-seed"); e != nil {
		return e
	}
	defer run("/usr/bin/umount", "/run/fbd-seed")
	sum, size, e := fileHash("/run/fbd-seed/runtimekit.tar")
	if e != nil {
		entries, _ := os.ReadDir("/run/fbd-seed")
		names := []string{}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		return fmt.Errorf("runtime kit unreadable (%v); seed filenames: %v", e, names)
	}
	if sum != expected {
		return errors.New("runtime kit content hash mismatch")
	}
	if size > 512*1024*1024 {
		return errors.New("runtime kit exceeds size budget")
	}
	source, e := os.Open("/run/fbd-seed/runtimekit.tar")
	if e != nil {
		return e
	}
	defer source.Close()
	staging, e := os.MkdirTemp("/opt/fbd", "runtime-kit-")
	if e != nil {
		return e
	}
	if e = extractArchive(source, staging, 512*1024*1024); e != nil {
		return e
	}
	return os.Rename(staging, "/opt/fbd/runtime-kit")
}

func startServiceBuild(c configuration) error {
	if _, err := status(c); err != nil {
		return err
	}
	runtimeJob.Lock()
	defer runtimeJob.Unlock()
	if runtimeJob.state != nil && runtimeJob.state.State == "running" {
		return errors.New("build already running")
	}
	if _, err := os.Stat("/opt/fbd/runtime-ready.json"); err != nil {
		return errors.New("runtime unavailable")
	}
	var a transferArtifact
	b, err := os.ReadFile(dataRoot + "/staging/source.tar.json")
	if err != nil || json.Unmarshal(b, &a) != nil || a.validateSource() != nil {
		return errors.New("committed source unavailable")
	}
	runtimeJob.state = &jobState{Operation: "buildServices", State: "running", Step: "building committed service images"}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
		defer cancel()
		_ = os.WriteFile(dataRoot+"/staging/buildLog.tar", []byte("Verifying committed source archive.\n"), 0600)
		work, err := os.MkdirTemp(dataRoot+"/staging", "build-")
		if err == nil {
			var f *os.File
			f, err = os.Open(dataRoot + "/staging/source.tar")
			if err == nil {
				err = extractSource(f, filepath.Join(work, "source"))
				f.Close()
			}
		}
		if err != nil {
			// Extraction errors contain only bounded structural descriptions, never
			// source content. They must not leave a stale prior job's log on screen.
			_ = os.WriteFile(dataRoot+"/staging/buildLog.tar", []byte("Committed source staging failed: "+err.Error()+"\n"), 0600)
		}
		if err == nil {
			command := boundedCommand(ctx, "/bin/bash", "/opt/fbd/guest-build.sh", work, a.Revision, a.Tree)
			var log *os.File
			log, err = os.OpenFile(dataRoot+"/staging/buildLog.tar", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if err == nil {
				output := &boundedBuildLog{file: log, remaining: 16 * 1024 * 1024}
				command.Stdout = output
				command.Stderr = output
				err = command.Run()
				log.Close()
			}
		}
		stopContext, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		_ = boundedCommand(stopContext, "/usr/bin/docker", "buildx", "stop", "fbd-builder").Run()
		stopCancel()
		if err == nil {
			var produced serviceRelease
			b, readErr := os.ReadFile(filepath.Join(work, "kit/service-release.json"))
			if readErr != nil || json.Unmarshal(b, &produced) != nil {
				err = errors.New("build release record unavailable")
			} else {
				expected := map[string]string{}
				for name, image := range produced.Images {
					expected[name] = image.Digest
				}
				_, err = verifyServiceKit(filepath.Join(work, "kit"), expected)
				if err == nil {
					err = validateBuiltServiceKit(ctx, work, produced)
				}
				if err == nil {
					var record map[string]any
					if json.Unmarshal(b, &record) != nil {
						err = errors.New("invalid acceptance record")
					} else {
						record["acceptance"] = map[string]string{"dockerfileTests": "passed", "ociVerification": "passed", "renderedComposeBoundary": "passed", "ingressConfiguration": "passed", "offlineOnionIdentity": "passed", "serviceRuntime": "not-run", "spacesSync": "not-run"}
						err = writeJSONFile(filepath.Join(work, "kit/service-release.json"), record)
					}
				}
				if err == nil {
					archive := filepath.Join(work, "accepted-serviceKit.tar")
					_, err = privateOutput(ctx, "/usr/bin/tar", "-cf", archive, "-C", filepath.Join(work, "kit"), "images", "recipes", "images.json", "service-release.json")
					if err == nil {
						err = os.Rename(archive, dataRoot+"/staging/serviceKit.tar")
					}
				}
			}
		}
		if err != nil {
			// Only structural appliance errors reach this record. Fixed private
			// command wrappers never include command arguments or configuration.
			if f, e := os.OpenFile(dataRoot+"/staging/buildLog.tar", os.O_APPEND|os.O_WRONLY, 0600); e == nil {
				_, _ = fmt.Fprintln(f, "Build acceptance:", err)
				f.Close()
			}
		}
		runtimeJob.Lock()
		defer runtimeJob.Unlock()
		runtimeJob.state.State = "succeeded"
		runtimeJob.state.Step = "candidate service kit prepared; not installed"
		if err != nil {
			runtimeJob.state.State = "failed"
			runtimeJob.state.Step = "service build failed; export private build log"
		}
	}()
	return nil
}

func runtimeHealth(h *health) {
	runtimeJob.Lock()
	if runtimeJob.state != nil {
		value := *runtimeJob.state
		h.Job = &value
	}
	runtimeJob.Unlock()
	if b, err := os.ReadFile("/opt/fbd/runtime-ready.json"); err == nil {
		_ = json.Unmarshal(b, &h.Runtime)
		if version, e := os.ReadFile("/proc/sys/kernel/osrelease"); e == nil && h.Runtime != nil {
			h.Runtime["kernel"] = strings.TrimSpace(string(version))
		}
	}
}

func jobRunning() bool {
	runtimeJob.Lock()
	defer runtimeJob.Unlock()
	return runtimeJob.state != nil && runtimeJob.state.State == "running"
}
