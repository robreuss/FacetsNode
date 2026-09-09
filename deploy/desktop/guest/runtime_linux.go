//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var runtimeJob struct {
	sync.Mutex
	state *jobState
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
		command := boundedCommand(ctx, "/bin/bash", "/opt/fbd/guest-runtime.sh", "prepare")
		log, err := os.OpenFile("/opt/fbd/runtime-build.log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err == nil {
			// Private build output is never included in status or diagnostic exports.
			command.Stdout = log
			command.Stderr = log
			err = command.Run()
			log.Close()
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
		work, err := os.MkdirTemp(dataRoot+"/staging", "build-")
		if err == nil {
			var f *os.File
			f, err = os.Open(dataRoot + "/staging/source.tar")
			if err == nil {
				err = extractSource(f, filepath.Join(work, "source"))
				f.Close()
			}
		}
		if err == nil {
			command := boundedCommand(ctx, "/bin/bash", "/opt/fbd/guest-build.sh", work, a.Revision, a.Tree)
			var log *os.File
			log, err = os.OpenFile(dataRoot+"/staging/buildLog.tar", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if err == nil {
				command.Stdout = log
				command.Stderr = log
				err = command.Run()
				log.Close()
			}
		}
		stopContext, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		_ = boundedCommand(stopContext, "/usr/bin/docker", "buildx", "stop", "fbd-builder").Run()
		stopCancel()
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
	}
}

func jobRunning() bool {
	runtimeJob.Lock()
	defer runtimeJob.Unlock()
	return runtimeJob.state != nil && runtimeJob.state.State == "running"
}
