//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"sync"
	"time"
)

var runtimeJob struct {
	sync.Mutex
	state *jobState
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
		command := exec.CommandContext(ctx, "/bin/bash", "/opt/fbd/guest-runtime.sh", "prepare")
		log, err := os.OpenFile("/opt/fbd/runtime-build.log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err == nil {
			// Private build output is never included in status or diagnostic exports.
			command.Stdout = log
			command.Stderr = log
			err = command.Run()
			log.Close()
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
