//go:build linux

package main

import (
	"context"
	"os"
	"time"
)

// Explicit developer export only. Workload/container logs and configuration
// (including activation codes) are deliberately absent. Capture bounded unit
// journals to explain storage/runtime shutdown without exposing a shell API.
func captureApplianceLog() error {
	if err := os.MkdirAll(dataRoot+"/staging", 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(dataRoot+"/staging/applianceLog.tar", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := boundedCommand(ctx, "/usr/bin/journalctl", "--no-pager", "--lines=300", "--output=short-monotonic", "-u", "fbd-guest", "-u", "fbd-data", "-u", "docker", "-u", "containerd")
	output := &boundedBuildLog{file: f, remaining: 1024 * 1024}
	command.Stdout, command.Stderr = output, output
	if err = command.Run(); err != nil {
		return err
	}
	return f.Sync()
}
