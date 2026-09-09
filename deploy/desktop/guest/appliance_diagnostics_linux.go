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
	output := &boundedBuildLog{file: f, remaining: 1024 * 1024}
	for _, args := range [][]string{
		{"--no-pager", "--lines=300", "--output=short-monotonic", "-u", "fbd-guest", "-u", "fbd-data", "-u", "docker", "-u", "containerd"},
		{"--no-pager", "--lines=200", "--output=short-monotonic", "--dmesg"},
		{"--no-pager", "--lines=100", "--output=short-monotonic", "--dmesg", "--boot=-1"},
	} {
		command := boundedCommand(ctx, "/usr/bin/journalctl", args...)
		command.Stdout, command.Stderr = output, output
		// A first boot has no previous journal. Keep the available evidence.
		_ = command.Run()
	}
	return f.Sync()
}
