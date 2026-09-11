//go:build linux

package main

import (
	"errors"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

var applicationSlots = make(chan struct{}, 32)

func openLANApplication(c configuration, operation string) (net.Conn, error) {
	// Reuse the activated-release/storage fence, not its restricted HTTP surface.
	check, err := openManagement(c)
	if err != nil {
		return nil, err
	}
	check.Close()
	path := ""
	switch operation {
	case "openDeviceSyncLAN":
		path = dataRoot + "/management/box-lan.sock"
	case "openGroupSpacesLAN":
		path = dataRoot + "/management/group-lan.sock"
	default:
		return nil, errors.New("unknown application stream")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("application socket unavailable")
	}
	return net.DialTimeout("unix", path, 3*time.Second)
}

func relayLANApplication(host *os.File, application net.Conn) {
	defer func() { host.Close(); application.Close(); <-applicationSlots }()
	unix.SetsockoptTimeval(int(host.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 60})
	unix.SetsockoptTimeval(int(host.Fd()), unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Sec: 60})
	application.SetDeadline(time.Now().Add(time.Hour))
	timer := time.AfterFunc(time.Hour, func() { host.Close(); application.Close() })
	defer timer.Stop()
	completed := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(application, io.LimitReader(host, 1024*1024*1024)); completed <- struct{}{} }()
	go func() { _, _ = io.Copy(host, io.LimitReader(application, 1024*1024*1024)); completed <- struct{}{} }()
	<-completed
	host.Close()
	application.Close()
	<-completed
}
