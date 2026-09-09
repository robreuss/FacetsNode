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

var managementSlots = make(chan struct{}, 4)

func openManagement(c configuration) (net.Conn, error) {
	if _, err := status(c); err != nil {
		return nil, err
	}
	b, err := boundedIdentityFile(dataRoot+"/service-activation.json", 2048)
	if err != nil {
		return nil, errors.New("controller management unavailable")
	}
	if err = validateManagementActivation(b, c.InstallationID, c.ReleaseID); err != nil {
		return nil, err
	}
	// No request parameter can select a host, port, path or container. Caddy's
	// separate controller-only listener enforces the reviewed HTTP route surface.
	const path = dataRoot + "/management/controller.sock"
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("controller socket unavailable")
	}
	return net.DialTimeout("unix", path, 3*time.Second)
}

func relayManagement(host *os.File, controller net.Conn) {
	defer func() { host.Close(); controller.Close(); <-managementSlots }()
	// The relay is TLS-opaque. Limit connection age, idle I/O and total bytes;
	// neither credentials nor application traffic enter management logs.
	unix.SetsockoptTimeval(int(host.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 30})
	unix.SetsockoptTimeval(int(host.Fd()), unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Sec: 30})
	controller.SetDeadline(time.Now().Add(5 * time.Minute))
	timer := time.AfterFunc(5*time.Minute, func() { host.Close(); controller.Close() })
	defer timer.Stop()
	finished := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(controller, io.LimitReader(host, 128*1024*1024)); finished <- struct{}{} }()
	go func() { _, _ = io.Copy(host, io.LimitReader(controller, 128*1024*1024)); finished <- struct{}{} }()
	<-finished
	host.Close()
	controller.Close()
	<-finished
}
