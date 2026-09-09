//go:build linux

// The appliance agent is private root infrastructure. It exposes no IP socket,
// public API, arbitrary command execution, or container specification interface.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const dataRoot = "/srv/facets-box-data"

type configuration struct {
	InstallationID    string `json:"installationID"`
	DataID            string `json:"dataID"`
	ReleaseID         string `json:"releaseID"`
	Key               []byte `json:"key"`
	ActivationPending bool   `json:"activationPending"`
	AllowFormat       bool   `json:"allowFormat"`
}

func load() (configuration, error) {
	var c configuration
	b, err := os.ReadFile("/opt/fbd/installation.json")
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if _, err = uuid.Parse(c.DataID); err != nil {
		return c, err
	}
	if _, err = uuid.Parse(c.InstallationID); err != nil {
		return c, err
	}
	if len(c.Key) != 32 || c.ReleaseID == "" {
		return c, errors.New("invalid installation")
	}
	return c, nil
}
func run(name string, args ...string) error {
	command := exec.Command(name, args...)
	// No secrets, config contents, or subprocess output go into the boot console.
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s failed", name)
	}
	return nil
}
func diskUUID() string {
	data, _ := exec.Command("/usr/sbin/blkid", "-s", "UUID", "-o", "value", "/dev/vdb").Output()
	return strings.TrimSpace(string(data))
}
func prepare(c configuration) error {
	if _, err := os.Stat("/dev/vdb"); err != nil {
		return errors.New("storage unavailable")
	}
	if diskUUID() == "" {
		if !c.AllowFormat {
			return errors.New("expected data filesystem missing")
		}
		if _, err := os.Stat("/opt/fbd/data-initialized"); !os.IsNotExist(err) {
			return errors.New("refusing to replace initialized storage")
		}
		// wipefs recognizes more signatures than blkid's UUID query; never format an unknown nonempty filesystem.
		signatures, err := exec.Command("/usr/sbin/wipefs", "--no-act", "--noheadings", "--output", "TYPE", "/dev/vdb").Output()
		if err != nil || strings.TrimSpace(string(signatures)) != "" {
			return errors.New("unrecognized data disk")
		}
		if err = run("/usr/sbin/mkfs.ext4", "-q", "-U", c.DataID, "-L", "facets-data", "/dev/vdb"); err != nil {
			return err
		}
	}
	if diskUUID() != c.DataID {
		return errors.New("data identity mismatch")
	}
	if err := os.WriteFile("/opt/fbd/data-initialized", []byte(c.DataID), 0600); err != nil {
		return err
	}
	// This runs before mounting and before any workload runtime. Corrected filesystems return 1.
	command := exec.Command("/usr/sbin/e2fsck", "-p", "/dev/vdb")
	if err := command.Run(); err != nil {
		var e *exec.ExitError
		if !errors.As(err, &e) || e.ExitCode() != 1 {
			return errors.New("data filesystem needs repair")
		}
	}
	if err := run("/usr/sbin/resize2fs", "/dev/vdb"); err != nil {
		return err
	}
	if err := os.MkdirAll(dataRoot, 0700); err != nil {
		return err
	}
	if err := run("/usr/bin/mount", "-t", "ext4", "-o", "nodev,nosuid", "/dev/vdb", dataRoot); err != nil {
		return err
	}
	identity := dataRoot + "/installation-id"
	if b, err := os.ReadFile(identity); err == nil {
		if string(b) != c.InstallationID {
			return errors.New("installation identity mismatch")
		}
	} else if os.IsNotExist(err) && c.AllowFormat {
		if err = os.WriteFile(identity, []byte(c.InstallationID), 0600); err != nil {
			return err
		}
		value := make([]byte, 32)
		if _, err = rand.Read(value); err != nil {
			return err
		}
		if err = os.WriteFile(dataRoot+"/sentinel", []byte(hex.EncodeToString(value)), 0600); err != nil {
			return err
		}
	} else {
		return errors.New("installation identity unavailable")
	}
	unix.Sync()
	return nil
}
func status(c configuration) (*health, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(dataRoot, &stat); err != nil || stat.Type != unix.EXT4_SUPER_MAGIC {
		return nil, errors.New("data filesystem unavailable")
	}
	if diskUUID() != c.DataID {
		return nil, errors.New("data identity mismatch")
	}
	id, err := os.ReadFile(dataRoot + "/installation-id")
	if err != nil || string(id) != c.InstallationID {
		return nil, errors.New("installation identity mismatch")
	}
	sentinel, err := os.ReadFile(dataRoot + "/sentinel")
	if err != nil {
		return nil, errors.New("sentinel unavailable")
	}
	return &health{Version: 1, InstallationID: c.InstallationID, DataID: c.DataID, ReleaseID: c.ReleaseID,
		DataMounted: true, FreeBytes: stat.Bavail * uint64(stat.Bsize), TotalBytes: stat.Blocks * uint64(stat.Bsize),
		Sentinel: string(sentinel), Services: map[string]string{}, IngressEnabled: false}, nil
}
func serve(c configuration) error {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: 4050}); err != nil {
		return err
	}
	if err = unix.Listen(fd, 8); err != nil {
		return err
	}
	seen := make(map[string]time.Time)
	for {
		client, address, err := unix.Accept(fd)
		if err != nil {
			continue
		}
		peer, ok := address.(*unix.SockaddrVM)
		if !ok || peer.CID != unix.VMADDR_CID_HOST {
			unix.Close(client)
			continue
		}
		unix.SetsockoptTimeval(client, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5})
		unix.SetsockoptTimeval(client, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Sec: 5})
		file := os.NewFile(uintptr(client), "host-channel")
		line, err := bufio.NewReader(io.LimitReader(file, maximumFrame+1)).ReadBytes('\n')
		if err != nil {
			file.Close()
			continue
		}
		r, err := decodeRequest(line, c.Key)
		if err != nil {
			file.Close()
			continue
		}
		for id, expiry := range seen {
			if time.Now().After(expiry) {
				delete(seen, id)
			}
		}
		if _, exists := seen[r.ID]; exists {
			file.Close()
			continue
		}
		seen[r.ID] = time.Now().Add(10 * time.Minute)
		h, err := status(c)
		reply := response{ID: r.ID, Status: h}
		if err != nil {
			reply.Error = "storage unavailable"
		}
		// Foundation releases have no workloads and never claim service readiness or enable ingress.
		encoded, _ := encodeResponse(reply, c.Key)
		file.Write(encoded)
		file.Close()
		if err == nil && r.Operation == "shutdown" {
			return run("/usr/bin/systemctl", "poweroff", "--no-block")
		}
	}
}
func main() {
	c, err := load()
	if err == nil && len(os.Args) == 2 && os.Args[1] == "prepare" {
		err = prepare(c)
	} else if err == nil {
		err = serve(c)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FBD guest: appliance infrastructure unavailable:", err)
		os.Exit(1)
	}
}
