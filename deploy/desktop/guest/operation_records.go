package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

var operationRecordsLock sync.Mutex

// Deliberately closed vocabulary: never accept error text, command arguments,
// environment, activation codes, paths or application content as log fields.
func recordOperation(root, release, operation, state string) error {
	if operation != "boot" && operation != "prepareRuntime" && operation != "buildServices" && operation != "shutdown" {
		return errors.New("unknown operational record")
	}
	if state != "started" && state != "succeeded" && state != "failed" {
		return errors.New("unknown operational state")
	}
	if release == "" || len(release) > 100 {
		return errors.New("invalid operational release")
	}
	operationRecordsLock.Lock()
	defer operationRecordsLock.Unlock()
	directory := filepath.Join(root, "operations")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("operational storage unavailable")
	}
	path := filepath.Join(directory, "events.jsonl")
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("invalid operational log")
		}
		if info.Size() >= 256*1024 {
			for index := 3; index >= 1; index-- {
				previous := path
				if index > 1 {
					previous += "." + strconv.Itoa(index-1)
				}
				if err := os.Rename(previous, path+"."+strconv.Itoa(index)); err != nil && !os.IsNotExist(err) {
					return err
				}
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	b, err := json.Marshal(struct {
		Time      string `json:"time"`
		Release   string `json:"release"`
		Operation string `json:"operation"`
		State     string `json:"state"`
	}{time.Now().UTC().Format(time.RFC3339), release, operation, state})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	d, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
