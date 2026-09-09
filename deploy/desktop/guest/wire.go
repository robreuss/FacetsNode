package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
)

const maximumFrame = 64 * 1024

type frame struct {
	Payload        []byte `json:"payload"`
	Authentication []byte `json:"authentication"`
}
type request struct {
	ID        string            `json:"id"`
	Operation string            `json:"operation"`
	Artifact  *transferArtifact `json:"artifact,omitempty"`
	Offset    int64             `json:"offset,omitempty"`
	Chunk     []byte            `json:"chunk,omitempty"`
}
type response struct {
	ID       string            `json:"id"`
	Status   *health           `json:"status,omitempty"`
	Error    string            `json:"error,omitempty"`
	Artifact *transferArtifact `json:"artifact,omitempty"`
	Chunk    []byte            `json:"chunk,omitempty"`
}
type health struct {
	Version         int               `json:"version"`
	InstallationID  string            `json:"installationID"`
	DataID          string            `json:"dataID"`
	ReleaseID       string            `json:"releaseID"`
	DataMounted     bool              `json:"dataMounted"`
	FreeBytes       uint64            `json:"freeBytes"`
	TotalBytes      uint64            `json:"totalBytes"`
	Sentinel        string            `json:"sentinel"`
	Services        map[string]string `json:"services"`
	IngressEnabled  bool              `json:"ingressEnabled"`
	ServiceMode     string            `json:"serviceMode,omitempty"`
	ServiceIdentity string            `json:"serviceIdentity,omitempty"`
	Runtime         map[string]string `json:"runtime,omitempty"`
	Job             *jobState         `json:"job,omitempty"`
}

type jobState struct {
	Operation string `json:"operation"`
	State     string `json:"state"`
	Step      string `json:"step"`
}

func decodeRequest(data, key []byte) (request, error) {
	var f frame
	var r request
	if len(data) > maximumFrame || json.Unmarshal(data, &f) != nil {
		return r, errors.New("invalid frame")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(f.Payload)
	if !hmac.Equal(mac.Sum(nil), f.Authentication) {
		return r, errors.New("authentication failed")
	}
	if json.Unmarshal(f.Payload, &r) != nil || len(r.ID) != 36 {
		return r, errors.New("invalid request")
	}
	switch r.Operation {
	case "status", "shutdown", "activate", "prepareRuntime", "uploadStart", "uploadChunk", "uploadFinish", "artifactInfo", "artifactRead", "buildServices", "openManagement":
	default:
		return r, errors.New("unknown operation")
	}
	return r, nil
}
func encodeResponse(r response, key []byte) ([]byte, error) {
	payload, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	data, err := json.Marshal(frame{payload, mac.Sum(nil)})
	return append(data, '\n'), err
}
