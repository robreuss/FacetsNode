package main

import (
	"encoding/json"
	"errors"
)

type serviceActivation struct {
	Version        int    `json:"version"`
	InstallationID string `json:"installationID"`
	ReleaseID      string `json:"releaseID"`
	Phase          string `json:"phase"`
}

func validateManagementActivation(raw []byte, installation, release string) error {
	var state serviceActivation
	if len(raw) > 2048 || json.Unmarshal(raw, &state) != nil || state.Version != 1 || state.InstallationID != installation || state.ReleaseID != release || state.Phase != "active" {
		return errors.New("controller management is not activated")
	}
	return nil
}
