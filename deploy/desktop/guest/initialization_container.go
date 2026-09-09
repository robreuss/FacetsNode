package main

import (
	"encoding/json"
	"errors"
)

// A name collision alone never authorizes stopping somebody else's container.
// These labels belong only to private, one-shot appliance initialization jobs.
func validateInitializationContainer(b []byte, name, installation, role, image string) error {
	var records []struct {
		Name   string
		Config struct {
			Image  string
			Labels map[string]string
		}
	}
	if len(b) > 1024*1024 || json.Unmarshal(b, &records) != nil || len(records) != 1 {
		return errors.New("initialization container evidence unavailable")
	}
	r := records[0]
	if r.Name != "/"+name || r.Config.Image != image ||
		r.Config.Labels["net.simplyformed.facets.box.installation"] != installation ||
		r.Config.Labels["net.simplyformed.facets.box.initialization"] != role {
		return errors.New("initialization container ownership mismatch")
	}
	return nil
}
