//go:build linux

package main

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/robreuss/FacetsNode/internal/applianceprofile"
)

const installedApplianceProfilePath = "/etc/facets-box/profile.json"

func currentApplianceProfile() (applianceprofile.Profile, applianceReleaseBinding, error) {
	profile, digest, err := applianceprofile.ReadWithSHA256(installedApplianceProfilePath)
	if err != nil || profile.Architecture != runtime.GOARCH {
		return profile, applianceReleaseBinding{}, errors.New("appliance profile mismatch")
	}
	return profile, applianceReleaseBinding{
		Architecture:  profile.Architecture,
		ProfileID:     profile.ProfileID,
		ProfileSHA256: digest,
	}, nil
}

func printCurrentApplianceProfile() error {
	profile, binding, err := currentApplianceProfile()
	if err != nil {
		return err
	}
	_, err = fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		binding.ProfileID, binding.Architecture, profile.HostAdapter,
		profile.Runtime.EngineVersion, profile.Runtime.ComposeVersion,
		profile.Runtime.ContainerdVersion, profile.Runtime.DataRoot,
		binding.ProfileSHA256)
	return err
}
