package main

import (
	"fmt"
	"os"

	"github.com/robreuss/FacetsNode/internal/applianceprofile"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "validate" {
		fmt.Fprintln(os.Stderr, "usage: facets-appliance-profile validate PROFILE.json")
		os.Exit(64)
	}
	profile, err := applianceprofile.Read(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid appliance profile:", err)
		os.Exit(1)
	}
	fmt.Printf("%s %s %s\n", profile.ProfileID, profile.Architecture, profile.HostAdapter)
}
