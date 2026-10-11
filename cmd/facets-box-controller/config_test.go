package main

import "testing"

func TestJobCustodyControllerConfigurationIsOptionalButPaired(t *testing.T) {
	t.Setenv("FACETS_BOX_CONTROLLER_DATABASE_URL", "postgres://controller")
	t.Setenv("FACETS_BOX_PUBLIC_URL", "https://box.example/facetsbox")
	t.Setenv("FACETS_DEVICE_SYNC_BOX_CONTROLLER_TOKEN", "token")
	t.Setenv("FACETS_BOX_DEVICE_SYNC_URL", "https://box.example/facetsbox/device-sync")
	t.Setenv("FACETS_BOX_JOB_CUSTODY_PRIVATE_URL", "")
	t.Setenv("FACETS_BOX_JOB_CUSTODY_URL", "")
	configuration, err := loadConfiguration()
	if err != nil || configuration.jobCustodyPrivateURL != "" || configuration.jobCustodyPublicURL != "" {
		t.Fatalf("optional Job Custody configuration=%+v error=%v", configuration, err)
	}

	t.Setenv("FACETS_BOX_JOB_CUSTODY_PRIVATE_URL", "http://job-custody:8080")
	if _, err := loadConfiguration(); err == nil {
		t.Fatal("unpaired private Job Custody URL accepted")
	}
	t.Setenv("FACETS_BOX_JOB_CUSTODY_URL", "https://box.example/facetsbox/job-custody")
	configuration, err = loadConfiguration()
	if err != nil || configuration.jobCustodyPrivateURL != "http://job-custody:8080" ||
		configuration.jobCustodyPublicURL != "https://box.example/facetsbox/job-custody" {
		t.Fatalf("paired Job Custody configuration=%+v error=%v", configuration, err)
	}

	t.Setenv("FACETS_BOX_JOB_CUSTODY_PRIVATE_URL", "")
	if _, err := loadConfiguration(); err == nil {
		t.Fatal("unpaired public Job Custody URL accepted")
	}
}
