package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/robreuss/FacetsNode/internal/applianceprofile"
	"github.com/robreuss/FacetsNode/internal/proxmoxadapter"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "plan":
		err = makePlan(os.Args[2:])
	case "review":
		err = reviewPlan(os.Args[2:])
	case "apply":
		err = applyPlan(os.Args[2:])
	case "next-id":
		err = nextID(os.Args[2:])
	case "api-plan":
		err = makeAPIPlan(os.Args[2:])
	case "api-review":
		err = reviewAPIPlan(os.Args[2:])
	case "api-check":
		err = checkAPIPlan(os.Args[2:])
	case "api-apply":
		err = applyAPIPlan(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "facets-proxmox-vm:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: facets-proxmox-vm {plan|review|apply|next-id|api-plan|api-review|api-check|api-apply} [options]")
	os.Exit(64)
}

func makeAPIPlan(arguments []string) error {
	flags := flag.NewFlagSet("api-plan", flag.ContinueOnError)
	profilePath := flags.String("profile", "", "validated Proxmox appliance profile")
	outputPath := flags.String("output", "", "new API plan file")
	endpoint := flags.String("endpoint", "", "pinned PVE HTTPS origin")
	tlsCertificateSHA256 := flags.String("tls-cert-sha256", "", "lowercase SHA-256 of the PVE leaf certificate")
	node := flags.String("node", "", "PVE node name")
	vmID := flags.Int("vmid", 0, "unused PVE VM ID")
	name := flags.String("name", "", "new VM name")
	storage := flags.String("storage", "", "PVE VM storage ID")
	imageStorage := flags.String("image-storage", "", "PVE image-import storage ID")
	bridge := flags.String("bridge", "", "PVE bridge ID")
	adminUser := flags.String("admin-user", "facets-admin", "non-root guest administrator")
	cloudImage := flags.String("cloud-image", "", "local pinned Ubuntu cloud image")
	sshPublicKey := flags.String("ssh-public-key", "", "local Ed25519 public-key path")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid API plan arguments")
	}
	profile, err := applianceprofile.Read(*profilePath)
	if err != nil {
		return err
	}
	imageDigest, err := proxmoxadapter.FileSHA256(*cloudImage, 8*1024*1024*1024)
	if err != nil {
		return fmt.Errorf("cloud image: %w", err)
	}
	keyDigest, err := proxmoxadapter.FileSHA256(*sshPublicKey, 16*1024)
	if err != nil {
		return fmt.Errorf("SSH public key: %w", err)
	}
	plan := proxmoxadapter.NewAPIPlan(profile, *endpoint, *tlsCertificateSHA256, *node, *vmID, *name, *storage, *imageStorage, *bridge, *adminUser,
		proxmoxadapter.FileEvidence{Path: *cloudImage, SHA256: imageDigest},
		proxmoxadapter.FileEvidence{Path: *sshPublicKey, SHA256: keyDigest})
	if err = plan.Validate(profile); err != nil {
		return err
	}
	encoded, err := proxmoxadapter.EncodeAPIPlan(plan)
	if err != nil {
		return err
	}
	if err = writeNewFile(*outputPath, encoded); err != nil {
		return err
	}
	fmt.Println(proxmoxadapter.PlanDigest(encoded))
	return nil
}

func reviewAPIPlan(arguments []string) error {
	plan, err := readAPIPlanFlags("api-review", arguments)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(proxmoxadapter.ReviewAPIPlan(plan))
}

func checkAPIPlan(arguments []string) error {
	plan, tokenID, err := readAPIExecutionFlags("api-check", arguments, false)
	if err != nil {
		return err
	}
	client, err := proxmoxadapter.NewAPIClient(plan.Endpoint, plan.TLSCertificateSHA256, tokenID, os.Getenv("FACETS_PROXMOX_API_TOKEN_SECRET"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if _, err = proxmoxadapter.PreflightAPI(ctx, client, plan); err != nil {
		return err
	}
	fmt.Println("Proxmox API preflight passed")
	return nil
}

func applyAPIPlan(arguments []string) error {
	plan, tokenID, err := readAPIExecutionFlags("api-apply", arguments, true)
	if err != nil {
		return err
	}
	client, err := proxmoxadapter.NewAPIClient(plan.Endpoint, plan.TLSCertificateSHA256, tokenID, os.Getenv("FACETS_PROXMOX_API_TOKEN_SECRET"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	return proxmoxadapter.ApplyAPI(ctx, client, plan, func(message string) {
		fmt.Fprintln(os.Stderr, "facets-proxmox-vm:", message)
	})
}

func readAPIExecutionFlags(name string, arguments []string, requireApproval bool) (proxmoxadapter.APIPlan, string, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	profilePath := flags.String("profile", "", "validated Proxmox appliance profile")
	planPath := flags.String("plan", "", "reviewed API plan file")
	approval := flags.String("approval", "", "exact SHA-256 printed by api-plan")
	tokenID := flags.String("token-id", os.Getenv("FACETS_PROXMOX_API_TOKEN_ID"), "PVE API token ID; secret is read only from FACETS_PROXMOX_API_TOKEN_SECRET")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return proxmoxadapter.APIPlan{}, "", errors.New("invalid Proxmox API execution arguments")
	}
	profile, err := applianceprofile.Read(*profilePath)
	if err != nil {
		return proxmoxadapter.APIPlan{}, "", err
	}
	var plan proxmoxadapter.APIPlan
	if requireApproval {
		plan, err = proxmoxadapter.ReadApprovedAPIPlan(*planPath, profile, *approval)
	} else {
		plan, err = proxmoxadapter.ReadAPIPlan(*planPath, profile)
	}
	return plan, *tokenID, err
}

func readAPIPlanFlags(name string, arguments []string) (proxmoxadapter.APIPlan, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	profilePath := flags.String("profile", "", "validated Proxmox appliance profile")
	planPath := flags.String("plan", "", "API plan file")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return proxmoxadapter.APIPlan{}, errors.New("invalid API review arguments")
	}
	profile, err := applianceprofile.Read(*profilePath)
	if err != nil {
		return proxmoxadapter.APIPlan{}, err
	}
	return proxmoxadapter.ReadAPIPlan(*planPath, profile)
}

func writeNewFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func makePlan(arguments []string) error {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	profilePath := flags.String("profile", "", "validated Proxmox appliance profile")
	outputPath := flags.String("output", "", "new plan file")
	node := flags.String("node", "", "PVE node name")
	vmID := flags.Int("vmid", 0, "unused PVE VM ID")
	name := flags.String("name", "", "new VM name")
	storage := flags.String("storage", "", "PVE storage ID")
	bridge := flags.String("bridge", "", "PVE bridge ID")
	adminUser := flags.String("admin-user", "facets-admin", "non-root guest administrator")
	cloudImage := flags.String("cloud-image", "", "absolute PVE cloud image path")
	sshPublicKey := flags.String("ssh-public-key", "", "absolute PVE SSH public-key path")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid plan arguments")
	}
	profile, err := applianceprofile.Read(*profilePath)
	if err != nil {
		return err
	}
	imageDigest, err := proxmoxadapter.FileSHA256(*cloudImage, 8*1024*1024*1024)
	if err != nil {
		return fmt.Errorf("cloud image: %w", err)
	}
	keyDigest, err := proxmoxadapter.FileSHA256(*sshPublicKey, 16*1024)
	if err != nil {
		return fmt.Errorf("SSH public key: %w", err)
	}
	plan := proxmoxadapter.NewPlan(profile, *node, *vmID, *name, *storage, *bridge, *adminUser,
		proxmoxadapter.FileEvidence{Path: *cloudImage, SHA256: imageDigest},
		proxmoxadapter.FileEvidence{Path: *sshPublicKey, SHA256: keyDigest})
	if err = plan.Validate(profile); err != nil {
		return err
	}
	encoded, err := proxmoxadapter.EncodePlan(plan)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write(encoded); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	fmt.Println(proxmoxadapter.PlanDigest(encoded))
	return nil
}

func reviewPlan(arguments []string) error {
	plan, err := readPlanFlags("review", arguments)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(proxmoxadapter.Review(plan))
}

func applyPlan(arguments []string) error {
	flags := flag.NewFlagSet("apply", flag.ContinueOnError)
	profilePath := flags.String("profile", "", "validated Proxmox appliance profile")
	planPath := flags.String("plan", "", "reviewed plan file")
	approval := flags.String("approval", "", "exact SHA-256 printed by plan")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid apply arguments")
	}
	profile, err := applianceprofile.Read(*profilePath)
	if err != nil {
		return err
	}
	plan, err := proxmoxadapter.ReadApprovedPlan(*planPath, profile, *approval)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	return proxmoxadapter.Apply(ctx, proxmoxadapter.ExecRunner{}, plan)
}

func nextID(arguments []string) error {
	flags := flag.NewFlagSet("next-id", flag.ContinueOnError)
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid next-id arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	value, err := proxmoxadapter.AvailableVMID(ctx, proxmoxadapter.ExecRunner{})
	if err != nil {
		return err
	}
	fmt.Println(value)
	return nil
}

func readPlanFlags(name string, arguments []string) (proxmoxadapter.Plan, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	profilePath := flags.String("profile", "", "validated Proxmox appliance profile")
	planPath := flags.String("plan", "", "plan file")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return proxmoxadapter.Plan{}, errors.New("invalid review arguments")
	}
	profile, err := applianceprofile.Read(*profilePath)
	if err != nil {
		return proxmoxadapter.Plan{}, err
	}
	plan, err := proxmoxadapter.ReadPlan(*planPath, profile)
	return plan, err
}
