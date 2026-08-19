package scripts

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const validSharedSpacesRevision = "0123456789abcdef0123456789abcdef01234567"

func TestSharedSpacesCheckpointRevisionPrefersStrictCallerValue(t *testing.T) {
	output, err := resolveSharedSpacesRevision(
		t,
		fakeSharedSpacesGit(t, "89abcdef0123456789abcdef0123456789abcdef", 0),
		stringPointer(validSharedSpacesRevision),
	)
	if err != nil {
		t.Fatal(err)
	}
	if output != validSharedSpacesRevision {
		t.Fatalf("resolved revision %q, want %q", output, validSharedSpacesRevision)
	}
}

func TestSharedSpacesCheckpointRevisionRejectsInvalidCallerValues(t *testing.T) {
	for _, value := range []string{
		"",
		"0123456789abcdef",
		"0123456789ABCDEF0123456789ABCDEF01234567",
		"unknown",
	} {
		t.Run(value, func(t *testing.T) {
			_, err := resolveSharedSpacesRevision(
				t,
				fakeSharedSpacesGit(t, validSharedSpacesRevision, 0),
				&value,
			)
			var exitError *exec.ExitError
			if err == nil || !errors.As(err, &exitError) || exitError.ExitCode() != 65 {
				t.Fatalf("resolve invalid revision error=%v, want exit 65", err)
			}
		})
	}
}

func TestSharedSpacesCheckpointRevisionFallsBackToGitOrUnknown(t *testing.T) {
	output, err := resolveSharedSpacesRevision(
		t,
		fakeSharedSpacesGit(t, validSharedSpacesRevision, 0),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if output != validSharedSpacesRevision {
		t.Fatalf("Git revision %q, want %q", output, validSharedSpacesRevision)
	}

	output, err = resolveSharedSpacesRevision(t, fakeSharedSpacesGit(t, "", 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	if output != "unknown" {
		t.Fatalf("missing Git revision %q, want unknown", output)
	}
}

func resolveSharedSpacesRevision(t *testing.T, gitDirectory string, explicit *string) (string, error) {
	t.Helper()
	command := exec.Command(
		"bash",
		"-c",
		"source ./revision-attestation.sh; facets_shared_spaces_resolve_checkpoint_revision",
	)
	environment := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "FACETS_SHARED_SPACES_CHECKPOINT_REVISION=") &&
			!strings.HasPrefix(entry, "PATH=") {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "PATH="+gitDirectory+":/usr/bin:/bin")
	if explicit != nil {
		environment = append(
			environment,
			"FACETS_SHARED_SPACES_CHECKPOINT_REVISION="+*explicit,
		)
	}
	command.Env = environment
	output, err := command.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

func fakeSharedSpacesGit(t *testing.T, output string, exitCode int) string {
	t.Helper()
	directory := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' '" + output + "'\nexit " + strconv.Itoa(exitCode) + "\n"
	path := filepath.Join(directory, "git")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func stringPointer(value string) *string {
	return &value
}
