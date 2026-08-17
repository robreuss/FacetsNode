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

const validRevision = "0123456789abcdef0123456789abcdef01234567"

func TestCheckpointRevisionPrefersStrictCallerValue(t *testing.T) {
	gitDirectory := fakeGit(t, "89abcdef0123456789abcdef0123456789abcdef", 0)
	explicitRevision := validRevision
	output, err := resolveRevision(t, gitDirectory, &explicitRevision)
	if err != nil {
		t.Fatal(err)
	}
	if output != validRevision {
		t.Fatalf("resolved revision %q, want caller value %q", output, validRevision)
	}
}

func TestCheckpointRevisionRejectsInvalidCallerValues(t *testing.T) {
	for _, value := range []string{
		"",
		"0123456789abcdef",
		"0123456789ABCDEF0123456789ABCDEF01234567",
		"unknown",
	} {
		t.Run(value, func(t *testing.T) {
			_, err := resolveRevision(t, fakeGit(t, validRevision, 0), &value)
			var exitError *exec.ExitError
			if err == nil || !errors.As(err, &exitError) || exitError.ExitCode() != 65 {
				t.Fatalf("resolve invalid revision error=%v, want exit 65", err)
			}
		})
	}
}

func TestCheckpointRevisionFallsBackToGitOrUnknown(t *testing.T) {
	output, err := resolveRevision(t, fakeGit(t, validRevision, 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	if output != validRevision {
		t.Fatalf("Git revision %q, want %q", output, validRevision)
	}

	output, err = resolveRevision(t, fakeGit(t, "", 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	if output != "unknown" {
		t.Fatalf("missing Git revision %q, want unknown", output)
	}
}

func TestOCIRevisionLabelsAreWiredThroughCompose(t *testing.T) {
	dockerfile := readFile(t, "../Dockerfile")
	compose := readFile(t, "../compose.yaml")
	backupCompose := readFile(t, "../compose.backup.yaml")
	backupScript := readFile(t, "backup-checkpoint.sh")

	for _, expected := range []string{
		`ARG FACETS_NODE_SOURCE_REVISION=unknown`,
		`ARG FACETS_NODE_SOURCE_TREE=unknown`,
		`org.opencontainers.image.revision="$FACETS_NODE_SOURCE_REVISION"`,
		`org.opencontainers.image.source-tree="$FACETS_NODE_SOURCE_TREE"`,
	} {
		if !strings.Contains(dockerfile, expected) {
			t.Errorf("Dockerfile is missing %q", expected)
		}
	}
	for _, expected := range []string{
		`FACETS_NODE_SOURCE_REVISION: ${FACETS_NODE_SOURCE_REVISION:-unknown}`,
		`FACETS_NODE_SOURCE_TREE: ${FACETS_NODE_SOURCE_TREE:-unknown}`,
	} {
		if !strings.Contains(compose, expected) {
			t.Errorf("Compose build is missing %q", expected)
		}
	}
	if !strings.Contains(backupScript,
		`FACETS_NODE_CHECKPOINT_REVISION=$(facets_node_resolve_checkpoint_revision)`) {
		t.Error("backup script does not resolve the validated checkpoint revision")
	}
	if !strings.Contains(backupCompose, `sourceRevision`) ||
		!strings.Contains(backupCompose, `$${FACETS_NODE_CHECKPOINT_REVISION}`) {
		t.Error("checkpoint manifest does not record the resolved revision")
	}
}

func resolveRevision(t *testing.T, gitDirectory string, explicit *string) (string, error) {
	t.Helper()
	command := exec.Command("bash", "-c", "source ./revision-attestation.sh; facets_node_resolve_checkpoint_revision")
	environment := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "FACETS_NODE_CHECKPOINT_REVISION=") &&
			!strings.HasPrefix(entry, "PATH=") {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "PATH="+gitDirectory+":/usr/bin:/bin")
	if explicit != nil {
		environment = append(environment, "FACETS_NODE_CHECKPOINT_REVISION="+*explicit)
	}
	command.Env = environment
	output, err := command.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

func fakeGit(t *testing.T, output string, exitCode int) string {
	t.Helper()
	directory := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' '" + output + "'\nexit " + strconv.Itoa(exitCode) + "\n"
	path := filepath.Join(directory, "git")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}
