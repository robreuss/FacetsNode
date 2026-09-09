package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCommittedRepositoryArchiveExtraction(t *testing.T) {
	// Prepared source archives deliberately contain no .git directory. Exercise
	// real Git PAX metadata using an isolated repository, including in Docker.
	repository := t.TempDir()
	git := func(args ...string) []byte {
		command := exec.Command("git", append([]string{"-C", repository, "-c", "user.name=FBD test", "-c", "user.email=fbd-test@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"}, args...)...)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture git: %v: %s", err, output)
		}
		return output
	}
	git("init", "--initial-branch=main")
	content := []byte("committed source fixture\n")
	if err := os.WriteFile(filepath.Join(repository, "source.txt"), content, 0600); err != nil {
		t.Fatal(err)
	}
	git("add", "source.txt")
	git("commit", "-m", "Archive fixture")
	archive := git("archive", "--format=tar", "HEAD")
	destination := t.TempDir()
	if e := extractSource(bytes.NewReader(archive), destination); e != nil {
		t.Fatalf("actual committed archive: %v", e)
	}
	actual, err := os.ReadFile(filepath.Join(destination, "source.txt"))
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatal("committed fixture did not survive extraction")
	}
}

func TestSourceTransferIdentityOffsetsAndHash(t *testing.T) {
	root := t.TempDir()
	data := []byte("a committed source archive")
	sum := sha256.Sum256(data)
	a := transferArtifact{Kind: "source", Size: int64(len(data)), SHA256: fmt.Sprintf("%x", sum), Revision: fmt.Sprintf("%040x", 1), Tree: fmt.Sprintf("%040x", 2)}
	call := func(op string, offset int64, chunk []byte) error {
		_, e := transfer(root, request{Operation: op, Artifact: &a, Offset: offset, Chunk: chunk})
		return e
	}
	if e := call("uploadStart", 0, nil); e != nil {
		t.Fatal(e)
	}
	if e := call("uploadChunk", 1, data); e == nil {
		t.Fatal("accepted gap")
	}
	if e := call("uploadChunk", 0, []byte("wrong")); e != nil {
		t.Fatal(e)
	}
	if e := call("uploadFinish", 0, nil); e == nil {
		t.Fatal("accepted wrong hash")
	}
	if e := call("uploadChunk", 0, data); e != nil {
		t.Fatal(e)
	}
	if e := call("uploadFinish", 0, nil); e != nil {
		t.Fatal(e)
	}
	got, _ := os.ReadFile(filepath.Join(root, "source.tar"))
	if !bytes.Equal(got, data) {
		t.Fatal("wrong content")
	}
	a.Kind = "../../etc/passwd"
	if e := call("uploadStart", 0, nil); e == nil {
		t.Fatal("accepted path")
	}
}
func TestSourceExtractionRejectsLinksTraversalAndDuplicates(t *testing.T) {
	for _, test := range []struct {
		name      string
		kind      byte
		duplicate bool
	}{
		{"../escape", tar.TypeReg, false}, {"/absolute", tar.TypeReg, false}, {"link", tar.TypeSymlink, false}, {"file", tar.TypeReg, true},
	} {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		h := &tar.Header{Name: test.name, Typeflag: test.kind, Mode: 0600}
		_ = tw.WriteHeader(h)
		if test.duplicate {
			_ = tw.WriteHeader(h)
		}
		_ = tw.Close()
		if e := extractSource(&b, t.TempDir()); e == nil {
			t.Fatalf("accepted %+v", test)
		}
	}
}
