package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const chunkBytes = 24 * 1024

type transferArtifact struct {
	Kind     string `json:"kind"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Revision string `json:"revision,omitempty"`
	Tree     string `json:"tree,omitempty"`
}

func validHex(s string, size int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == size && strings.ToLower(s) == s
}
func (a transferArtifact) validateSource() error {
	if a.Kind != "source" || a.Size <= 0 || a.Size > 100*1024*1024 || !validHex(a.SHA256, 32) || !validHex(a.Revision, 20) || !validHex(a.Tree, 20) {
		return errors.New("invalid source artifact")
	}
	return nil
}
func fileHash(path string) (string, int64, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, e
}

// A caller selects an artifact kind, never a guest path. The private directory
// is writable only by appliance infrastructure, not by any workload container.
func artifactPath(root, kind string) (string, error) {
	switch kind {
	case "source", "runtimeKit", "serviceKit", "buildLog":
		return filepath.Join(root, kind+".tar"), nil
	default:
		return "", errors.New("unknown artifact kind")
	}
}
func writeJSONFile(path string, value any) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path+".new", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	f.Close()
	if e != nil {
		return e
	}
	if e = os.Rename(path+".new", path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func transfer(root string, r request) (response, error) {
	out := response{ID: r.ID}
	if r.Artifact == nil {
		return out, errors.New("missing artifact")
	}
	a := *r.Artifact
	path, e := artifactPath(root, a.Kind)
	if e != nil {
		return out, e
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		return out, e
	}
	if strings.HasPrefix(r.Operation, "upload") {
		if e = a.validateSource(); e != nil {
			return out, e
		}
		if r.Operation == "uploadStart" {
			f, e := os.OpenFile(path+".part", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if os.IsExist(e) {
				// Resume only the same authenticated archive. Different uploads must wait
				// for explicit staging cleanup; they never overwrite a partially built job.
				b, re := os.ReadFile(path + ".pending.json")
				var old transferArtifact
				if re != nil || json.Unmarshal(b, &old) != nil || old != a {
					return out, errors.New("different upload pending")
				}
				return out, nil
			}
			if e != nil {
				return out, e
			}
			f.Close()
			return out, writeJSONFile(path+".pending.json", a)
		}
		b, e := os.ReadFile(path + ".pending.json")
		var old transferArtifact
		if e != nil || json.Unmarshal(b, &old) != nil || old != a {
			return out, errors.New("upload identity mismatch")
		}
		if r.Operation == "uploadChunk" {
			if len(r.Chunk) == 0 || len(r.Chunk) > chunkBytes || r.Offset < 0 || r.Offset+int64(len(r.Chunk)) > a.Size {
				return out, errors.New("invalid chunk")
			}
			f, e := os.OpenFile(path+".part", os.O_WRONLY, 0600)
			if e != nil {
				return out, e
			}
			defer f.Close()
			stat, e := f.Stat()
			if e != nil || r.Offset > stat.Size() {
				return out, errors.New("noncontiguous upload")
			}
			_, e = f.WriteAt(r.Chunk, r.Offset)
			return out, e
		}
		sum, n, e := fileHash(path + ".part")
		if e != nil || n != a.Size || sum != a.SHA256 {
			return out, errors.New("artifact hash mismatch")
		}
		f, e := os.OpenFile(path+".part", os.O_RDWR, 0600)
		if e != nil {
			return out, e
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return out, e
		}
		if e = os.Rename(path+".part", path); e != nil {
			return out, e
		}
		if e = writeJSONFile(path+".json", a); e != nil {
			return out, e
		}
		return out, os.Remove(path + ".pending.json")
	}
	if r.Operation == "artifactInfo" {
		sum, n, e := fileHash(path)
		if e != nil {
			return out, e
		}
		out.Artifact = &transferArtifact{Kind: a.Kind, Size: n, SHA256: sum}
		return out, nil
	}
	if r.Operation == "artifactRead" {
		if r.Offset < 0 {
			return out, errors.New("invalid offset")
		}
		f, e := os.Open(path)
		if e != nil {
			return out, e
		}
		defer f.Close()
		out.Chunk = make([]byte, chunkBytes)
		n, e := f.ReadAt(out.Chunk, r.Offset)
		out.Chunk = out.Chunk[:n]
		if e == io.EOF {
			e = nil
		}
		return out, e
	}
	return out, errors.New("unknown transfer")
}

// The exported committed source is data until a separately requested bounded
// build. Reject links, devices, traversal, excessive expansion, and duplicates.
func extractSource(reader io.Reader, destination string) error {
	return extractArchive(reader, destination, 100*1024*1024)
}

func extractArchive(reader io.Reader, destination string, budget int64) error {
	tr := tar.NewReader(reader)
	seen := map[string]bool{}
	var total int64
	for {
		h, e := tr.Next()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		// git archive emits one global PAX comment carrying its commit ID. It is
		// metadata, not a filesystem entry; no path/ownership overrides are allowed.
		if h.Typeflag == tar.TypeXGlobalHeader {
			if len(h.PAXRecords) != 1 || !validHex(h.PAXRecords["comment"], 20) {
				return errors.New("unsupported archive metadata")
			}
			continue
		}
		name := strings.TrimSuffix(h.Name, "/")
		if name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || seen[name] {
			return errors.New("unsafe archive path")
		}
		seen[name] = true
		path := filepath.Join(destination, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if e = os.MkdirAll(path, 0700); e != nil {
				return e
			}
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 || h.Size > budget-total || len(seen) > 20000 {
				return errors.New("archive budget exceeded")
			}
			total += h.Size
			if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
				return e
			}
			mode := os.FileMode(0600)
			if h.Mode&0111 != 0 {
				mode = 0700
			}
			f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if e != nil {
				return e
			}
			_, e = io.CopyN(f, tr, h.Size)
			f.Close()
			if e != nil {
				return e
			}
		default:
			return fmt.Errorf("archive entry type %d rejected", h.Typeflag)
		}
	}
}
