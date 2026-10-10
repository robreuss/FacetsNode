package proxmoxadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pinnedTestServer(t *testing.T, handler http.Handler) (*httptest.Server, string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	digest := sha256.Sum256(server.Certificate().Raw)
	return server, hex.EncodeToString(digest[:])
}

func TestAPIClientPinsCertificateAndKeepsTokenInHeader(t *testing.T) {
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "PVEAPIToken=test@pve!automation=secret" {
			t.Error("missing API token header")
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"data":{"version":"8.4.0"}}`)
	})
	server, fingerprint := pinnedTestServer(t, handler)
	client, err := NewAPIClient(server.URL, fingerprint, "test@pve!automation", "secret")
	if err != nil {
		t.Fatal(err)
	}
	var version struct {
		Version string `json:"version"`
	}
	if err = client.get(context.Background(), "/version", nil, &version); err != nil || version.Version != "8.4.0" {
		t.Fatalf("version=%q err=%v", version.Version, err)
	}

	wrongClient, err := NewAPIClient(server.URL, strings.Repeat("a", 64), "test@pve!automation", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if err = wrongClient.get(context.Background(), "/version", nil, &version); err == nil || !strings.Contains(err.Error(), "certificate digest mismatch") {
		t.Fatalf("wrong certificate pin result: %v", err)
	}
}

func TestAPIClientStreamsUploadAndWaitsForTask(t *testing.T) {
	var uploadChecked bool
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api2/json/nodes/pve/storage/local/upload":
			if err := request.ParseMultipartForm(1 << 20); err != nil {
				t.Error(err)
				http.Error(response, "bad upload", http.StatusBadRequest)
				return
			}
			if request.FormValue("content") != "iso" || request.FormValue("checksum-algorithm") != "sha256" || request.FormValue("checksum") != "abc" {
				t.Errorf("unexpected upload fields: %#v", request.MultipartForm.Value)
			}
			file, header, err := request.FormFile("filename")
			if err != nil {
				t.Error(err)
				http.Error(response, "missing upload", http.StatusBadRequest)
				return
			}
			defer file.Close()
			data, _ := io.ReadAll(file)
			if header.Filename != "pinned.img" || string(data) != "cloud-image" {
				t.Errorf("unexpected upload: filename=%q data=%q", header.Filename, data)
			}
			uploadChecked = true
			_, _ = io.WriteString(response, `{"data":"UPID:pve:00000001:test"}`)
		case "/api2/json/nodes/pve/tasks/UPID:pve:00000001:test/status":
			_, _ = io.WriteString(response, `{"data":{"status":"stopped","exitstatus":"OK"}}`)
		default:
			http.NotFound(response, request)
		}
	})
	server, fingerprint := pinnedTestServer(t, handler)
	client, err := NewAPIClient(server.URL, fingerprint, "test@pve!automation", "secret")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "source.img")
	if err = os.WriteFile(source, []byte("cloud-image"), 0600); err != nil {
		t.Fatal(err)
	}
	upid, err := client.upload(context.Background(), "/nodes/pve/storage/local/upload", map[string]string{
		"content": "iso", "checksum": "abc", "checksum-algorithm": "sha256",
	}, source, "pinned.img")
	if err != nil {
		t.Fatal(err)
	}
	if err = client.waitTask(context.Background(), "pve", upid); err != nil {
		t.Fatal(err)
	}
	if !uploadChecked {
		t.Fatal("upload was not inspected")
	}
}

func TestAPIClientRejectsUnsafeCredentialAndMutationResponse(t *testing.T) {
	if _, err := NewAPIClient("https://192.0.2.1:8006", strings.Repeat("a", 64), "bad-token", "secret"); err == nil {
		t.Fatal("invalid token ID accepted")
	}
	for _, fixture := range []string{`123`, `"not-a-task"`, `{}`} {
		if _, err := taskID(json.RawMessage(fixture)); err == nil {
			t.Fatalf("invalid mutation response accepted: %s", fixture)
		}
	}
}
