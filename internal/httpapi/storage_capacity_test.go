package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

func TestStoragePressureResponseIsDistinctBoundedAndContentFree(t *testing.T) {
	for _, item := range []struct {
		err           error
		code, message string
	}{
		{storagecapacity.ErrPressure, "storage_pressure", "Sync paused: the Box needs more storage."},
		{storagecapacity.ErrUnavailable, "storage_capacity_unavailable", "Sync paused: the Box cannot check its available storage."},
	} {
		server := &Server{}
		recorder := httptest.NewRecorder()
		server.writeError(recorder, fmt.Errorf("private filesystem detail: %w", item.err))
		if recorder.Code != http.StatusInsufficientStorage || recorder.Header().Get("Retry-After") != "30" {
			t.Fatal(recorder.Code, recorder.Header())
		}
		var body struct {
			Error struct{ Code, Message string }
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Error.Code != item.code || body.Error.Message != item.message {
			t.Fatalf("response=%+v", body)
		}
	}
}
