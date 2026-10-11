package boxcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/robreuss/FacetsNode/internal/storagecapacity"
)

const maximumJobCustodyReadinessBytes = 16 * 1024

// JobCustodyHTTPClient is the Controller's content-blind service monitor. It
// reads only operational health and the coarse admission projection; it has no
// Job, Space, object, prompt, result, or capacity-ledger authority.
type JobCustodyHTTPClient struct {
	baseURL string
	client  *http.Client
}

func NewJobCustodyHTTPClient(baseURL string, client *http.Client) (*JobCustodyHTTPClient, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/"))
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return nil, errors.New("private Job Custody URL is invalid")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &JobCustodyHTTPClient{baseURL: parsed.String(), client: client}, nil
}

func (client *JobCustodyHTTPClient) Healthy(ctx context.Context) error {
	_, err := client.get(ctx, "/readyz")
	return err
}

func (client *JobCustodyHTTPClient) AdmissionReadiness(
	ctx context.Context,
) (storagecapacity.CoarseReadinessSnapshot, error) {
	data, err := client.get(ctx, "/v1/readiness")
	if err != nil {
		return storagecapacity.CoarseReadinessSnapshot{}, err
	}
	var readiness storagecapacity.CoarseReadinessSnapshot
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&readiness); err != nil || readiness.Validate() != nil {
		return storagecapacity.CoarseReadinessSnapshot{}, errors.New("Job Custody readiness response is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return storagecapacity.CoarseReadinessSnapshot{}, errors.New("Job Custody readiness response is invalid")
	}
	return readiness, nil
}

func (client *JobCustodyHTTPClient) get(ctx context.Context, path string) ([]byte, error) {
	if client == nil || client.client == nil || ctx == nil {
		return nil, errors.New("Job Custody monitor is unavailable")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maximumJobCustodyReadinessBytes+1))
	if err != nil || len(data) > maximumJobCustodyReadinessBytes {
		return nil, errors.New("Job Custody readiness response is invalid")
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("Job Custody readiness is unavailable")
	}
	return data, nil
}
