package boxcontrol

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type DeviceSyncController interface {
	Groups(context.Context) ([]DeviceSyncGroup, error)
	IssueAccountBootstrap(context.Context) (json.RawMessage, error)
	Healthy(context.Context) error
}

type DeviceSyncHTTPClient struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewDeviceSyncHTTPClient(baseURL, token string, client *http.Client) (*DeviceSyncHTTPClient, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/"))
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return nil, errors.New("private Device Sync URL is invalid")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return nil, errors.New("private Device Sync controller token is invalid")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &DeviceSyncHTTPClient{baseURL: parsed.String(), token: token, client: client}, nil
}

func (client *DeviceSyncHTTPClient) Groups(ctx context.Context) ([]DeviceSyncGroup, error) {
	request, err := client.request(ctx, http.MethodGet, "/internal/box-controller/device-sync/groups", nil)
	if err != nil {
		return nil, err
	}
	data, err := client.send(request, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var response struct {
		Groups []DeviceSyncGroup `json:"groups"`
	}
	if err := json.Unmarshal(data, &response); err != nil || len(response.Groups) > 256 {
		return nil, errors.New("Device Sync group response is invalid")
	}
	seen := make(map[string]struct{}, len(response.Groups))
	for _, group := range response.Groups {
		if err := group.Validate(); err != nil {
			return nil, errors.New("Device Sync group response is invalid")
		}
		if _, exists := seen[group.SetDiscriminator]; exists {
			return nil, errors.New("Device Sync group response is invalid")
		}
		seen[group.SetDiscriminator] = struct{}{}
	}
	sort.Slice(response.Groups, func(left, right int) bool {
		if response.Groups[left].DisplayName != response.Groups[right].DisplayName {
			return response.Groups[left].DisplayName < response.Groups[right].DisplayName
		}
		return response.Groups[left].SetDiscriminator < response.Groups[right].SetDiscriminator
	})
	return response.Groups, nil
}

func (client *DeviceSyncHTTPClient) IssueAccountBootstrap(ctx context.Context) (json.RawMessage, error) {
	request, err := client.request(ctx, http.MethodPost, "/internal/box-controller/device-sync/account-admissions", bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	data, err := client.send(request, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	var response struct {
		Bootstrap json.RawMessage `json:"bootstrap"`
	}
	if err := json.Unmarshal(data, &response); err != nil || len(response.Bootstrap) == 0 || len(response.Bootstrap) > 512*1024 {
		return nil, errors.New("Device Sync bootstrap response is invalid")
	}
	return response.Bootstrap, nil
}

func (client *DeviceSyncHTTPClient) Healthy(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+"/readyz", nil)
	if err != nil {
		return err
	}
	_, err = client.send(request, http.StatusOK)
	return err
}

func (client *DeviceSyncHTTPClient) request(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, client.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Accept", "application/json")
	return request, nil
}

func (client *DeviceSyncHTTPClient) send(request *http.Request, expected int) ([]byte, error) {
	response, err := client.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1024*1024 {
		return nil, errors.New("Device Sync private response is too large")
	}
	if response.StatusCode != expected {
		return nil, fmt.Errorf("Device Sync private request returned status %d", response.StatusCode)
	}
	return data, nil
}
