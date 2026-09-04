package boxcontrol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type DeviceSyncController interface {
	Healthy(context.Context) error
}

type DeviceSyncHTTPClient struct {
	baseURL string
	client  *http.Client
}

func NewDeviceSyncHTTPClient(baseURL string, client *http.Client) (*DeviceSyncHTTPClient, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/"))
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return nil, errors.New("private Device Sync URL is invalid")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &DeviceSyncHTTPClient{baseURL: parsed.String(), client: client}, nil
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
