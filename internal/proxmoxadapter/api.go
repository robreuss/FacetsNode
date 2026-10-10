package proxmoxadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maximumAPIResponseBytes = 4 * 1024 * 1024

var tokenIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+![a-zA-Z0-9._-]+$`)

type APIClient struct {
	endpoint    string
	tokenID     string
	tokenSecret string
	httpClient  *http.Client
}

type apiEnvelope struct {
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
	Errors  json.RawMessage `json:"errors"`
}

func NewAPIClient(endpoint, tlsCertificateSHA256, tokenID, tokenSecret string) (*APIClient, error) {
	normalized, err := normalizeAPIEndpoint(endpoint)
	if err != nil || normalized != endpoint {
		return nil, errors.New("invalid Proxmox API endpoint")
	}
	if !validHex(tlsCertificateSHA256, 64) {
		return nil, errors.New("invalid Proxmox TLS certificate digest")
	}
	if !tokenIDPattern.MatchString(tokenID) || tokenSecret == "" || len(tokenSecret) > 4096 || strings.ContainsAny(tokenSecret, "\x00\r\n") {
		return nil, errors.New("invalid Proxmox API credential")
	}
	wantedFingerprint, _ := hex.DecodeString(tlsCertificateSHA256)
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // Exact leaf-certificate pinning is performed below.
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("unexpected Proxmox TLS certificate chain")
			}
			actual := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(actual[:], wantedFingerprint) != 1 {
				return errors.New("Proxmox TLS certificate digest mismatch")
			}
			return nil
		},
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          4,
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("Proxmox API redirect refused")
		},
	}
	return &APIClient{endpoint: endpoint, tokenID: tokenID, tokenSecret: tokenSecret, httpClient: client}, nil
}

func (client *APIClient) get(ctx context.Context, apiPath string, query url.Values, target any) error {
	requestURL, err := client.apiURL(apiPath, query)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return err
	}
	data, err := client.do(request)
	if err != nil {
		return err
	}
	if target == nil {
		return nil
	}
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return errors.New("Proxmox API returned no data")
	}
	return json.Unmarshal(data, target)
}

func (client *APIClient) mutate(ctx context.Context, method, apiPath string, form map[string]string) (string, error) {
	requestURL, err := client.apiURL(apiPath, nil)
	if err != nil {
		return "", err
	}
	values := url.Values{}
	for key, value := range form {
		values.Set(key, value)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL, strings.NewReader(values.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	data, err := client.do(request)
	if err != nil {
		return "", err
	}
	return taskID(data)
}

func (client *APIClient) upload(ctx context.Context, apiPath string, fields map[string]string, sourcePath, targetFilename string) (string, error) {
	file, err := os.Open(sourcePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return "", errors.New("invalid Proxmox upload source")
	}

	var prefix bytes.Buffer
	writer := multipart.NewWriter(&prefix)
	keys := make([]string, 0, len(fields))
	seen := make(map[string]bool, len(fields))
	for _, key := range []string{"content", "checksum-algorithm", "checksum"} {
		if _, ok := fields[key]; ok {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	var remaining []string
	for key := range fields {
		if !seen[key] {
			remaining = append(remaining, key)
		}
	}
	sort.Strings(remaining)
	keys = append(keys, remaining...)
	for _, key := range keys {
		if err = writer.WriteField(key, fields[key]); err != nil {
			return "", err
		}
	}
	if _, err = writer.CreateFormFile("filename", targetFilename); err != nil {
		return "", err
	}
	suffix := []byte("\r\n--" + writer.Boundary() + "--\r\n")
	body := io.MultiReader(bytes.NewReader(prefix.Bytes()), file, bytes.NewReader(suffix))
	requestURL, err := client.apiURL(apiPath, nil)
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, io.NopCloser(body))
	if err != nil {
		return "", err
	}
	request.ContentLength = int64(prefix.Len()) + info.Size() + int64(len(suffix))
	request.Header.Set("Content-Type", writer.FormDataContentType())
	data, err := client.do(request)
	if err != nil {
		return "", err
	}
	return taskID(data)
}

func (client *APIClient) apiURL(apiPath string, query url.Values) (string, error) {
	if !strings.HasPrefix(apiPath, "/") || strings.Contains(apiPath, "..") || strings.ContainsAny(apiPath, "\x00\r\n") {
		return "", errors.New("invalid Proxmox API path")
	}
	parsed, err := url.Parse(client.endpoint + "/api2/json" + apiPath)
	if err != nil {
		return "", err
	}
	if query != nil {
		parsed.RawQuery = query.Encode()
	}
	return parsed.String(), nil
}

func (client *APIClient) do(request *http.Request) (json.RawMessage, error) {
	request.Header.Set("Authorization", "PVEAPIToken="+client.tokenID+"="+client.tokenSecret)
	request.Header.Set("User-Agent", "facets-proxmox-vm/1")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maximumAPIResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maximumAPIResponseBytes {
		return nil, errors.New("Proxmox API response exceeds limit")
	}
	var envelope apiEnvelope
	if err = json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf(
			"invalid Proxmox API response: method=%s path=%s status=%d content-type=%q",
			request.Method,
			request.URL.Path,
			response.StatusCode,
			response.Header.Get("Content-Type"),
		)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := strings.TrimSpace(envelope.Message)
		if message == "" {
			message = http.StatusText(response.StatusCode)
		}
		return nil, fmt.Errorf("Proxmox API %s %s: %d %s", request.Method, request.URL.Path, response.StatusCode, message)
	}
	return envelope.Data, nil
}

func taskID(data json.RawMessage) (string, error) {
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil || (value != "" && !strings.HasPrefix(value, "UPID:")) {
		return "", errors.New("invalid Proxmox API mutation result")
	}
	return value, nil
}

func (client *APIClient) waitTask(ctx context.Context, node, upid string) error {
	if upid == "" {
		return nil
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		var status struct {
			Status     string `json:"status"`
			ExitStatus string `json:"exitstatus"`
		}
		apiPath := "/nodes/" + node + "/tasks/" + url.PathEscape(upid) + "/status"
		if err := client.get(ctx, apiPath, nil, &status); err != nil {
			return err
		}
		if strings.EqualFold(status.Status, "stopped") {
			if status.ExitStatus != "OK" {
				return fmt.Errorf("Proxmox task failed: %s", status.ExitStatus)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type apiNodeStatus struct {
	LoadAverage []string `json:"loadavg"`
	CPUInfo     struct {
		CPUs int    `json:"cpus"`
		HVM  string `json:"hvm"`
	} `json:"cpuinfo"`
	CurrentKernel struct {
		Machine string `json:"machine"`
	} `json:"current-kernel"`
}

type apiTask struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

type apiVM struct {
	VMID int    `json:"vmid"`
	Name string `json:"name"`
}

type apiNetwork struct {
	Interface string  `json:"iface"`
	Type      string  `json:"type"`
	Active    boolish `json:"active"`
}

type apiStorageContent struct {
	VolumeID string `json:"volid"`
}

func PreflightAPI(ctx context.Context, client *APIClient, plan APIPlan) (string, error) {
	if err := verifyEvidence(plan.CloudImage, int64(8*gibibyte)); err != nil {
		return "", fmt.Errorf("verify cloud image: %w", err)
	}
	if err := verifyEvidence(plan.SSHPublicKey, 16*1024); err != nil {
		return "", fmt.Errorf("verify SSH public key: %w", err)
	}
	keyData, err := os.ReadFile(plan.SSHPublicKey.Path)
	if err != nil {
		return "", err
	}
	publicKey, err := canonicalPublicKey(keyData)
	if err != nil {
		return "", err
	}

	var version struct {
		Version string `json:"version"`
		Release string `json:"release"`
	}
	if err = client.get(ctx, "/version", nil, &version); err != nil || version.Version == "" || version.Release == "" {
		return "", errors.New("PVE API version unavailable")
	}
	var nodeStatus apiNodeStatus
	if err = client.get(ctx, "/nodes/"+plan.Node+"/status", nil, &nodeStatus); err != nil {
		return "", errors.New("PVE node status unavailable")
	}
	if nodeStatus.CurrentKernel.Machine != "x86_64" || nodeStatus.CPUInfo.CPUs <= 0 || nodeStatus.CPUInfo.HVM != "1" {
		return "", errors.New("PVE node is not a compatible AMD64 virtualization host")
	}
	var tasks []apiTask
	if err = client.get(ctx, "/nodes/"+plan.Node+"/tasks", url.Values{"source": {"active"}, "limit": {"100"}}, &tasks); err != nil {
		return "", errors.New("active PVE task inventory unavailable")
	}
	for _, task := range tasks {
		if strings.EqualFold(task.Status, "running") && (task.Type == "vzdump" || strings.Contains(strings.ToLower(task.Type), "backup")) {
			return "", errors.New("active PVE backup task blocks appliance provisioning")
		}
	}
	if len(nodeStatus.LoadAverage) == 0 {
		return "", errors.New("PVE node load is unavailable")
	}
	load, err := strconv.ParseFloat(nodeStatus.LoadAverage[0], 64)
	if err != nil || load > float64(nodeStatus.CPUInfo.CPUs*2) {
		return "", errors.New("PVE node load exceeds the safe provisioning gate")
	}

	var permissions map[string]map[string]int
	if err = client.get(ctx, "/access/permissions", url.Values{"path": {"/"}}, &permissions); err != nil {
		return "", errors.New("PVE API permission inventory unavailable")
	}
	for _, required := range []string{
		"Sys.Audit", "Datastore.AllocateTemplate", "Datastore.AllocateSpace", "SDN.Use", "VM.Allocate",
		"VM.Config.CDROM", "VM.Config.Cloudinit", "VM.Config.CPU", "VM.Config.Disk", "VM.Config.HWType",
		"VM.Config.Memory", "VM.Config.Network", "VM.Config.Options", "VM.PowerMgmt",
	} {
		if permissions["/"][required] != 1 {
			return "", fmt.Errorf("PVE API credential lacks %s", required)
		}
	}

	var resources []apiVM
	if err = client.get(ctx, "/cluster/resources", url.Values{"type": {"vm"}}, &resources); err != nil {
		return "", errors.New("PVE VM inventory unavailable")
	}
	for _, resource := range resources {
		if resource.VMID == plan.VMID || (resource.Name != "" && resource.Name == plan.Name) {
			return "", errors.New("planned PVE VM identity is already in use")
		}
	}
	var nodeVMs []apiVM
	if err = client.get(ctx, "/nodes/"+plan.Node+"/qemu", nil, &nodeVMs); err != nil {
		return "", errors.New("PVE node VM inventory unavailable")
	}
	for _, existing := range nodeVMs {
		if existing.VMID == plan.VMID || existing.Name == plan.Name {
			return "", errors.New("planned PVE VM identity is already in use")
		}
	}

	var storage storageStatus
	if err = client.get(ctx, "/nodes/"+plan.Node+"/storage/"+plan.Storage+"/status", nil, &storage); err != nil || !bool(storage.Active) || !bool(storage.Enabled) || !containsCSV(storage.Content, "images") {
		return "", errors.New("planned PVE VM storage is unavailable")
	}
	requiredBytes := (plan.SystemDiskGiB + plan.DataDiskGiB + 8) * gibibyte
	if storage.Avail < requiredBytes {
		return "", errors.New("insufficient PVE VM storage for appliance plan")
	}
	var imageStorage storageStatus
	if err = client.get(ctx, "/nodes/"+plan.Node+"/storage/"+plan.ImageStorage+"/status", nil, &imageStorage); err != nil || !bool(imageStorage.Active) || !bool(imageStorage.Enabled) || !containsCSV(imageStorage.Content, plan.ImageContent) {
		return "", errors.New("planned PVE upload storage is unavailable")
	}
	imageInfo, err := os.Stat(plan.CloudImage.Path)
	if err != nil || uint64(imageInfo.Size())+gibibyte > imageStorage.Avail {
		return "", errors.New("insufficient PVE upload storage for cloud image")
	}
	var networks []apiNetwork
	if err = client.get(ctx, "/nodes/"+plan.Node+"/network", nil, &networks); err != nil {
		return "", errors.New("PVE bridge inventory unavailable")
	}
	bridgeFound := false
	for _, network := range networks {
		if network.Interface == plan.Bridge && network.Type == "bridge" && bool(network.Active) {
			bridgeFound = true
		}
	}
	if !bridgeFound {
		return "", errors.New("planned PVE bridge is unavailable")
	}
	var contents []apiStorageContent
	if err = client.get(ctx, "/nodes/"+plan.Node+"/storage/"+plan.ImageStorage+"/content", nil, &contents); err != nil {
		return "", errors.New("PVE upload inventory unavailable")
	}
	wantedVolume := plan.ImageStorage + ":" + plan.ImageContent + "/" + plan.ImageFilename
	for _, content := range contents {
		if content.VolumeID == wantedVolume {
			return "", errors.New("planned PVE upload target already exists")
		}
	}
	return publicKey, nil
}

func ApplyAPI(ctx context.Context, client *APIClient, plan APIPlan, report func(string)) error {
	publicKey, err := PreflightAPI(ctx, client, plan)
	if err != nil {
		return err
	}
	operations := APIOperations(plan, publicKey)
	for index, operation := range operations {
		if report != nil {
			report(fmt.Sprintf("%s (%d/%d)", operation.Name, index+1, len(operations)))
		}
		var upid string
		if operation.UploadPath != "" {
			upid, err = client.upload(ctx, operation.Path, operation.Form, operation.UploadPath, operation.UploadFilename)
		} else {
			upid, err = client.mutate(ctx, operation.Method, operation.Path, operation.Form)
		}
		if err == nil {
			err = client.waitTask(ctx, plan.Node, upid)
		}
		if err != nil {
			return fmt.Errorf("PVE API appliance creation stopped at %s: %w; no upload or VM was automatically deleted", operation.Name, err)
		}
	}
	var current struct {
		Status string `json:"status"`
	}
	statusPath := "/nodes/" + plan.Node + "/qemu/" + strconv.Itoa(plan.VMID) + "/status/current"
	if err = client.get(ctx, statusPath, nil, &current); err != nil || current.Status != "running" {
		return errors.New("created PVE appliance VM is not running")
	}
	return nil
}
