package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/grandcat/zeroconf"
	"github.com/robreuss/FacetsNode/internal/boxcontrol"
)

const (
	bonjourType    = "_facets-box._tcp"
	discoveryPath  = "/.well-known/facets-box"
	maximumPayload = 256 * 1024
)

type advertisement struct {
	instance string
	port     int
	txt      []string
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "healthcheck" {
		client, err := clientFromCAFile(os.Getenv("FACETS_BOX_DISCOVERY_CA_FILE"))
		if err != nil || fetchAdvertisement(context.Background(), client, os.Args[2]).instance == "" {
			os.Exit(1)
		}
		return
	}
	publicURL := strings.TrimSpace(os.Getenv("FACETS_BOX_PUBLIC_URL"))
	if _, err := boxcontrol.ValidatePublicBaseURL(publicURL); err != nil {
		fatal("public Box URL rejected", err)
	}
	client, err := clientFromCAFile(os.Getenv("FACETS_BOX_DISCOVERY_CA_FILE"))
	if err != nil {
		fatal("discovery TLS roots rejected", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var server *zeroconf.Server
	var current advertisement
	refresh := time.NewTicker(5 * time.Second)
	defer refresh.Stop()
	for {
		next := fetchAdvertisement(ctx, client, publicURL)
		if next.instance != "" && next.key() != current.key() {
			if server != nil {
				server.Shutdown()
				server = nil
			}
			server, err = zeroconf.Register(next.instance, bonjourType, "local.", next.port, next.txt, nil)
			if err != nil {
				slog.Error("Facets Box Bonjour registration failed", "error_type", fmt.Sprintf("%T", err))
			} else {
				current = next
				slog.Info("Facets Box Bonjour advertisement active", "box", next.instance)
			}
		}
		select {
		case <-ctx.Done():
			if server != nil {
				server.Shutdown()
			}
			return
		case <-refresh.C:
		}
	}
}

func (value advertisement) key() string {
	return value.instance + "\x00" + strconv.Itoa(value.port) + "\x00" + strings.Join(value.txt, "\x00")
}

func clientFromCAFile(path string) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if path = strings.TrimSpace(path); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("discovery CA file contains no certificates")
		}
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    roots,
		}},
	}, nil
}

func fetchAdvertisement(ctx context.Context, client *http.Client, publicURL string) advertisement {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(publicURL, "/")+discoveryPath, nil)
	if err != nil {
		return advertisement{}
	}
	response, err := client.Do(request)
	if err != nil {
		return advertisement{}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return advertisement{}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maximumPayload+1))
	if err != nil || len(data) > maximumPayload {
		return advertisement{}
	}
	result, err := advertisementFromManifest(data, publicURL)
	if err != nil {
		slog.Warn("Facets Box public manifest rejected", "error_type", fmt.Sprintf("%T", err))
		return advertisement{}
	}
	return result
}

func advertisementFromManifest(data []byte, publicURL string) (advertisement, error) {
	var envelope boxcontrol.SignedPublicManifest
	if err := strictJSON(data, &envelope); err != nil {
		return advertisement{}, err
	}
	payloadBytes, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil || len(payloadBytes) > maximumPayload || base64.RawURLEncoding.EncodeToString(payloadBytes) != envelope.Payload {
		return advertisement{}, errors.New("manifest payload is invalid")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return advertisement{}, errors.New("manifest signature is invalid")
	}
	var payload boxcontrol.PublicManifestPayload
	if err := strictJSON(payloadBytes, &payload); err != nil || payload.Version != boxcontrol.SchemaVersion {
		return advertisement{}, errors.New("manifest payload is invalid")
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(payload.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, payloadBytes, signature) {
		return advertisement{}, errors.New("manifest signature is invalid")
	}
	if payload.BoxID.String() == "00000000-0000-0000-0000-000000000000" {
		return advertisement{}, errors.New("manifest Box identity is invalid")
	}
	displayName, err := boxcontrol.NormalizeBoxDisplayName(payload.DisplayName)
	if err != nil {
		return advertisement{}, err
	}
	services, err := boxcontrol.ValidateServices(payload.Services)
	if err != nil {
		return advertisement{}, err
	}
	parsed, err := url.Parse(publicURL)
	if err != nil || parsed.Port() == "" {
		return advertisement{}, errors.New("public Box URL requires an explicit port for Bonjour")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return advertisement{}, errors.New("public Box port is invalid")
	}
	sort.Slice(services, func(left, right int) bool { return services[left].Kind < services[right].Kind })
	fingerprint := sha256.Sum256(publicKey)
	txt := []string{
		"v=1",
		"boxID=" + payload.BoxID.String(),
		"name=" + displayName,
		"url=" + strings.TrimSuffix(publicURL, "/"),
		"key=" + hex.EncodeToString(fingerprint[:]),
		"claimed=" + strconv.FormatBool(payload.Claimed),
	}
	for index, service := range services {
		txt = append(txt, fmt.Sprintf("service%d=%s", index, service.Kind))
	}
	for _, value := range txt {
		if len(value) > 255 {
			return advertisement{}, errors.New("Bonjour field is too large")
		}
	}
	return advertisement{
		instance: instanceName(displayName, payload.BoxID.String()[:8]),
		port:     port,
		txt:      txt,
	}, nil
}

func strictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("JSON contains trailing content")
	}
	return nil
}

func instanceName(displayName, suffix string) string {
	const maximumBytes = 63
	suffix = "-" + suffix
	maximumNameBytes := maximumBytes - len(suffix)
	for len(displayName) > maximumNameBytes {
		_, size := utf8.DecodeLastRuneInString(displayName)
		displayName = displayName[:len(displayName)-size]
	}
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		displayName = "Facets-Box"
	}
	return displayName + suffix
}

func fatal(message string, err error) {
	slog.Error(message, "error_type", fmt.Sprintf("%T", err), "error", err)
	os.Exit(1)
}
