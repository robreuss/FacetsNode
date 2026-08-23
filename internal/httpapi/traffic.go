package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/robreuss/FacetsNode/internal/traffic"
)

const (
	headerIngressTransport  = "X-Facets-Ingress-Transport"
	headerOnionIngressToken = "X-Facets-Onion-Ingress-Token"
	ingressTransportOnion   = "tor-onion"
)

type trafficSurfaceControl struct {
	identityLimiter   *traffic.Limiter
	connectionLimiter *traffic.Limiter
	concurrency       chan struct{}
}

type trafficController struct {
	surfaces [traffic.SurfaceCount]trafficSurfaceControl
}

func newTrafficController(limits traffic.Limits) (*trafficController, error) {
	if err := traffic.ValidateLimits(limits); err != nil {
		return nil, err
	}
	controller := &trafficController{}
	for _, surface := range traffic.Surfaces() {
		limit := limits[surface]
		connectionLimit := limit
		connectionLimit.RequestsPerMinute = limit.ConnectionRequestsPerMinute
		connectionLimit.Burst = limit.ConnectionBurst
		controller.surfaces[surface] = trafficSurfaceControl{
			identityLimiter:   traffic.NewLimiter(limit),
			connectionLimiter: traffic.NewLimiter(connectionLimit),
			concurrency:       make(chan struct{}, limit.Concurrency),
		}
	}
	return controller, nil
}

func (s *Server) SetTrafficLimits(limits traffic.Limits) error {
	controller, err := newTrafficController(limits)
	if err != nil {
		return err
	}
	s.traffic = controller
	return nil
}

func (s *Server) trafficHandler(
	surface traffic.Surface,
	next http.HandlerFunc,
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		s.metrics.ObserveRequest(surface)
		control := &s.traffic.surfaces[surface]
		now := s.now()
		onionIngress := s.consumeOnionIngressMarker(request)
		allowed, retryAfter := control.identityLimiter.Allow(
			requestTrafficIdentityKey(request, surface, onionIngress), now,
		)
		if !allowed {
			s.metrics.ObserveResponse(surface, http.StatusTooManyRequests)
			s.metrics.ObserveRejection(surface, rejectionIdentityRateLimit)
			writeTrafficRejection(writer, "rate_limited", retryAfter)
			return
		}
		allowed, retryAfter = control.connectionLimiter.Allow(
			requestTrafficConnectionKey(request, surface, onionIngress), now,
		)
		if !allowed {
			s.metrics.ObserveResponse(surface, http.StatusTooManyRequests)
			s.metrics.ObserveRejection(surface, rejectionConnectionRateLimit)
			writeTrafficRejection(writer, "rate_limited", retryAfter)
			return
		}
		select {
		case control.concurrency <- struct{}{}:
		case <-request.Context().Done():
			return
		default:
			s.metrics.ObserveResponse(surface, http.StatusTooManyRequests)
			s.metrics.ObserveRejection(surface, rejectionConcurrencyLimit)
			writeTrafficRejection(writer, "concurrency_limited", 1)
			return
		}
		recorder := &statusRecorder{ResponseWriter: writer, status: http.StatusOK}
		defer func() {
			<-control.concurrency
			if recovered := recover(); recovered != nil {
				s.metrics.ObserveResponse(surface, http.StatusInternalServerError)
				s.metrics.ObserveRejection(surface, rejectionInternal)
				panic(recovered)
			}
			s.metrics.ObserveResponse(surface, recorder.status)
			if class, rejected := rejectionForStatus(recorder.status); rejected {
				s.metrics.ObserveRejection(surface, class)
			}
		}()
		next.ServeHTTP(recorder, request)
	})
}

func requestTrafficIdentityKey(
	request *http.Request,
	surface traffic.Surface,
	onionIngress bool,
) traffic.Key {
	authorization := request.Header.Get("Authorization")
	if strings.HasPrefix(authorization, "Bearer ") && len(authorization) > len("Bearer ") {
		return traffic.Key(sha256.Sum256([]byte(
			"facets-server-traffic-credential-v1\x00" + strings.TrimPrefix(authorization, "Bearer "),
		)))
	}
	scope := surface.Name() + "\x00" + request.Pattern
	if routeID, err := uuid.Parse(request.PathValue("routeID")); err == nil && routeID != uuid.Nil {
		scope = "route\x00" + routeID.String()
	}
	address := trustedConnectionAddress(request.RemoteAddr)
	domain := "facets-server-traffic-route-v1\x00"
	if onionIngress {
		address = "concealed"
		domain = "facets-server-traffic-onion-route-v1\x00"
	}
	return traffic.Key(sha256.Sum256([]byte(domain + address + "\x00" + scope)))
}

func requestTrafficConnectionKey(
	request *http.Request,
	surface traffic.Surface,
	onionIngress bool,
) traffic.Key {
	if onionIngress {
		return traffic.Key(sha256.Sum256([]byte(
			"facets-server-traffic-onion-surface-v1\x00" + surface.Name(),
		)))
	}
	return traffic.Key(sha256.Sum256([]byte(
		"facets-server-traffic-address-v1\x00" + trustedConnectionAddress(request.RemoteAddr),
	)))
}

func (s *Server) consumeOnionIngressMarker(request *http.Request) bool {
	transport := request.Header.Get(headerIngressTransport)
	encodedToken := request.Header.Get(headerOnionIngressToken)
	request.Header.Del(headerIngressTransport)
	request.Header.Del(headerOnionIngressToken)
	if !s.onionIngressEnabled || transport != ingressTransportOnion {
		return false
	}
	token, err := base64.RawURLEncoding.Strict().DecodeString(encodedToken)
	if err != nil || len(token) != 32 ||
		base64.RawURLEncoding.EncodeToString(token) != encodedToken {
		return false
	}
	digest := sha256.Sum256(append(
		[]byte("facets-server-onion-ingress-token-v1\x00"),
		token...,
	))
	return subtle.ConstantTimeCompare(
		digest[:],
		s.onionIngressTokenDigest[:],
	) == 1
}

func trustedConnectionAddress(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap().String()
	}
	if host == "" {
		return "unknown"
	}
	return strings.ToLower(host)
}

func writeTrafficRejection(writer http.ResponseWriter, code string, retryAfter int) {
	if retryAfter < 1 {
		retryAfter = 1
	}
	writer.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	writeJSON(writer, http.StatusTooManyRequests, struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{Error: struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: "The request exceeded a bounded traffic limit."}})
}
