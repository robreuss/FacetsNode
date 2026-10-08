package boxcontrol

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
)

// This is an explicit lower-bound transport profile, not a routine test or an
// end-to-end Worker benchmark. It includes participant challenge/signature,
// exact-payload HTTP encode/decode, in-memory Box custody, claim, response and
// requester status. It deliberately excludes TCP/TLS, PostgreSQL, polling,
// encrypted Worker execution and inference.
func TestProfileSharedWorkerOperationHTTP(t *testing.T) {
	if os.Getenv("FACETS_BOX_WORKER_CARRIAGE_PROFILE") != "1" {
		t.Skip("set FACETS_BOX_WORKER_CARRIAGE_PROFILE=1 to run")
	}
	profiles := []struct {
		name          string
		requestBytes  int
		responseBytes int
		iterations    int
	}{
		{name: "control-1k", requestBytes: 1_024, responseBytes: 1_024, iterations: 60},
		{name: "product-16k", requestBytes: 16 * 1_024, responseBytes: 4 * 1_024, iterations: 60},
		{name: "large-256k", requestBytes: 256 * 1_024, responseBytes: 64 * 1_024, iterations: 30},
		{name: "envelope-1m", requestBytes: 1_024 * 1_024, responseBytes: 1_024 * 1_024, iterations: 12},
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			owner, requester, _, handler, ownerToken, requesterToken, worker := sharedWorkerAccessHTTPFixture(t)
			grant := approveSharedWorkerAccessHTTP(
				t, handler, ownerToken, requesterToken, &owner, &requester, worker,
			)
			requestBytes := bytes.Repeat([]byte{0x91, 0x22, 0x00, 0xff}, (profile.requestBytes+3)/4)[:profile.requestBytes]
			responseBytes := bytes.Repeat([]byte{0x44, 0x00, 0xac}, (profile.responseBytes+2)/3)[:profile.responseBytes]
			var endToEnd, enqueue, claim, respond, status []time.Duration
			for index := 0; index < profile.iterations; index++ {
				started := time.Now()
				operation := BoxSharedWorkerOperation{
					Version: 1, OperationID: uuid.New(), BoxID: worker.BoxID,
					WorkerID: worker.WorkerID, AccessGrantID: grant.GrantID,
					RequesterParticipantID: requester.anchor.ParticipantID,
					RequesterDeviceID:      requester.device.DeviceID,
					JobID:                  uuid.New(), RunID: uuid.New(), Attempt: uint64(index + 1),
					CapabilitiesDigest: worker.CapabilitiesDigest,
					RequestDigest:      SharedWorkerOperationDigest(requestBytes), RequestBytes: requestBytes,
					RequestedAtMilliseconds: requester.now,
					ExpiresAtMilliseconds:   requester.now + 60_000,
				}
				operationPayload, err := json.Marshal(operation)
				if err != nil {
					t.Fatal(err)
				}
				stage := time.Now()
				issueParticipantChallengeHTTP(t, handler, requesterToken, &requester)
				enqueued := postSharedWorkerOperationPayload(t, handler, http.MethodPost,
					"/v1/shared-workers/"+worker.WorkerID.String()+"/operations", requesterToken,
					sharedWorkerOperationEnqueueBody{
						Version: 1, OperationPayload: operationPayload, ChallengeID: requester.challengeID,
						Proof: signedParticipantActionProof(
							t, requester, ParticipantActionEnqueueWorkerOperation, operationPayload,
						),
					})
				if enqueued.Code != http.StatusCreated {
					t.Fatalf("enqueue status %d: %s", enqueued.Code, enqueued.Body.String())
				}
				enqueue = append(enqueue, time.Since(stage))

				claimValue := BoxSharedWorkerOperationClaim{
					Version: 1, ClaimID: uuid.New(), BoxID: worker.BoxID, WorkerID: worker.WorkerID,
					OwnerParticipantID: owner.anchor.ParticipantID, OwnerDeviceID: owner.device.DeviceID,
					RequestedAtMilliseconds: owner.now, ExpiresAtMilliseconds: owner.now + 30_000,
				}
				claimPayload, err := json.Marshal(claimValue)
				if err != nil {
					t.Fatal(err)
				}
				stage = time.Now()
				issueParticipantChallengeHTTP(t, handler, ownerToken, &owner)
				claimed := postSharedWorkerOperationPayload(t, handler, http.MethodPost,
					"/v1/shared-workers/"+worker.WorkerID.String()+"/operation-claims", ownerToken,
					sharedWorkerOperationClaimBody{
						Version: 1, ClaimPayload: claimPayload, ChallengeID: owner.challengeID,
						Proof: signedParticipantActionProof(
							t, owner, ParticipantActionClaimWorkerOperation, claimPayload,
						),
					})
				if claimed.Code != http.StatusOK {
					t.Fatalf("claim status %d: %s", claimed.Code, claimed.Body.String())
				}
				claim = append(claim, time.Since(stage))

				responseValue := BoxSharedWorkerOperationResponse{
					Version: 1, OperationID: operation.OperationID, ClaimID: claimValue.ClaimID,
					BoxID: worker.BoxID, WorkerID: worker.WorkerID,
					OwnerParticipantID: owner.anchor.ParticipantID, OwnerDeviceID: owner.device.DeviceID,
					ResponseDigest: SharedWorkerOperationDigest(responseBytes), ResponseBytes: responseBytes,
					RespondedAtMilliseconds: owner.now,
				}
				responsePayload, err := json.Marshal(responseValue)
				if err != nil {
					t.Fatal(err)
				}
				stage = time.Now()
				issueParticipantChallengeHTTP(t, handler, ownerToken, &owner)
				completed := postSharedWorkerOperationPayload(t, handler, http.MethodPost,
					"/v1/shared-worker-operations/"+operation.OperationID.String()+"/response", ownerToken,
					sharedWorkerOperationResponseBody{
						Version: 1, ResponsePayload: responsePayload, ChallengeID: owner.challengeID,
						Proof: signedParticipantActionProof(
							t, owner, ParticipantActionRespondWorkerOperation, responsePayload,
						),
					})
				if completed.Code != http.StatusNoContent {
					t.Fatalf("response status %d: %s", completed.Code, completed.Body.String())
				}
				respond = append(respond, time.Since(stage))

				stage = time.Now()
				statusRequest := httptestRequest(http.MethodGet,
					"/v1/shared-worker-operations/"+operation.OperationID.String(), nil, requesterToken)
				statusResponse := responseFor(handler, statusRequest)
				if statusResponse.Code != http.StatusOK {
					t.Fatalf("status code %d: %s", statusResponse.Code, statusResponse.Body.String())
				}
				status = append(status, time.Since(stage))
				endToEnd = append(endToEnd, time.Since(started))
			}
			t.Logf(
				"lower-bound in-process HTTP+memory carriage: iterations=%d request=%d response=%d end_to_end_p50=%s end_to_end_p95=%s enqueue_p50=%s claim_p50=%s respond_p50=%s status_p50=%s",
				profile.iterations, profile.requestBytes, profile.responseBytes,
				profileDuration(endToEnd, 0.50), profileDuration(endToEnd, 0.95),
				profileDuration(enqueue, 0.50), profileDuration(claim, 0.50),
				profileDuration(respond, 0.50), profileDuration(status, 0.50),
			)
		})
	}
}

func TestProfileSharedWorkerOperationLoopbackTLS(t *testing.T) {
	if os.Getenv("FACETS_BOX_WORKER_CARRIAGE_PROFILE") != "1" {
		t.Skip("set FACETS_BOX_WORKER_CARRIAGE_PROFILE=1 to run")
	}
	profiles := []struct {
		name          string
		requestBytes  int
		responseBytes int
		iterations    int
	}{
		{name: "product-16k", requestBytes: 16 * 1_024, responseBytes: 4 * 1_024, iterations: 60},
		{name: "envelope-1m", requestBytes: 1_024 * 1_024, responseBytes: 1_024 * 1_024, iterations: 12},
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			owner, requester, _, handler, ownerToken, requesterToken, worker := sharedWorkerAccessHTTPFixture(t)
			grant := approveSharedWorkerAccessHTTP(
				t, handler, ownerToken, requesterToken, &owner, &requester, worker,
			)
			server := httptest.NewTLSServer(handler)
			defer server.Close()
			client := server.Client()
			requestBytes := bytes.Repeat([]byte{0x91, 0x22, 0x00, 0xff}, (profile.requestBytes+3)/4)[:profile.requestBytes]
			responseBytes := bytes.Repeat([]byte{0x44, 0x00, 0xac}, (profile.responseBytes+2)/3)[:profile.responseBytes]
			var endToEnd []time.Duration
			for index := 0; index < profile.iterations; index++ {
				started := time.Now()
				operation := BoxSharedWorkerOperation{
					Version: 1, OperationID: uuid.New(), BoxID: worker.BoxID,
					WorkerID: worker.WorkerID, AccessGrantID: grant.GrantID,
					RequesterParticipantID: requester.anchor.ParticipantID,
					RequesterDeviceID:      requester.device.DeviceID,
					JobID:                  uuid.New(), RunID: uuid.New(), Attempt: uint64(index + 1),
					CapabilitiesDigest: worker.CapabilitiesDigest,
					RequestDigest:      SharedWorkerOperationDigest(requestBytes), RequestBytes: requestBytes,
					RequestedAtMilliseconds: requester.now,
					ExpiresAtMilliseconds:   requester.now + 60_000,
				}
				operationPayload, err := json.Marshal(operation)
				if err != nil {
					t.Fatal(err)
				}
				profileIssueParticipantChallenge(
					t, client, server.URL, requesterToken, &requester,
				)
				enqueueBody := sharedWorkerOperationEnqueueBody{
					Version: 1, OperationPayload: operationPayload, ChallengeID: requester.challengeID,
					Proof: signedParticipantActionProof(
						t, requester, ParticipantActionEnqueueWorkerOperation, operationPayload,
					),
				}
				statusCode, _ := profileNetworkJSON(t, client, server.URL,
					http.MethodPost, "/v1/shared-workers/"+worker.WorkerID.String()+"/operations",
					requesterToken, enqueueBody)
				if statusCode != http.StatusCreated {
					t.Fatalf("enqueue status %d", statusCode)
				}

				claimValue := BoxSharedWorkerOperationClaim{
					Version: 1, ClaimID: uuid.New(), BoxID: worker.BoxID, WorkerID: worker.WorkerID,
					OwnerParticipantID: owner.anchor.ParticipantID, OwnerDeviceID: owner.device.DeviceID,
					RequestedAtMilliseconds: owner.now, ExpiresAtMilliseconds: owner.now + 30_000,
				}
				claimPayload, err := json.Marshal(claimValue)
				if err != nil {
					t.Fatal(err)
				}
				profileIssueParticipantChallenge(t, client, server.URL, ownerToken, &owner)
				claimBody := sharedWorkerOperationClaimBody{
					Version: 1, ClaimPayload: claimPayload, ChallengeID: owner.challengeID,
					Proof: signedParticipantActionProof(
						t, owner, ParticipantActionClaimWorkerOperation, claimPayload,
					),
				}
				statusCode, _ = profileNetworkJSON(t, client, server.URL,
					http.MethodPost, "/v1/shared-workers/"+worker.WorkerID.String()+"/operation-claims",
					ownerToken, claimBody)
				if statusCode != http.StatusOK {
					t.Fatalf("claim status %d", statusCode)
				}

				responseValue := BoxSharedWorkerOperationResponse{
					Version: 1, OperationID: operation.OperationID, ClaimID: claimValue.ClaimID,
					BoxID: worker.BoxID, WorkerID: worker.WorkerID,
					OwnerParticipantID: owner.anchor.ParticipantID, OwnerDeviceID: owner.device.DeviceID,
					ResponseDigest: SharedWorkerOperationDigest(responseBytes), ResponseBytes: responseBytes,
					RespondedAtMilliseconds: owner.now,
				}
				responsePayload, err := json.Marshal(responseValue)
				if err != nil {
					t.Fatal(err)
				}
				profileIssueParticipantChallenge(t, client, server.URL, ownerToken, &owner)
				responseBody := sharedWorkerOperationResponseBody{
					Version: 1, ResponsePayload: responsePayload, ChallengeID: owner.challengeID,
					Proof: signedParticipantActionProof(
						t, owner, ParticipantActionRespondWorkerOperation, responsePayload,
					),
				}
				statusCode, _ = profileNetworkJSON(t, client, server.URL,
					http.MethodPost, "/v1/shared-worker-operations/"+operation.OperationID.String()+"/response",
					ownerToken, responseBody)
				if statusCode != http.StatusNoContent {
					t.Fatalf("response status %d", statusCode)
				}

				statusCode, _ = profileNetworkJSON(t, client, server.URL,
					http.MethodGet, "/v1/shared-worker-operations/"+operation.OperationID.String(),
					requesterToken, nil)
				if statusCode != http.StatusOK {
					t.Fatalf("status code %d", statusCode)
				}
				endToEnd = append(endToEnd, time.Since(started))
			}
			t.Logf(
				"lower-bound loopback TLS+HTTP+memory carriage: iterations=%d request=%d response=%d end_to_end_p50=%s end_to_end_p95=%s",
				profile.iterations, profile.requestBytes, profile.responseBytes,
				profileDuration(endToEnd, 0.50), profileDuration(endToEnd, 0.95),
			)
		})
	}
}

func profileIssueParticipantChallenge(
	t *testing.T,
	client *http.Client,
	baseURL, token string,
	fixture *participantFixture,
) {
	t.Helper()
	body := createParticipantChallengeBody{
		Version: 1, ParticipantID: fixture.anchor.ParticipantID,
		DeviceID: fixture.device.DeviceID,
	}
	statusCode, response := profileNetworkJSON(
		t, client, baseURL, http.MethodPost, "/v1/participant-challenges", token, body,
	)
	if statusCode != http.StatusCreated {
		t.Fatalf("challenge status %d: %s", statusCode, response)
	}
	var challenge participantChallengeResponse
	if err := json.Unmarshal(response, &challenge); err != nil {
		t.Fatal(err)
	}
	fixture.challengeID = challenge.ChallengeID
}

func profileNetworkJSON(
	t *testing.T,
	client *http.Client,
	baseURL, method, path, token string,
	body any,
) (int, []byte) {
	t.Helper()
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request, err := http.NewRequest(method, baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseBytes, err := io.ReadAll(io.LimitReader(
		response.Body, maximumSharedWorkerOperationHTTPBytes+1,
	))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, responseBytes
}

func httptestRequest(method, target string, body *bytes.Reader, token string) *http.Request {
	if body == nil {
		body = bytes.NewReader(nil)
	}
	request, err := http.NewRequest(method, target, body)
	if err != nil {
		panic(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

func responseFor(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func profileDuration(values []time.Duration, quantile float64) time.Duration {
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left] < ordered[right] })
	index := int(float64(len(ordered)-1) * quantile)
	return ordered[index]
}
