package backupcustody

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

type AuthorityHistory interface {
	ResolveBackupCustodyAuthority(
		context.Context,
		serviceauthority.BackupCustodyAuthorityContext,
	) (serviceauthority.TrustAnchor, serviceauthority.Manifest, error)
}

type Clock interface{ Now() time.Time }

type Coordinator struct {
	Store                  Store
	Content                *ContentStore
	Registry               *serviceauthority.BindingRegistry
	Signer                 *serviceauthority.DeploymentSigner
	AuthorityHistory       AuthorityHistory
	Clock                  Clock
	MaximumChunkBytes      uint64
	MaximumGenerationBytes uint64
	NewID                  func() uuid.UUID
}

func (coordinator *Coordinator) validate() error {
	if coordinator == nil || coordinator.Store == nil || coordinator.Content == nil ||
		coordinator.Registry == nil || coordinator.Signer == nil || coordinator.Clock == nil ||
		coordinator.AuthorityHistory == nil ||
		coordinator.MaximumChunkBytes == 0 || coordinator.MaximumGenerationBytes == 0 ||
		coordinator.MaximumChunkBytes > coordinator.MaximumGenerationBytes ||
		coordinator.MaximumGenerationBytes > math.MaxInt64 || coordinator.NewID == nil {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (coordinator *Coordinator) BeginUpload(
	ctx context.Context,
	credential TargetCredential,
	request PublishRequest,
	binding serviceauthority.RequestBinding,
) (UploadRecord, error) {
	if coordinator.validate() != nil || request.Validate() != nil ||
		request.Generation > math.MaxInt64 || !targetReferencesEqual(credential.Reference, request.Credential) {
		return UploadRecord{}, serviceauthority.ErrInvalid
	}
	use, err := credentialUse(credential)
	if err != nil {
		return UploadRecord{}, serviceauthority.ErrInvalid
	}
	requestBytes, err := canonicalRequest(request)
	if err != nil {
		return UploadRecord{}, err
	}
	lease, authorization, now, err := coordinator.authorizeMutation(ctx, request.Credential.AccountID, binding)
	if err != nil {
		return UploadRecord{}, err
	}
	defer lease.Release()
	if !credential.Reference.Admits(Publish, now.UnixMilli()) {
		return UploadRecord{}, ErrUnauthorized
	}
	upload := UploadRecord{
		AccountID: request.Credential.AccountID, TargetID: request.Credential.TargetID, BackupSetID: request.Credential.BackupSetID,
		UploadID: coordinator.NewID(), Request: request, RequestBytes: requestBytes,
		CreatedAtMilliseconds: now.UnixMilli(),
	}
	if upload.UploadID == uuid.Nil {
		return UploadRecord{}, serviceauthority.ErrInvalid
	}
	reserved, created, err := coordinator.Store.ReserveUpload(ctx, upload, use, coordinator.Clock, authorization)
	if err != nil {
		return UploadRecord{}, err
	}
	if created {
		if err := coordinator.Content.PrepareUpload(reserved.UploadID); err != nil {
			return UploadRecord{}, err
		}
	} else if !reserved.Committed {
		if err := coordinator.Content.EnsureStaging(reserved, coordinator.MaximumChunkBytes, coordinator.MaximumGenerationBytes); err != nil {
			return UploadRecord{}, err
		}
	}
	return reserved, nil
}

func (coordinator *Coordinator) AppendUploadChunk(
	ctx context.Context,
	credential TargetCredential,
	binding serviceauthority.RequestBinding,
	uploadID uuid.UUID,
	offset uint64,
	chunk []byte,
	chunkSHA256 string,
) (uint64, error) {
	if coordinator.validate() != nil || uploadID == uuid.Nil || len(chunk) == 0 ||
		!validHexDigest(chunkSHA256) {
		return 0, serviceauthority.ErrInvalid
	}
	use, useErr := credentialUse(credential)
	if useErr != nil {
		return 0, serviceauthority.ErrInvalid
	}
	digest := sha256.Sum256(chunk)
	if !bytes.Equal([]byte(hex.EncodeToString(digest[:])), []byte(chunkSHA256)) {
		return 0, serviceauthority.ErrInvalid
	}
	lease, authorization, now, err := coordinator.authorizeMutation(ctx, credential.Reference.AccountID, binding)
	if err != nil {
		return 0, err
	}
	defer lease.Release()
	if !credential.Reference.Admits(Publish, now.UnixMilli()) {
		return 0, ErrUnauthorized
	}
	appendLease, err := coordinator.Store.BeginUploadAppend(ctx, credential.Reference.AccountID, uploadID, offset, chunkSHA256, uint64(len(chunk)), use, coordinator.Clock, authorization)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = appendLease.Abort(context.WithoutCancel(ctx))
		}
	}()
	upload := appendLease.Upload()
	if !targetReferencesEqual(upload.Request.Credential, credential.Reference) || upload.TargetID != credential.Reference.TargetID ||
		upload.BackupSetID != credential.Reference.BackupSetID {
		return 0, ErrConflict
	}
	if existingNext := appendLease.ExistingNextOffset(); existingNext != nil {
		if err := coordinator.Content.VerifyUploadRange(upload, offset, uint64(len(chunk)), chunkSHA256); err != nil {
			return 0, err
		}
		if err := appendLease.Abort(ctx); err != nil {
			return 0, err
		}
		committed = true
		return *existingNext, nil
	}
	if upload.TargetID != credential.Reference.TargetID || upload.CommittedBytes != offset {
		return 0, ErrConflict
	}
	next, err := coordinator.Content.ReconcileAndAppend(
		uploadID, offset, chunk, coordinator.MaximumChunkBytes, coordinator.MaximumGenerationBytes,
	)
	if err != nil {
		return 0, err
	}
	criticalContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := appendLease.Commit(criticalContext, next); err != nil {
		return 0, err
	}
	committed = true
	return next, nil
}

func (coordinator *Coordinator) FinalizeUpload(
	ctx context.Context,
	credential TargetCredential,
	binding serviceauthority.RequestBinding,
	uploadID uuid.UUID,
) (serviceauthority.BackupCustodyReceipt, error) {
	if coordinator.validate() != nil || uploadID == uuid.Nil {
		return serviceauthority.BackupCustodyReceipt{}, serviceauthority.ErrInvalid
	}
	use, useErr := credentialUse(credential)
	if useErr != nil {
		return serviceauthority.BackupCustodyReceipt{}, serviceauthority.ErrInvalid
	}
	// Exact committed retries are resolved before current freshness checks. The
	// stored receipt remains evidence of the historical accepted mutation.
	if existing, err := coordinator.Store.LoadGenerationByUpload(ctx, credential.Reference.AccountID, uploadID); err == nil {
		payload, verifyErr := existing.CustodyReceipt.VerifiedPayload()
		if verifyErr == nil && existing.ValidateStored() == nil && payload.CredentialID == credential.Reference.CredentialID &&
			existing.Generation.AccountID == credential.Reference.AccountID && existing.Generation.TargetID == credential.Reference.TargetID &&
			existing.Generation.BackupSetID == credential.Reference.BackupSetID &&
			coordinator.Store.AuthorizeHistoricalCredential(ctx, use, payload.CredentialGrantReferenceDigest, payload.ControlHeadReferenceDigest, Publish, payload.IssuedAtMilliseconds) == nil {
			return existing.CustodyReceipt, nil
		}
		return serviceauthority.BackupCustodyReceipt{}, ErrConflict
	} else if !errors.Is(err, ErrNotFound) {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	lease, authorization, now, err := coordinator.authorizeMutation(ctx, credential.Reference.AccountID, binding)
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	defer lease.Release()
	finalization, err := coordinator.Store.BeginFinalization(ctx, credential.Reference.AccountID, uploadID, use, authorization)
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = finalization.Abort(context.WithoutCancel(ctx))
		}
	}()
	upload, target := finalization.Upload(), finalization.Target()
	if upload.TargetID != target.TargetID || upload.BackupSetID != target.BackupSetID ||
		!targetReferencesEqual(upload.Request.Credential, credential.Reference) {
		return serviceauthority.BackupCustodyReceipt{}, ErrUnauthorized
	}
	if existing := finalization.Existing(); existing != nil {
		payload, verifyErr := existing.CustodyReceipt.VerifiedPayload()
		if verifyErr != nil || existing.ValidateStored() != nil || payload.CredentialID != credential.Reference.CredentialID ||
			existing.Generation.AccountID != target.AccountID || existing.Generation.TargetID != target.TargetID ||
			existing.Generation.BackupSetID != target.BackupSetID || existing.Generation.UploadID != upload.UploadID {
			return serviceauthority.BackupCustodyReceipt{}, ErrConflict
		}
		if err := finalization.Abort(ctx); err != nil {
			return serviceauthority.BackupCustodyReceipt{}, err
		}
		committed = true
		return existing.CustodyReceipt, nil
	}
	if !credential.Reference.Admits(Publish, now.UnixMilli()) || upload.TargetID != target.TargetID {
		return serviceauthority.BackupCustodyReceipt{}, ErrUnauthorized
	}
	file, err := coordinator.Content.OpenFinalizationBytes(target.AccountID, target.TargetID, upload.Request.Generation, uploadID)
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	summary, validationErr := ValidateOuterStream(file, coordinator.MaximumGenerationBytes)
	closeErr := file.Close()
	if validationErr != nil || closeErr != nil || summary.OuterByteCount != upload.CommittedBytes {
		return serviceauthority.BackupCustodyReceipt{}, serviceauthority.ErrInvalid
	}
	record, err := generationFromSummary(upload, target, summary)
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	// Stream validation may be long. Reauthorize against the server clock while
	// retaining the account mutation lease, immediately before durable effects.
	freshNow := coordinator.Clock.Now()
	freshAuthorization, err := coordinator.Registry.AuthorizeMutationAt(binding, freshNow)
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	if !credential.Reference.Admits(Publish, freshNow.UnixMilli()) {
		return serviceauthority.BackupCustodyReceipt{}, ErrUnauthorized
	}
	if err := finalization.Revalidate(ctx, freshAuthorization); err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	objectPath, err := coordinator.Content.Publish(record)
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	authority := authorityContext(freshAuthorization)
	credentialAuthority := finalization.CredentialAuthority()
	payload := serviceauthority.BackupCustodyReceiptPayload{
		Version:   serviceauthority.BackupCustodyReceiptVersion,
		ReceiptID: coordinator.NewID(), RequestID: upload.Request.RequestID,
		CredentialID: credential.Reference.CredentialID, Authority: authority,
		Generation: record, IssuedAtMilliseconds: freshNow.UnixMilli(), Kind: serviceauthority.BackupCustodyCommittedKind,
		CredentialGrantReferenceDigest: credentialAuthority.GrantReferenceDigest,
		ControlHeadReferenceDigest:     credentialAuthority.ControlHead.ReferenceDigest,
	}
	receipt, err := coordinator.Signer.SignBackupCustodyReceipt(payload)
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	freshAnchor, freshManifest, err := coordinator.AuthorityHistory.ResolveBackupCustodyAuthority(ctx, authority)
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	if _, err := receipt.Authorize(freshAnchor, freshManifest); err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	stored, err := generationStorage(record, receipt, objectPath)
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	criticalContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := finalization.Commit(criticalContext, stored); err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	committed = true
	return receipt, nil
}

func (coordinator *Coordinator) ConfirmRetention(
	ctx context.Context,
	credential TargetCredential,
	request RetentionProofRequest,
	binding serviceauthority.RequestBinding,
) (serviceauthority.BackupCustodyReceipt, error) {
	if coordinator.validate() != nil || coordinator.AuthorityHistory == nil || request.Validate() != nil ||
		!targetReferencesEqual(credential.Reference, request.Credential) {
		return serviceauthority.BackupCustodyReceipt{}, serviceauthority.ErrInvalid
	}
	use, useErr := credentialUse(credential)
	if useErr != nil {
		return serviceauthority.BackupCustodyReceipt{}, serviceauthority.ErrInvalid
	}
	requestBytes, err := canonicalRequest(request)
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	// Historical exact retry still requires possession of the exact stored
	// target bearer, but does not require current authority freshness.
	if existing, loadErr := coordinator.Store.LoadRetentionByRequest(ctx, request.Credential.AccountID, request.RequestID); loadErr == nil {
		payload, payloadErr := existing.Receipt.VerifiedPayload()
		if payloadErr == nil && existing.ValidateStored() == nil && bytes.Equal(existing.RequestBytes, requestBytes) &&
			coordinator.Store.AuthorizeHistoricalCredential(ctx, use, payload.CredentialGrantReferenceDigest, payload.ControlHeadReferenceDigest, RetentionProof, payload.IssuedAtMilliseconds) == nil {
			return existing.Receipt, nil
		}
		return serviceauthority.BackupCustodyReceipt{}, ErrConflict
	} else if !errors.Is(loadErr, ErrNotFound) {
		return serviceauthority.BackupCustodyReceipt{}, loadErr
	}
	lease, authorization, now, err := coordinator.authorizeMutation(ctx, request.Credential.AccountID, binding)
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	defer lease.Release()
	if now.UnixMilli() < request.MinimumRetainedThroughMilliseconds {
		return serviceauthority.BackupCustodyReceipt{}, serviceauthority.ErrInvalid
	}
	confirmation, err := coordinator.Store.BeginRetention(ctx, request, requestBytes, use, authorization)
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	retentionCommitted := false
	defer func() {
		if !retentionCommitted {
			_ = confirmation.Abort(context.WithoutCancel(ctx))
		}
	}()
	if existing := confirmation.Existing(); existing != nil {
		if existing.ValidateStored() != nil || !bytes.Equal(existing.RequestBytes, requestBytes) {
			return serviceauthority.BackupCustodyReceipt{}, ErrConflict
		}
		if err := confirmation.Abort(ctx); err != nil {
			return serviceauthority.BackupCustodyReceipt{}, err
		}
		retentionCommitted = true
		return existing.Receipt, nil
	}
	if now.UnixMilli() < confirmation.ServerTimeHighWaterMilliseconds() {
		return serviceauthority.BackupCustodyReceipt{}, ErrClockRollback
	}
	target := confirmation.Target()
	if !credential.Reference.Admits(RetentionProof, now.UnixMilli()) {
		return serviceauthority.BackupCustodyReceipt{}, ErrUnauthorized
	}
	generation := confirmation.Generation()
	if generation.CustodyReceiptReferenceDigest != request.CustodyReceiptReferenceDigest ||
		generation.Generation.TargetID != target.TargetID {
		return serviceauthority.BackupCustodyReceipt{}, serviceauthority.ErrInvalid
	}
	custodyPayload, err := generation.CustodyReceipt.VerifiedPayload()
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	anchor, manifest, err := coordinator.AuthorityHistory.ResolveBackupCustodyAuthority(ctx, custodyPayload.Authority)
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	if _, err := generation.CustodyReceipt.Authorize(anchor, manifest); err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	if err := coordinator.Content.VerifyObject(generation.Generation, generation.ObjectPath); err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	freshNow := coordinator.Clock.Now()
	freshAuthorization, err := coordinator.Registry.AuthorizeMutationAt(binding, freshNow)
	if freshNow.UnixMilli() < now.UnixMilli() || freshNow.UnixMilli() < confirmation.ServerTimeHighWaterMilliseconds() {
		return serviceauthority.BackupCustodyReceipt{}, ErrClockRollback
	}
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	if freshNow.UnixMilli() < request.MinimumRetainedThroughMilliseconds {
		return serviceauthority.BackupCustodyReceipt{}, serviceauthority.ErrInvalid
	}
	if !credential.Reference.Admits(RetentionProof, freshNow.UnixMilli()) {
		return serviceauthority.BackupCustodyReceipt{}, ErrUnauthorized
	}
	if err := confirmation.Revalidate(ctx, freshAuthorization); err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	payload, err := serviceauthority.NewBackupRetentionReceiptPayload(
		coordinator.NewID(), authorityContext(freshAuthorization), request.RequestID,
		credential.Reference.CredentialID, confirmation.CredentialAuthority().GrantReferenceDigest,
		confirmation.CredentialAuthority().ControlHead.ReferenceDigest, generation.CustodyReceipt, anchor, manifest,
		freshNow.UnixMilli(), freshNow.UnixMilli(),
	)
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	receipt, err := coordinator.Signer.SignBackupCustodyReceipt(payload)
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	freshAnchor, freshManifest, err := coordinator.AuthorityHistory.ResolveBackupCustodyAuthority(ctx, authorityContext(freshAuthorization))
	if err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	if _, err := receipt.Authorize(freshAnchor, freshManifest); err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	encoded, err := receipt.CanonicalJSON()
	reference, referenceErr := receipt.ReferenceDigest()
	if err != nil || referenceErr != nil {
		return serviceauthority.BackupCustodyReceipt{}, serviceauthority.ErrInvalid
	}
	record := RetentionRecord{AccountID: target.AccountID, Request: request, RequestBytes: requestBytes,
		Receipt: receipt, ReceiptBytes: encoded, ReceiptReferenceDigest: reference}
	criticalContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := confirmation.Commit(criticalContext, record, freshNow.UnixMilli()); err != nil {
		return serviceauthority.BackupCustodyReceipt{}, err
	}
	retentionCommitted = true
	return receipt, nil
}

func (coordinator *Coordinator) Read(
	ctx context.Context,
	credential TargetCredential,
	request ReadRequest,
	binding serviceauthority.RequestBinding,
) (ReadResult, error) {
	if coordinator.validate() != nil || request.Validate() != nil || !targetReferencesEqual(credential.Reference, request.Credential) {
		return ReadResult{}, serviceauthority.ErrInvalid
	}
	use, err := credentialUse(credential)
	if err != nil {
		return ReadResult{}, serviceauthority.ErrInvalid
	}
	scope := serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: request.Credential.AccountID}
	if binding.Scope != scope {
		return ReadResult{}, ErrUnauthorized
	}
	lease, err := coordinator.Registry.AcquireMutationLease(ctx, scope)
	if err != nil {
		return ReadResult{}, err
	}
	defer lease.Release()
	now := coordinator.Clock.Now()
	if coordinator.Registry.AuthorizeRequestAt(binding, serviceauthority.RequestRead, now) != nil ||
		!credential.Reference.Admits(Read, now.UnixMilli()) {
		return ReadResult{}, ErrUnauthorized
	}
	authorization, err := newReadAuthorization(binding, now)
	if err != nil {
		return ReadResult{}, err
	}
	target, generation, err := coordinator.Store.ReadSnapshot(ctx, authorization, use, coordinator.Clock, request.Credential.TargetID, request.GenerationReferenceDigest)
	if err != nil {
		return ReadResult{}, err
	}
	if generation.ValidateStored() != nil || generation.Generation.TargetID != target.TargetID ||
		generation.Generation.BackupSetID != target.BackupSetID {
		return ReadResult{}, ErrNotFound
	}
	file, err := coordinator.Content.OpenObject(generation.Generation, generation.ObjectPath)
	if err != nil {
		return ReadResult{}, err
	}
	return ReadResult{Generation: generation, Content: file}, nil
}

func (coordinator *Coordinator) authorizeMutation(ctx context.Context, accountID uuid.UUID, binding serviceauthority.RequestBinding) (*serviceauthority.ScopeLease, serviceauthority.MutationAuthorization, time.Time, error) {
	scope := serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: accountID}
	if binding.Scope != scope {
		return nil, serviceauthority.MutationAuthorization{}, time.Time{}, serviceauthority.ErrInvalid
	}
	lease, err := coordinator.Registry.AcquireMutationLease(ctx, scope)
	if err != nil {
		return nil, serviceauthority.MutationAuthorization{}, time.Time{}, err
	}
	now := coordinator.Clock.Now()
	authorization, err := coordinator.Registry.AuthorizeMutationAt(binding, now)
	if err != nil {
		lease.Release()
		return nil, serviceauthority.MutationAuthorization{}, time.Time{}, err
	}
	return lease, authorization, now, nil
}

func authorityContext(authorization serviceauthority.MutationAuthorization) serviceauthority.BackupCustodyAuthorityContext {
	return serviceauthority.BackupCustodyAuthorityContext{
		Scope: authorization.Scope(), AuthorityRevision: authorization.AuthorityRevision(),
		AuthorityManifestDigest: authorization.AuthorityManifestDigest(), DeploymentID: authorization.DeploymentID(),
	}
}

func generationFromSummary(upload UploadRecord, target TargetRecord, summary OuterWireSummary) (serviceauthority.BackupCustodyGenerationRecord, error) {
	request := upload.Request
	if request.Generation > math.MaxInt64 || summary.Generation > math.MaxInt64 || summary.BackupSetID != target.BackupSetID || summary.Generation != request.Generation {
		return serviceauthority.BackupCustodyGenerationRecord{}, serviceauthority.ErrInvalid
	}
	predecessorReference := (*string)(nil)
	if request.Generation == 1 {
		if target.Head != nil || target.HeadReferenceDigest != nil || request.ExpectedHeadReferenceDigest != nil || summary.PredecessorOuterDigest != nil {
			return serviceauthority.BackupCustodyGenerationRecord{}, ErrConflict
		}
	} else {
		if target.Head == nil || target.HeadReferenceDigest == nil || request.ExpectedHeadReferenceDigest == nil ||
			*request.ExpectedHeadReferenceDigest != *target.HeadReferenceDigest || summary.PredecessorOuterDigest == nil ||
			*summary.PredecessorOuterDigest != target.Head.OuterDigest || request.Generation != target.Head.Generation+1 {
			return serviceauthority.BackupCustodyGenerationRecord{}, ErrConflict
		}
		predecessorReference = cloneString(target.HeadReferenceDigest)
	}
	record := serviceauthority.BackupCustodyGenerationRecord{
		Version: Version, AccountID: target.AccountID, TargetID: target.TargetID, BackupSetID: target.BackupSetID,
		Generation: request.Generation, UploadID: upload.UploadID, OuterDigest: summary.OuterDigest,
		OuterByteCount: summary.OuterByteCount, PredecessorReferenceDigest: predecessorReference,
	}
	if record.Validate() != nil {
		return serviceauthority.BackupCustodyGenerationRecord{}, serviceauthority.ErrInvalid
	}
	return record, nil
}

func generationStorage(record serviceauthority.BackupCustodyGenerationRecord, receipt serviceauthority.BackupCustodyReceipt, objectPath string) (GenerationRecord, error) {
	generationReference, err := record.ReferenceDigest()
	receiptReference, receiptErr := receipt.ReferenceDigest()
	receiptBytes, encodeErr := receipt.CanonicalJSON()
	if err != nil || receiptErr != nil || encodeErr != nil {
		return GenerationRecord{}, serviceauthority.ErrInvalid
	}
	return GenerationRecord{Generation: record, GenerationReferenceDigest: generationReference,
		ObjectPath: objectPath, CustodyReceipt: receipt, CustodyReceiptBytes: receiptBytes,
		CustodyReceiptReferenceDigest: receiptReference}, nil
}
