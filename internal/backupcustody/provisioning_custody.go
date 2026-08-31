package backupcustody

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

const preparedAccountClaimVersion = 1

type PreparedAccountClaim struct {
	AccountID                    uuid.UUID                          `json:"accountID"`
	Admission                    AccountAdmissionReference          `json:"admission"`
	AdmissionAuthorizationDigest string                             `json:"admissionAuthorizationDigest"`
	ClaimID                      uuid.UUID                          `json:"claimID"`
	ClaimedAtMilliseconds        int64                              `json:"claimedAtMilliseconds"`
	InitialControlAnchor         ControlPossessionAnchor            `json:"initialControlAnchor"`
	InitialEnrollment            serviceauthority.InitialEnrollment `json:"initialEnrollment"`
	Version                      int                                `json:"version"`
}

func (claim PreparedAccountClaim) validate() error {
	expected := serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: claim.AccountID}
	if claim.Version != preparedAccountClaimVersion || claim.AccountID == uuid.Nil || claim.ClaimID == uuid.Nil ||
		claim.ClaimedAtMilliseconds < 0 || claim.Admission.Validate() != nil || claim.Admission.AccountID != claim.AccountID ||
		claim.InitialControlAnchor.VerifyPossession() != nil ||
		claim.InitialControlAnchor.Unsigned.AccountID != claim.AccountID ||
		claim.InitialControlAnchor.Unsigned.ControlGeneration != 1 ||
		!validHexDigest(claim.AdmissionAuthorizationDigest) {
		return serviceauthority.ErrInvalid
	}
	if _, err := claim.InitialEnrollment.ValidateForAdmissionClaim(expected); err != nil {
		return serviceauthority.ErrInvalid
	}
	return nil
}

type PreparedAccountJournal struct {
	parentPath  string
	rootName    string
	parentRoot  *os.Root
	parent      *os.File
	directory   *os.File
	root        *os.Root
	processLock *os.File
}

func OpenPreparedAccountJournal(path string) (*PreparedAccountJournal, error) {
	resolved, err := filepath.Abs(path)
	if err != nil || filepath.Clean(resolved) != resolved {
		return nil, serviceauthority.ErrInvalid
	}
	parentPath, rootName := filepath.Dir(resolved), filepath.Base(resolved)
	parentInfo, err := os.Lstat(parentPath)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("invalid prepared-journal parent: %w", serviceauthority.ErrInvalid)
	}
	parentRoot, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, err
	}
	parent, err := parentRoot.Open(".")
	if err != nil {
		_ = parentRoot.Close()
		return nil, err
	}
	parentOpened, parentOpenedErr := parent.Stat()
	if parentOpenedErr != nil || !os.SameFile(parentInfo, parentOpened) {
		_ = parent.Close()
		_ = parentRoot.Close()
		return nil, serviceauthority.ErrInvalid
	}
	if err := parentRoot.Mkdir(rootName, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		_ = parent.Close()
		_ = parentRoot.Close()
		return nil, err
	}
	if err := parent.Sync(); err != nil {
		_ = parent.Close()
		_ = parentRoot.Close()
		return nil, err
	}
	info, err := parentRoot.Lstat(rootName)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		_ = parent.Close()
		_ = parentRoot.Close()
		return nil, fmt.Errorf("invalid prepared-journal root: %w", serviceauthority.ErrInvalid)
	}
	root, err := os.OpenRoot(resolved)
	if err != nil {
		_ = parent.Close()
		_ = parentRoot.Close()
		return nil, err
	}
	directory, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		_ = parent.Close()
		_ = parentRoot.Close()
		return nil, err
	}
	processLock, err := root.OpenFile(".process.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil || syscall.Flock(int(processLock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		if processLock != nil {
			_ = processLock.Close()
		}
		_ = directory.Close()
		_ = root.Close()
		_ = parent.Close()
		_ = parentRoot.Close()
		return nil, serviceauthority.ErrInvalid
	}
	lockInfo, lockErr := processLock.Stat()
	pathInfo, pathErr := root.Lstat(".process.lock")
	if lockErr != nil || pathErr != nil || !lockInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(lockInfo, pathInfo) || lockInfo.Mode().Perm()&0o077 != 0 {
		_ = syscall.Flock(int(processLock.Fd()), syscall.LOCK_UN)
		_ = processLock.Close()
		_ = directory.Close()
		_ = root.Close()
		_ = parent.Close()
		_ = parentRoot.Close()
		return nil, fmt.Errorf("invalid prepared-journal lock: %w", serviceauthority.ErrInvalid)
	}
	if err := processLock.Sync(); err != nil {
		_ = syscall.Flock(int(processLock.Fd()), syscall.LOCK_UN)
		_ = processLock.Close()
		_ = directory.Close()
		_ = root.Close()
		_ = parent.Close()
		_ = parentRoot.Close()
		return nil, err
	}
	if err := directory.Sync(); err != nil {
		_ = syscall.Flock(int(processLock.Fd()), syscall.LOCK_UN)
		_ = processLock.Close()
		_ = directory.Close()
		_ = root.Close()
		_ = parent.Close()
		_ = parentRoot.Close()
		return nil, err
	}
	journal := &PreparedAccountJournal{parentPath: parentPath, rootName: rootName, parentRoot: parentRoot,
		parent: parent, directory: directory, root: root, processLock: processLock}
	if journal.validateRoot() != nil {
		_ = journal.Close()
		return nil, serviceauthority.ErrInvalid
	}
	return journal, nil
}

func (journal *PreparedAccountJournal) Close() error {
	if journal == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(journal.processLock.Fd()), syscall.LOCK_UN)
	return errors.Join(unlockErr, journal.processLock.Close(), journal.directory.Close(), journal.root.Close(),
		journal.parent.Close(), journal.parentRoot.Close())
}

func (journal *PreparedAccountJournal) Prepare(claim PreparedAccountClaim) (bool, error) {
	if journal == nil || journal.root == nil || claim.validate() != nil || journal.validateRoot() != nil {
		return false, serviceauthority.ErrInvalid
	}
	encoded, err := json.Marshal(claim)
	if err != nil || len(encoded) > 2*1024*1024 {
		return false, serviceauthority.ErrInvalid
	}
	name := claim.AccountID.String() + ".prepared.json"
	staging := claim.AccountID.String() + ".prepared.tmp"
	if existing, readErr := journal.read(name); readErr == nil {
		if !bytes.Equal(existing, encoded) {
			return false, ErrConflict
		}
		if err := journal.syncExact(name); err != nil {
			return false, err
		}
		if err := journal.removeExactStaging(staging, encoded); err != nil {
			return false, err
		}
		return true, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return false, readErr
	}
	if existing, readErr := journal.read(staging); readErr == nil {
		if !bytes.Equal(existing, encoded) {
			return false, ErrConflict
		}
		if err := journal.syncExact(staging); err != nil {
			return false, err
		}
	} else if errors.Is(readErr, os.ErrNotExist) {
		file, err := journal.root.OpenFile(staging, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return false, err
		}
		if written, err := file.Write(encoded); err != nil || written != len(encoded) {
			_ = file.Close()
			return false, fmt.Errorf("write prepared Backup account claim: %w", err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return false, err
		}
		if err := file.Close(); err != nil {
			return false, err
		}
		if err := journal.directory.Sync(); err != nil {
			return false, err
		}
	} else {
		return false, readErr
	}
	if err := journal.root.Link(staging, name); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return false, err
		}
		existing, readErr := journal.read(name)
		if readErr != nil || !bytes.Equal(existing, encoded) {
			return false, ErrConflict
		}
	}
	if err := journal.syncExact(name); err != nil {
		return false, err
	}
	if err := journal.root.Remove(staging); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := journal.directory.Sync(); err != nil {
		return false, err
	}
	return false, nil
}

func (journal *PreparedAccountJournal) Load(accountID uuid.UUID) (PreparedAccountClaim, bool, error) {
	if journal == nil || accountID == uuid.Nil || journal.validateRoot() != nil {
		return PreparedAccountClaim{}, false, serviceauthority.ErrInvalid
	}
	data, err := journal.read(accountID.String() + ".prepared.json")
	if errors.Is(err, os.ErrNotExist) {
		data, err = journal.read(accountID.String() + ".prepared.tmp")
		if errors.Is(err, os.ErrNotExist) {
			return PreparedAccountClaim{}, false, nil
		}
	}
	if err != nil {
		return PreparedAccountClaim{}, false, err
	}
	var claim PreparedAccountClaim
	if err := json.Unmarshal(data, &claim); err != nil || claim.validate() != nil {
		return PreparedAccountClaim{}, false, serviceauthority.ErrInvalid
	}
	return claim, true, nil
}

func (journal *PreparedAccountJournal) RemoveExact(claim PreparedAccountClaim) error {
	if journal == nil || claim.validate() != nil || journal.validateRoot() != nil {
		return serviceauthority.ErrInvalid
	}
	encoded, err := json.Marshal(claim)
	if err != nil {
		return err
	}
	name := claim.AccountID.String() + ".prepared.json"
	staging := claim.AccountID.String() + ".prepared.tmp"
	existing, err := journal.read(name)
	if errors.Is(err, os.ErrNotExist) {
		return journal.removeExactStaging(staging, encoded)
	}
	if err != nil || !bytes.Equal(existing, encoded) {
		return ErrConflict
	}
	if err := journal.root.Remove(name); err != nil {
		return err
	}
	if err := journal.directory.Sync(); err != nil {
		return err
	}
	return journal.removeExactStaging(staging, encoded)
}

func (journal *PreparedAccountJournal) read(name string) ([]byte, error) {
	info, err := journal.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, serviceauthority.ErrInvalid
	}
	file, err := journal.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if current, err := file.Stat(); err != nil || !os.SameFile(info, current) {
		return nil, serviceauthority.ErrInvalid
	}
	limited := io.LimitReader(file, 2*1024*1024+1)
	data, err := io.ReadAll(limited)
	if err != nil || len(data) > 2*1024*1024 {
		return nil, serviceauthority.ErrInvalid
	}
	var claim PreparedAccountClaim
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&claim) != nil || decoder.Decode(&struct{}{}) != io.EOF || claim.validate() != nil {
		return nil, serviceauthority.ErrInvalid
	}
	canonical, err := json.Marshal(claim)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, serviceauthority.ErrInvalid
	}
	return data, nil
}

func (journal *PreparedAccountJournal) syncExact(name string) error {
	file, err := journal.root.Open(name)
	if err != nil {
		return err
	}
	before, err := journal.root.Lstat(name)
	after, statErr := file.Stat()
	if err != nil || statErr != nil || !after.Mode().IsRegular() || after.Mode().Perm()&0o077 != 0 ||
		before.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, after) {
		_ = file.Close()
		return serviceauthority.ErrInvalid
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return journal.directory.Sync()
}

func (journal *PreparedAccountJournal) removeExactStaging(name string, expected []byte) error {
	encoded, err := journal.read(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !bytes.Equal(encoded, expected) {
		return ErrConflict
	}
	if err := journal.root.Remove(name); err != nil {
		return err
	}
	return journal.directory.Sync()
}

func (journal *PreparedAccountJournal) validateRoot() error {
	if journal == nil || journal.root == nil || journal.directory == nil || journal.parent == nil || journal.parentRoot == nil {
		return serviceauthority.ErrInvalid
	}
	parentHeld, parentErr := journal.parent.Stat()
	parentCurrent, parentCurrentErr := os.Lstat(journal.parentPath)
	rootHeld, rootErr := journal.directory.Stat()
	rootCurrent, rootCurrentErr := journal.parentRoot.Lstat(journal.rootName)
	lockHeld, lockErr := journal.processLock.Stat()
	lockCurrent, lockCurrentErr := journal.root.Lstat(".process.lock")
	if parentErr != nil || parentCurrentErr != nil || !parentHeld.IsDir() || parentHeld.Mode().Perm()&0o077 != 0 ||
		parentCurrent.Mode()&os.ModeSymlink != 0 || !os.SameFile(parentHeld, parentCurrent) || rootErr != nil ||
		rootCurrentErr != nil || !rootHeld.IsDir() || rootHeld.Mode().Perm()&0o077 != 0 ||
		rootCurrent.Mode()&os.ModeSymlink != 0 || !os.SameFile(rootHeld, rootCurrent) || lockErr != nil ||
		lockCurrentErr != nil || !lockHeld.Mode().IsRegular() || lockHeld.Mode().Perm()&0o077 != 0 ||
		lockCurrent.Mode()&os.ModeSymlink != 0 || !os.SameFile(lockHeld, lockCurrent) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

type ProvisioningCustody struct {
	Store    Store
	Journal  *PreparedAccountJournal
	Registry *serviceauthority.BindingRegistry
	Signer   *serviceauthority.DeploymentSigner
	Clock    Clock
}

func (custody *ProvisioningCustody) ProvisionAccount(
	ctx context.Context,
	credential AccountAdmissionCredential,
	claimID uuid.UUID,
	enrollment serviceauthority.InitialEnrollment,
	initialControlAnchor ControlPossessionAnchor,
) error {
	if custody == nil || custody.Store == nil || custody.Journal == nil || custody.Registry == nil ||
		custody.Signer == nil || custody.Clock == nil || claimID == uuid.Nil || credential.Reference.AccountID == uuid.Nil ||
		initialControlAnchor.VerifyPossession() != nil ||
		initialControlAnchor.Unsigned.AccountID != credential.Reference.AccountID ||
		initialControlAnchor.Unsigned.ControlGeneration != 1 {
		return serviceauthority.ErrInvalid
	}
	nowMilliseconds := custody.Clock.Now().UnixMilli()
	expectedScope := serviceauthority.Scope{Kind: serviceauthority.ScopeBackupCustody, ScopeID: credential.Reference.AccountID}
	binding, err := serviceauthority.NewInitialBinding(enrollment, custody.Signer, expectedScope, nowMilliseconds)
	if err != nil {
		return err
	}
	authorizationDigest, err := credential.AuthorizationDigest()
	if err != nil {
		return err
	}
	if !bytes.Equal(binding.ManifestRecord(), canonicalJSONUnchecked(enrollment.Manifest)) {
		return serviceauthority.ErrInvalid
	}
	anchorRecord, err := json.Marshal(enrollment.Anchor)
	enrollmentRecord, enrollmentErr := json.Marshal(enrollment)
	if err != nil {
		return err
	}
	if enrollmentErr != nil {
		return enrollmentErr
	}
	if persisted, state, loadErr := custody.Store.LoadAccountClaim(ctx, credential.Reference.AccountID, claimID, credential.Reference.AdmissionID); loadErr == nil {
		if persisted.AccountID != credential.Reference.AccountID || persisted.ClaimID != claimID ||
			persisted.Admission != credential.Reference || persisted.AdmissionAuthorizationDigest != authorizationDigest ||
			persisted.AuthorityRevision != binding.Revision() || persisted.AuthorityManifestDigest != binding.ManifestDigest() ||
			persisted.DeploymentID != binding.LocalDeploymentID() || !bytes.Equal(persisted.InitialAnchorRecord, anchorRecord) ||
			!bytes.Equal(persisted.InitialManifestRecord, binding.ManifestRecord()) ||
			!bytes.Equal(persisted.InitialEnrollmentRecord, enrollmentRecord) || persisted.CreatedAtMilliseconds < 0 ||
			(state != AccountStateStandby && state != AccountStateWritable) {
			return ErrConflict
		}
		claim := PreparedAccountClaim{Version: preparedAccountClaimVersion, AccountID: persisted.AccountID,
			Admission: persisted.Admission, AdmissionAuthorizationDigest: persisted.AdmissionAuthorizationDigest,
			ClaimID: persisted.ClaimID, ClaimedAtMilliseconds: persisted.CreatedAtMilliseconds,
			InitialControlAnchor: persisted.InitialControlAnchor, InitialEnrollment: enrollment}
		if persisted.InitialControlAnchor != initialControlAnchor {
			return ErrConflict
		}
		storedClaim, hasStoredClaim, err := custody.Journal.Load(claim.AccountID)
		if err != nil {
			return err
		}
		if hasStoredClaim {
			if !preparedClaimsEqual(storedClaim, claim) {
				return ErrConflict
			}
			if _, err := custody.Journal.Prepare(claim); err != nil {
				return err
			}
		} else if state == AccountStateStandby {
			if _, err := custody.Journal.Prepare(claim); err != nil {
				return err
			}
		}
		manifest := binding.Manifest()
		if err := custody.Registry.Activate(binding.Scope(), serviceauthority.CurrentBinding{
			Revision: binding.Revision(), Digest: binding.ManifestDigest(), DeploymentID: binding.LocalDeploymentID(), Manifest: &manifest,
		}); err != nil {
			return err
		}
		if err := custody.Store.ActivateAccount(ctx, claim.AccountID, binding.Revision(), binding.ManifestDigest(), binding.LocalDeploymentID(), claim.ClaimedAtMilliseconds); err != nil {
			return err
		}
		_ = custody.Journal.RemoveExact(claim)
		return nil
	} else if !errors.Is(loadErr, ErrNotFound) {
		return loadErr
	}
	claim, existingPreparation, err := custody.Journal.Load(credential.Reference.AccountID)
	if err != nil {
		return err
	}
	if !existingPreparation {
		if nowMilliseconds < 0 || nowMilliseconds >= credential.Reference.ExpiresAtMilliseconds ||
			binding.RequireFreshClaimAt(nowMilliseconds) != nil {
			return serviceauthority.ErrInvalid
		}
		claim = PreparedAccountClaim{Version: preparedAccountClaimVersion, AccountID: credential.Reference.AccountID,
			Admission: credential.Reference, AdmissionAuthorizationDigest: authorizationDigest,
			ClaimID: claimID, ClaimedAtMilliseconds: nowMilliseconds,
			InitialControlAnchor: initialControlAnchor, InitialEnrollment: enrollment}
		if claim.validate() != nil {
			return serviceauthority.ErrInvalid
		}
		if _, err := custody.Journal.Prepare(claim); err != nil {
			return err
		}
	} else {
		expectedEnrollment, encodeErr := json.Marshal(enrollment)
		storedEnrollment, storedErr := json.Marshal(claim.InitialEnrollment)
		if encodeErr != nil || storedErr != nil || claim.ClaimID != claimID || claim.Admission != credential.Reference ||
			claim.AdmissionAuthorizationDigest != authorizationDigest || claim.InitialControlAnchor != initialControlAnchor ||
			!bytes.Equal(expectedEnrollment, storedEnrollment) {
			return ErrConflict
		}
		if _, err := custody.Journal.Prepare(claim); err != nil {
			return err
		}
	}
	account := AccountRecord{AccountID: claim.AccountID, ClaimID: claim.ClaimID, Admission: claim.Admission,
		AdmissionAuthorizationDigest: claim.AdmissionAuthorizationDigest,
		InitialControlAnchor:         claim.InitialControlAnchor,
		AuthorityRevision:            binding.Revision(), AuthorityManifestDigest: binding.ManifestDigest(),
		DeploymentID: binding.LocalDeploymentID(), InitialManifestRecord: binding.ManifestRecord(),
		InitialAnchorRecord: anchorRecord, InitialEnrollmentRecord: enrollmentRecord, InitialBinding: binding,
		CreatedAtMilliseconds: claim.ClaimedAtMilliseconds}
	if err := custody.Store.PrepareAccount(ctx, account); err != nil {
		return err
	}
	manifest := binding.Manifest()
	if err := custody.Registry.Activate(binding.Scope(), serviceauthority.CurrentBinding{
		Revision: binding.Revision(), Digest: binding.ManifestDigest(), DeploymentID: binding.LocalDeploymentID(), Manifest: &manifest,
	}); err != nil {
		return err
	}
	if err := custody.Store.ActivateAccount(ctx, claim.AccountID, binding.Revision(), binding.ManifestDigest(), binding.LocalDeploymentID(), claim.ClaimedAtMilliseconds); err != nil {
		return err
	}
	// Once both the registry and writable account state have committed, the
	// journal is no longer authority. Cleanup failure is retried opportunistically.
	_ = custody.Journal.RemoveExact(claim)
	return nil
}

func canonicalJSONUnchecked(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func preparedClaimsEqual(left, right PreparedAccountClaim) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}
