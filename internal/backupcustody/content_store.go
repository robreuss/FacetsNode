package backupcustody

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/google/uuid"
	"github.com/robreuss/FacetsNode/internal/serviceauthority"
)

// ContentStore owns only opaque staged and immutable Backup bytes. Paths are
// derived exclusively from server-validated UUIDs and generation numbers.
type ContentStore struct {
	resolvedPath     string
	parentPath       string
	rootName         string
	parentRoot       *os.Root
	parentDirectory  *os.File
	root             *os.Root
	rootDirectory    *os.File
	stagingDirectory *os.File
	processLock      *os.File
}

func OpenContentStore(path string) (*ContentStore, error) {
	resolved, err := filepath.Abs(path)
	if err != nil || filepath.Clean(resolved) != resolved {
		return nil, serviceauthority.ErrInvalid
	}
	parentPath, rootName := filepath.Dir(resolved), filepath.Base(resolved)
	parentInfo, parentErr := os.Lstat(parentPath)
	if parentErr != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("invalid custody parent: %w", serviceauthority.ErrInvalid)
	}
	parentRoot, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, serviceauthority.ErrInvalid
	}
	parentDirectory, err := parentRoot.Open(".")
	if err != nil {
		_ = parentRoot.Close()
		return nil, serviceauthority.ErrInvalid
	}
	openedParentInfo, openedParentErr := parentDirectory.Stat()
	if openedParentErr != nil || !os.SameFile(parentInfo, openedParentInfo) {
		_ = parentDirectory.Close()
		_ = parentRoot.Close()
		return nil, serviceauthority.ErrInvalid
	}
	info, err := parentRoot.Lstat(rootName)
	if errors.Is(err, os.ErrNotExist) {
		if err := parentRoot.Mkdir(rootName, 0o700); err != nil {
			_ = parentDirectory.Close()
			_ = parentRoot.Close()
			return nil, fmt.Errorf("create Backup custody root: %w", err)
		}
		if err := parentDirectory.Sync(); err != nil {
			_ = parentDirectory.Close()
			_ = parentRoot.Close()
			return nil, fmt.Errorf("sync Backup custody parent: %w", err)
		}
		info, err = parentRoot.Lstat(rootName)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		_ = parentDirectory.Close()
		_ = parentRoot.Close()
		return nil, fmt.Errorf("invalid custody root: %w", serviceauthority.ErrInvalid)
	}
	root, err := os.OpenRoot(resolved)
	if err != nil {
		_ = parentDirectory.Close()
		_ = parentRoot.Close()
		return nil, fmt.Errorf("open Backup custody root: %w", err)
	}
	for _, directory := range []string{"staging", "objects"} {
		if err := root.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			_ = root.Close()
			_ = parentDirectory.Close()
			_ = parentRoot.Close()
			return nil, fmt.Errorf("create Backup custody %s: %w", directory, err)
		}
		info, err := root.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			_ = root.Close()
			_ = parentDirectory.Close()
			_ = parentRoot.Close()
			return nil, fmt.Errorf("invalid custody child: %w", serviceauthority.ErrInvalid)
		}
	}
	rootDirectory, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		_ = parentDirectory.Close()
		_ = parentRoot.Close()
		return nil, fmt.Errorf("open Backup custody root directory: %w", err)
	}
	openedRootInfo, openedRootErr := rootDirectory.Stat()
	if openedRootErr != nil || !os.SameFile(info, openedRootInfo) {
		_ = rootDirectory.Close()
		_ = root.Close()
		_ = parentDirectory.Close()
		_ = parentRoot.Close()
		return nil, fmt.Errorf("invalid opened custody root: %w", serviceauthority.ErrInvalid)
	}
	stagingDirectory, err := root.Open("staging")
	if err != nil {
		_ = rootDirectory.Close()
		_ = root.Close()
		_ = parentDirectory.Close()
		_ = parentRoot.Close()
		return nil, fmt.Errorf("open Backup custody staging directory: %w", err)
	}
	if err := rootDirectory.Sync(); err != nil {
		_ = stagingDirectory.Close()
		_ = rootDirectory.Close()
		_ = root.Close()
		_ = parentDirectory.Close()
		_ = parentRoot.Close()
		return nil, fmt.Errorf("sync Backup custody root: %w", err)
	}
	processLock, err := root.OpenFile(".process.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil || syscall.Flock(int(processLock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		if processLock != nil {
			_ = processLock.Close()
		}
		_ = stagingDirectory.Close()
		_ = rootDirectory.Close()
		_ = root.Close()
		_ = parentDirectory.Close()
		_ = parentRoot.Close()
		return nil, serviceauthority.ErrInvalid
	}
	lockInfo, err := processLock.Stat()
	lockPathInfo, lockPathErr := root.Lstat(".process.lock")
	if err != nil || lockPathErr != nil || !lockInfo.Mode().IsRegular() ||
		lockPathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(lockInfo, lockPathInfo) || lockInfo.Mode().Perm()&0o077 != 0 {
		_ = syscall.Flock(int(processLock.Fd()), syscall.LOCK_UN)
		_ = processLock.Close()
		_ = stagingDirectory.Close()
		_ = rootDirectory.Close()
		_ = root.Close()
		_ = parentDirectory.Close()
		_ = parentRoot.Close()
		return nil, fmt.Errorf("invalid custody process lock: %w", serviceauthority.ErrInvalid)
	}
	if err := processLock.Sync(); err != nil {
		_ = syscall.Flock(int(processLock.Fd()), syscall.LOCK_UN)
		_ = processLock.Close()
		_ = stagingDirectory.Close()
		_ = rootDirectory.Close()
		_ = root.Close()
		_ = parentDirectory.Close()
		_ = parentRoot.Close()
		return nil, err
	}
	if err := rootDirectory.Sync(); err != nil {
		_ = syscall.Flock(int(processLock.Fd()), syscall.LOCK_UN)
		_ = processLock.Close()
		_ = stagingDirectory.Close()
		_ = rootDirectory.Close()
		_ = root.Close()
		_ = parentDirectory.Close()
		_ = parentRoot.Close()
		return nil, err
	}
	store := &ContentStore{resolvedPath: resolved, parentPath: parentPath, rootName: rootName,
		parentRoot: parentRoot, parentDirectory: parentDirectory, root: root,
		rootDirectory: rootDirectory, stagingDirectory: stagingDirectory, processLock: processLock}
	if store.validateRoot() != nil {
		_ = store.Close()
		return nil, serviceauthority.ErrInvalid
	}
	return store, nil
}

func (store *ContentStore) Close() error {
	if store == nil || store.root == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(store.processLock.Fd()), syscall.LOCK_UN)
	return errors.Join(unlockErr, store.processLock.Close(), store.stagingDirectory.Close(), store.rootDirectory.Close(),
		store.root.Close(), store.parentDirectory.Close(), store.parentRoot.Close())
}

func (store *ContentStore) PrepareUpload(uploadID uuid.UUID) error {
	if store == nil || store.root == nil || uploadID == uuid.Nil || store.validateRoot() != nil {
		return serviceauthority.ErrInvalid
	}
	path := stagingPath(uploadID)
	file, err := store.root.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		file, err = store.openStableRegular(path, os.O_RDONLY)
		if err == nil {
			defer file.Close()
			info, statErr := file.Stat()
			if statErr == nil && info.Size() == 0 {
				if err := file.Sync(); err != nil {
					return err
				}
				return store.stagingDirectory.Sync()
			}
		}
		return serviceauthority.ErrInvalid
	}
	if err != nil {
		return fmt.Errorf("create Backup upload staging: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync Backup upload staging: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close Backup upload staging: %w", err)
	}
	if err := store.stagingDirectory.Sync(); err != nil {
		return fmt.Errorf("sync Backup staging directory: %w", err)
	}
	return nil
}

func (store *ContentStore) EnsureStaging(upload UploadRecord, maximumChunkBytes, maximumGenerationBytes uint64) error {
	if store == nil || upload.UploadID == uuid.Nil || upload.Request.Validate() != nil ||
		upload.AccountID != upload.Request.Credential.AccountID || upload.TargetID != upload.Request.Credential.TargetID ||
		upload.BackupSetID != upload.Request.Credential.BackupSetID || upload.Committed || upload.CommittedBytes > math.MaxInt64 ||
		maximumChunkBytes == 0 || maximumGenerationBytes == 0 || maximumChunkBytes > maximumGenerationBytes ||
		maximumGenerationBytes > math.MaxInt64 || upload.CommittedBytes > maximumGenerationBytes ||
		store.validateRoot() != nil {
		return serviceauthority.ErrInvalid
	}
	path := stagingPath(upload.UploadID)
	partial := serviceauthority.BackupCustodyGenerationRecord{Version: Version, AccountID: upload.AccountID,
		TargetID: upload.TargetID, BackupSetID: upload.BackupSetID, Generation: upload.Request.Generation, UploadID: upload.UploadID}
	object := objectPath(partial)
	objectInfo, objectErr := store.root.Lstat(object)
	if objectErr == nil {
		if !objectInfo.Mode().IsRegular() || objectInfo.Mode()&os.ModeSymlink != 0 || objectInfo.Mode().Perm()&0o077 != 0 {
			return serviceauthority.ErrInvalid
		}
		stagingInfo, stagingErr := store.root.Lstat(path)
		if stagingErr == nil {
			if !os.SameFile(stagingInfo, objectInfo) {
				return ErrConflict
			}
			if err := store.syncRootedDirectory(objectDirectory(partial)); err != nil {
				return err
			}
			if err := store.root.Remove(path); err != nil {
				return err
			}
			return store.syncRootedDirectory("staging")
		}
		if !errors.Is(stagingErr, os.ErrNotExist) {
			return stagingErr
		}
		return nil
	}
	if !errors.Is(objectErr, os.ErrNotExist) {
		return objectErr
	}
	if info, err := store.root.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return serviceauthority.ErrInvalid
		}
		file, err := store.openStableRegular(path, os.O_RDONLY)
		if err != nil {
			return err
		}
		defer file.Close()
		stat, err := file.Stat()
		if err != nil || stat.Size() < 0 || uint64(stat.Size()) < upload.CommittedBytes ||
			uint64(stat.Size()) > maximumGenerationBytes || uint64(stat.Size())-upload.CommittedBytes > maximumChunkBytes {
			return serviceauthority.ErrInvalid
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if upload.CommittedBytes != 0 {
		return serviceauthority.ErrInvalid
	}
	return store.PrepareUpload(upload.UploadID)
}

func (store *ContentStore) VerifyUploadRange(upload UploadRecord, offset, length uint64, expectedSHA256 string) error {
	if store == nil || upload.UploadID == uuid.Nil || length == 0 || offset > math.MaxInt64 || length > math.MaxInt64 ||
		offset > math.MaxInt64-length || !validHexDigest(expectedSHA256) || store.validateRoot() != nil {
		return serviceauthority.ErrInvalid
	}
	file, err := store.OpenFinalizationBytes(upload.AccountID, upload.TargetID, upload.Request.Generation, upload.UploadID)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
		return serviceauthority.ErrInvalid
	}
	digest := sha256.New()
	if count, err := io.CopyN(digest, file, int64(length)); err != nil || uint64(count) != length ||
		fmt.Sprintf("%x", digest.Sum(nil)) != expectedSHA256 {
		return serviceauthority.ErrInvalid
	}
	held, err := file.Stat()
	if err != nil {
		return serviceauthority.ErrInvalid
	}
	stagingInfo, stagingErr := store.root.Lstat(stagingPath(upload.UploadID))
	partial := serviceauthority.BackupCustodyGenerationRecord{Version: Version, AccountID: upload.AccountID,
		TargetID: upload.TargetID, BackupSetID: upload.BackupSetID, Generation: upload.Request.Generation, UploadID: upload.UploadID}
	objectInfo, objectErr := store.root.Lstat(objectPath(partial))
	if (stagingErr != nil || !os.SameFile(held, stagingInfo)) && (objectErr != nil || !os.SameFile(held, objectInfo)) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

// ReconcileAndAppend makes the file match the last committed database offset,
// then appends and fsyncs the next exact chunk. A database failure after this
// call is repaired by truncation on the exact retry.
func (store *ContentStore) ReconcileAndAppend(
	uploadID uuid.UUID,
	committedOffset uint64,
	chunk []byte,
	maximumChunkBytes uint64,
	maximumGenerationBytes uint64,
) (uint64, error) {
	if store == nil || store.root == nil || uploadID == uuid.Nil || store.validateRoot() != nil || len(chunk) == 0 ||
		uint64(len(chunk)) > maximumChunkBytes || committedOffset > maximumGenerationBytes ||
		maximumGenerationBytes > math.MaxInt64 || committedOffset > math.MaxInt64 ||
		uint64(len(chunk)) > maximumGenerationBytes-committedOffset {
		return 0, serviceauthority.ErrInvalid
	}
	file, err := store.openStableRegular(stagingPath(uploadID), os.O_RDWR)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() < 0 || uint64(info.Size()) < committedOffset {
		return 0, serviceauthority.ErrInvalid
	}
	if uint64(info.Size()) > committedOffset {
		if err := file.Truncate(int64(committedOffset)); err != nil {
			return 0, fmt.Errorf("truncate uncommitted Backup upload tail: %w", err)
		}
		if err := file.Sync(); err != nil {
			return 0, fmt.Errorf("sync reconciled Backup upload: %w", err)
		}
	}
	if _, err := file.Seek(int64(committedOffset), io.SeekStart); err != nil {
		return 0, fmt.Errorf("seek Backup upload: %w", err)
	}
	if written, err := file.Write(chunk); err != nil || written != len(chunk) {
		return 0, fmt.Errorf("append Backup upload: wrote %d of %d: %w", written, len(chunk), err)
	}
	if err := file.Sync(); err != nil {
		return 0, fmt.Errorf("sync Backup upload chunk: %w", err)
	}
	return committedOffset + uint64(len(chunk)), nil
}

func (store *ContentStore) OpenStaging(uploadID uuid.UUID) (*os.File, error) {
	if store == nil || uploadID == uuid.Nil || store.validateRoot() != nil {
		return nil, serviceauthority.ErrInvalid
	}
	return store.openStableRegular(stagingPath(uploadID), os.O_RDONLY)
}

// OpenFinalizationBytes supports the only legitimate orphan state: an object
// was durably and exclusively published, but the database transaction did not
// commit. No writable staging alias remains in that state.
func (store *ContentStore) OpenFinalizationBytes(
	accountID, targetID uuid.UUID,
	generation uint64,
	uploadID uuid.UUID,
) (*os.File, error) {
	if store == nil || accountID == uuid.Nil || targetID == uuid.Nil || uploadID == uuid.Nil ||
		generation == 0 || generation > math.MaxInt64 || store.validateRoot() != nil {
		return nil, serviceauthority.ErrInvalid
	}
	staging := stagingPath(uploadID)
	if _, err := store.root.Lstat(staging); err == nil {
		return store.OpenStaging(uploadID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	candidate := serviceauthority.BackupCustodyGenerationRecord{
		Version: Version, AccountID: accountID, TargetID: targetID,
		Generation: generation, UploadID: uploadID,
	}
	return store.openStableRegular(objectPath(candidate), os.O_RDONLY)
}

// Publish links staged bytes to an immutable generation-specific name. An
// existing exact object is a crash-recovery retry; different bytes fail closed.
func (store *ContentStore) Publish(record serviceauthority.BackupCustodyGenerationRecord) (string, error) {
	if store == nil || store.root == nil || record.Validate() != nil || record.Generation > math.MaxInt64 || store.validateRoot() != nil {
		return "", serviceauthority.ErrInvalid
	}
	directory := objectDirectory(record)
	components := []string{"objects", filepath.Join("objects", record.AccountID.String()), directory}
	for index, component := range components {
		if index > 0 {
			if _, err := store.root.Lstat(component); errors.Is(err, os.ErrNotExist) {
				if err := store.root.Mkdir(component, 0o700); err != nil {
					return "", fmt.Errorf("create Backup object directory: %w", err)
				}
				if err := store.syncRootedDirectory(filepath.Dir(component)); err != nil {
					return "", err
				}
			} else if err != nil {
				return "", err
			}
		}
		info, statErr := store.root.Lstat(component)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return "", serviceauthority.ErrInvalid
		}
	}
	object := objectPath(record)
	err := store.root.Link(stagingPath(record.UploadID), object)
	if err != nil {
		if _, objectErr := store.root.Lstat(object); objectErr != nil {
			return "", fmt.Errorf("publish immutable Backup object: %w", err)
		}
	}
	if verifyErr := store.VerifyObject(record, object); verifyErr != nil {
		return "", verifyErr
	}
	objectFile, err := store.openStableRegular(object, os.O_RDONLY)
	if err != nil {
		return "", err
	}
	if err := objectFile.Chmod(0o400); err != nil {
		_ = objectFile.Close()
		return "", err
	}
	if err := objectFile.Sync(); err != nil {
		_ = objectFile.Close()
		return "", err
	}
	if err := objectFile.Close(); err != nil {
		return "", err
	}
	// Repeat every durability step on exact retry; a prior attempt may have
	// returned after any individual fsync failure.
	if syncErr := store.syncRootedDirectory(directory); syncErr != nil {
		return "", syncErr
	}
	stagingInfo, stagingErr := store.root.Lstat(stagingPath(record.UploadID))
	if stagingErr == nil {
		objectInfo, objectErr := store.root.Lstat(object)
		if objectErr != nil || !os.SameFile(stagingInfo, objectInfo) {
			return "", ErrConflict
		}
		if removeErr := store.root.Remove(stagingPath(record.UploadID)); removeErr != nil {
			return "", removeErr
		}
	} else if !errors.Is(stagingErr, os.ErrNotExist) {
		return "", stagingErr
	}
	if syncErr := store.stagingDirectory.Sync(); syncErr != nil {
		return "", syncErr
	}
	if syncErr := store.syncRootedDirectory(filepath.Dir(directory)); syncErr != nil {
		return "", syncErr
	}
	if syncErr := store.syncRootedDirectory("objects"); syncErr != nil {
		return "", syncErr
	}
	if verifyErr := store.VerifyObject(record, object); verifyErr != nil {
		return "", verifyErr
	}
	return object, nil
}

func (store *ContentStore) VerifyObject(record serviceauthority.BackupCustodyGenerationRecord, path string) error {
	if store == nil || store.root == nil || record.Validate() != nil || record.Generation > math.MaxInt64 ||
		path != objectPath(record) || store.validateRoot() != nil {
		return serviceauthority.ErrInvalid
	}
	file, err := store.openStableRegular(path, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || before.Size() < 0 || uint64(before.Size()) != record.OuterByteCount {
		return serviceauthority.ErrInvalid
	}
	digest := sha256.New()
	count, err := io.Copy(digest, file)
	if err != nil || count < 0 || uint64(count) != record.OuterByteCount {
		return serviceauthority.ErrInvalid
	}
	after, err := file.Stat()
	pathAfter, pathErr := store.root.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(after, pathAfter) || after.Size() != before.Size() ||
		base64.RawURLEncoding.EncodeToString(digest.Sum(nil)) != record.OuterDigest {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (store *ContentStore) OpenObject(record serviceauthority.BackupCustodyGenerationRecord, path string) (*os.File, error) {
	if store == nil || record.Validate() != nil || path != objectPath(record) || store.validateRoot() != nil {
		return nil, serviceauthority.ErrInvalid
	}
	file, err := store.openStableRegular(path, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	before, err := file.Stat()
	if err != nil || before.Size() < 0 || uint64(before.Size()) != record.OuterByteCount {
		_ = file.Close()
		return nil, serviceauthority.ErrInvalid
	}
	digest := sha256.New()
	count, hashErr := io.Copy(digest, file)
	after, statErr := file.Stat()
	pathInfo, pathErr := store.root.Lstat(path)
	if hashErr != nil || statErr != nil || pathErr != nil || count < 0 || uint64(count) != record.OuterByteCount ||
		!os.SameFile(before, after) || !os.SameFile(after, pathInfo) || before.Size() != after.Size() ||
		base64.RawURLEncoding.EncodeToString(digest.Sum(nil)) != record.OuterDigest {
		_ = file.Close()
		return nil, serviceauthority.ErrInvalid
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, serviceauthority.ErrInvalid
	}
	return file, nil
}

// OpenObjectRange authenticates the complete immutable object first, then
// serves only the requested range from the same held descriptor. Path identity
// and size are rechecked at range completion and close; a pathname swap can
// therefore never redirect an established read to foreign bytes.
func (store *ContentStore) OpenObjectRange(
	record serviceauthority.BackupCustodyGenerationRecord,
	path string,
	offset uint64,
	maximumByteCount uint64,
) (io.ReadCloser, uint64, error) {
	if store == nil || maximumByteCount == 0 || maximumByteCount > MaximumRangeByteCount ||
		offset >= record.OuterByteCount || offset > math.MaxInt64 ||
		maximumByteCount > math.MaxInt64 || offset > ^uint64(0)-maximumByteCount {
		return nil, 0, serviceauthority.ErrInvalid
	}
	file, err := store.OpenObject(record, path)
	if err != nil {
		return nil, 0, err
	}
	info, err := file.Stat()
	if err != nil || info.Size() < 0 || uint64(info.Size()) != record.OuterByteCount {
		_ = file.Close()
		return nil, 0, serviceauthority.ErrInvalid
	}
	count := maximumByteCount
	if remaining := record.OuterByteCount - offset; count > remaining {
		count = remaining
	}
	reader := &heldObjectRange{
		file: file, section: io.NewSectionReader(file, int64(offset), int64(count)),
		store: store, path: path, identity: info, expectedSize: info.Size(), remaining: count,
	}
	return reader, count, nil
}

type heldObjectRange struct {
	file         *os.File
	section      *io.SectionReader
	store        *ContentStore
	path         string
	identity     os.FileInfo
	expectedSize int64
	remaining    uint64
}

func (reader *heldObjectRange) Read(buffer []byte) (int, error) {
	if reader == nil || reader.file == nil || reader.section == nil {
		return 0, serviceauthority.ErrInvalid
	}
	if reader.remaining == 0 {
		if err := reader.validate(); err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	if uint64(len(buffer)) > reader.remaining {
		buffer = buffer[:reader.remaining]
	}
	count, err := reader.section.Read(buffer)
	if count < 0 || uint64(count) > reader.remaining {
		return 0, serviceauthority.ErrInvalid
	}
	reader.remaining -= uint64(count)
	if errors.Is(err, io.EOF) && reader.remaining != 0 {
		return count, serviceauthority.ErrInvalid
	}
	return count, err
}

func (reader *heldObjectRange) Close() error {
	if reader == nil || reader.file == nil {
		return nil
	}
	validationErr := reader.validate()
	file := reader.file
	reader.file = nil
	reader.section = nil
	return errors.Join(validationErr, file.Close())
}

func (reader *heldObjectRange) validate() error {
	if reader.file == nil || reader.store == nil || reader.store.validateRoot() != nil {
		return serviceauthority.ErrInvalid
	}
	held, heldErr := reader.file.Stat()
	pathInfo, pathErr := reader.store.root.Lstat(reader.path)
	if heldErr != nil || pathErr != nil || !held.Mode().IsRegular() ||
		held.Size() != reader.expectedSize || !os.SameFile(reader.identity, held) ||
		pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(held, pathInfo) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (store *ContentStore) validateRoot() error {
	if store == nil || store.root == nil || store.rootDirectory == nil || store.stagingDirectory == nil ||
		store.processLock == nil || store.parentRoot == nil || store.parentDirectory == nil {
		return serviceauthority.ErrInvalid
	}
	parentHeld, parentErr := store.parentDirectory.Stat()
	parentAmbient, parentAmbientErr := os.Lstat(store.parentPath)
	rootHeld, rootErr := store.rootDirectory.Stat()
	rootCurrent, rootCurrentErr := store.root.Lstat(".")
	rootFromParent, rootFromParentErr := store.parentRoot.Lstat(store.rootName)
	rootAmbient, rootAmbientErr := os.Lstat(store.resolvedPath)
	stagingHeld, stagingErr := store.stagingDirectory.Stat()
	stagingCurrent, stagingCurrentErr := store.root.Lstat("staging")
	lockHeld, lockErr := store.processLock.Stat()
	lockCurrent, lockCurrentErr := store.root.Lstat(".process.lock")
	if parentErr != nil || parentAmbientErr != nil || !parentHeld.IsDir() || parentHeld.Mode().Perm()&0o077 != 0 ||
		parentAmbient.Mode()&os.ModeSymlink != 0 || !os.SameFile(parentHeld, parentAmbient) ||
		rootErr != nil || rootCurrentErr != nil || rootFromParentErr != nil || rootAmbientErr != nil || !rootHeld.IsDir() || rootHeld.Mode().Perm()&0o077 != 0 ||
		rootCurrent.Mode()&os.ModeSymlink != 0 || rootAmbient.Mode()&os.ModeSymlink != 0 || !os.SameFile(rootHeld, rootCurrent) ||
		!os.SameFile(rootHeld, rootFromParent) || !os.SameFile(rootHeld, rootAmbient) ||
		stagingErr != nil || stagingCurrentErr != nil || !stagingHeld.IsDir() || stagingHeld.Mode().Perm()&0o077 != 0 ||
		stagingCurrent.Mode()&os.ModeSymlink != 0 || !os.SameFile(stagingHeld, stagingCurrent) ||
		lockErr != nil || lockCurrentErr != nil || !lockHeld.Mode().IsRegular() || lockHeld.Mode().Perm()&0o077 != 0 ||
		lockCurrent.Mode()&os.ModeSymlink != 0 || !os.SameFile(lockHeld, lockCurrent) {
		return serviceauthority.ErrInvalid
	}
	return nil
}

func (store *ContentStore) openStableRegular(name string, flags int) (*os.File, error) {
	before, err := store.root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o077 != 0 {
		return nil, serviceauthority.ErrInvalid
	}
	file, err := store.root.OpenFile(name, flags, 0)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, serviceauthority.ErrInvalid
	}
	return file, nil
}

func stagingPath(uploadID uuid.UUID) string {
	return filepath.Join("staging", uploadID.String()+".part")
}

func objectDirectory(record serviceauthority.BackupCustodyGenerationRecord) string {
	return filepath.Join("objects", record.AccountID.String(), record.TargetID.String())
}

func objectPath(record serviceauthority.BackupCustodyGenerationRecord) string {
	return filepath.Join(objectDirectory(record), strconv.FormatUint(record.Generation, 10)+"-"+record.UploadID.String()+".b20")
}

func (store *ContentStore) syncRootedDirectory(path string) error {
	if store == nil || store.validateRoot() != nil {
		return serviceauthority.ErrInvalid
	}
	before, err := store.root.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o077 != 0 {
		return serviceauthority.ErrInvalid
	}
	directory, err := store.root.Open(path)
	if err != nil {
		return fmt.Errorf("open Backup custody directory: %w", err)
	}
	defer directory.Close()
	after, err := directory.Stat()
	if err != nil || !after.IsDir() || after.Mode().Perm()&0o077 != 0 || !os.SameFile(before, after) {
		return serviceauthority.ErrInvalid
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync Backup custody directory: %w", err)
	}
	return nil
}
