//go:build windows

package serviceauthority

import "errors"

type bindingProcessLock struct{}

func acquireBindingProcessLock(string) (*bindingProcessLock, error) {
	// A process-local mutex would allow two FacetsNode processes to load and
	// independently rewrite the same authority file. Until this adapter uses a
	// native cross-process lock (for example LockFileEx), persistent service
	// authority therefore fails closed on Windows.
	return nil, errors.New("persistent service authority is unsupported on Windows")
}

func (lock *bindingProcessLock) release() error {
	return nil
}
