package storagecapacity

import (
	"context"
	"io"
)

const MaximumWriteBoundary = 1 << 20

// CheckedWriter enforces physical headroom at bounded write boundaries. Its
// caller owns the durable reservation and pool admission lock for the entire
// operation. Previously staged bytes already reduce physical free space; they
// must not be charged again here. Unrelated filesystem consumers can still
// change capacity after allocation, so a reservation alone is insufficient.
type CheckedWriter struct {
	Context     context.Context
	Destination io.Writer
	Capacity    Provider
}

func (w CheckedWriter) Write(data []byte) (int, error) {
	if w.Capacity == nil || w.Destination == nil || w.Context == nil {
		return 0, ErrUnavailable
	}
	total := 0
	for len(data) > 0 {
		if err := w.Context.Err(); err != nil {
			return total, err
		}
		count := min(len(data), MaximumWriteBoundary)
		snapshot, err := w.Capacity.Snapshot(w.Context)
		if err != nil {
			return total, err
		}
		if err := Check(snapshot, 0, int64(count)); err != nil {
			return total, err
		}
		n, err := w.Destination.Write(data[:count])
		total += n
		if err != nil {
			return total, err
		}
		if n != count {
			return total, io.ErrShortWrite
		}
		data = data[count:]
	}
	return total, nil
}
