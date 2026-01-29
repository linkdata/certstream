package certstream

import "testing"

type fakeAtomicInt64 struct {
	value    int64
	failOnce bool
}

func (a *fakeAtomicInt64) Load() int64 {
	return a.value
}

func (a *fakeAtomicInt64) CompareAndSwap(old, new int64) bool {
	ok := false
	if a.value == old {
		if a.failOnce {
			a.failOnce = false
		} else {
			a.value = new
			ok = true
		}
	}
	return ok
}

func TestUpdateAtomicMinRetriesCompareAndSwap(t *testing.T) {
	v := &fakeAtomicInt64{value: -1, failOnce: true}
	updateAtomicMin(v, 0)
	if got, want := v.Load(), int64(0); got != want {
		t.Fatalf("min = %d, want %d", got, want)
	}
}

func TestUpdateAtomicMaxRetriesCompareAndSwap(t *testing.T) {
	v := &fakeAtomicInt64{value: -1, failOnce: true}
	updateAtomicMax(v, 5)
	if got, want := v.Load(), int64(5); got != want {
		t.Fatalf("max = %d, want %d", got, want)
	}
}
