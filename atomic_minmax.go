package certstream

type atomicInt64 interface {
	Load() int64
	CompareAndSwap(old, new int64) bool
}

func updateAtomicMin(a atomicInt64, candidate int64) {
	for {
		current := a.Load()
		if current == -1 || current > candidate {
			if !a.CompareAndSwap(current, candidate) {
				continue
			}
		}
		break
	}
}

func updateAtomicMax(a atomicInt64, candidate int64) {
	for {
		current := a.Load()
		if current == -1 || current < candidate {
			if !a.CompareAndSwap(current, candidate) {
				continue
			}
		}
		break
	}
}
