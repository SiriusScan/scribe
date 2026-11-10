package runtime

import "hash/maphash"

// Modified by Sirius Scan from GoLua v0.1.2: use supported Go 1.24 hashing
// instead of references to private Go runtime symbols. The process
// seed remains stable for every table and lookup; hash values are not persisted.
var valueHashSeed = maphash.MakeSeed()

func goRuntimeInt64Hash(i uint64, _ uintptr) uintptr {
	return uintptr(maphash.Comparable(valueHashSeed, i))
}

func goRuntimeEfaceHash(i interface{}, _ uintptr) uintptr {
	return uintptr(maphash.Comparable(valueHashSeed, i))
}
