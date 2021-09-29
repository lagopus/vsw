package dpdk

import (
	"syscall"
	"testing"
	"unsafe"
)

type hashTestDataType struct {
	text   string
	number int
	rc     int
}

func TestHashBasic(t *testing.T) {
	hp := &HashParams{
		Name:     "test hash",
		Entries:  32,
		KeyLen:   4,
		Func:     CRCHash4Byte,
		InitVal:  0,
		SocketId: SOCKET_ID_ANY,
	}

	hash, err := HashCreate(hp)
	if err != nil {
		t.Fatalf("HashCreate failed: %v", err)
	}

	key := 0x12345678
	data := &hashTestDataType{"hoge", 1234, 0}

	err = hash.AddKeyData(unsafe.Pointer(&key), unsafe.Pointer(data))
	if err != nil {
		t.Fatalf("AddKeyData failed: %v", err)
	}
	t.Logf("AddKeyData for %x", key)

	v, rc, err := hash.LookupData(unsafe.Pointer(&key))
	if err != nil {
		t.Fatalf("LookupData failed: %v", err)
	}

	t.Logf("LookupData for %x: %v @ %d", key, (*hashTestDataType)(v), rc)

	rc, err = hash.DelKey(unsafe.Pointer(&key))
	if err != nil {
		t.Fatalf("DelKey failed: %v", err)
	}

	t.Logf("DelKey for %x @ %d", key, rc)

	v, rc, err = hash.LookupData(unsafe.Pointer(&key))
	if dpdkErr, ok := err.(Errno); ok {
		if dpdkErr.Errno() != syscall.ENOENT {
			t.Fatalf("DelKey may have failed: %v", err)
		}
	} else {
		t.Fatalf("DelKey may have failed: %v", err)
	}
	t.Logf("Successively deleted key")

	hash.Free()
}

const HashTestSize = 32

func TestHashManyData(t *testing.T) {
	hp := &HashParams{
		Name:     "test hash",
		Entries:  HashTestSize,
		KeyLen:   4,
		Func:     CRCHash4Byte,
		InitVal:  0,
		SocketId: SOCKET_ID_ANY,
	}

	// Create (HashTestSize + 1) of test data.
	testData := make(map[uint32]*hashTestDataType)
	for i := 0; i <= HashTestSize; i++ {
		key := uint32(i + 0x12345678)
		testData[key] = &hashTestDataType{number: i}
	}

	t.Logf("testData created: %d data", len(testData))

	hash, err := HashCreate(hp)
	if err != nil {
		t.Fatalf("HashCreate failed: %v", err)
	}

	t.Logf("Hash created")

	count := 0
	var badKey uint32
	for key, data := range testData {
		t.Logf("Adding: key=%x, data=%v", key, data)
		err := hash.AddKeyData(unsafe.Pointer(&key), unsafe.Pointer(data))
		if err != nil {
			if count < HashTestSize {
				t.Fatalf("AddKeyData failed (%d data): %v", count, err)
			} else {
				t.Logf("Reached limit. Added %d/%d data. %v.", count, HashTestSize, err)
				badKey = key
			}
		} else {
			t.Logf("succeeded")
			count++
		}
	}

	t.Logf("Data added: %d data", count)

	count = 0
	for key := range testData {
		t.Logf("Lookup: key=%x", key)
		v, rc, err := hash.LookupData(unsafe.Pointer(&key))
		if err != nil {
			if dpdkErr, ok := err.(Errno); ok {
				if dpdkErr.Errno() == syscall.ENOENT && key == badKey {
					t.Logf("Lookup failed for bad key. Ok: 0x%x", key)
				} else {
					t.Fatalf("LookupData failed: %v", err)
				}
			} else {
				t.Fatalf("LookupData failed: %v", err)
			}
		} else {
			data := (*hashTestDataType)(v)
			if data.number == testData[key].number {
				t.Logf("succeeded (rc=%d)", rc)
				testData[key].rc = rc
				count++
			} else {
				t.Fatalf("data mismatch; exepected %v, got %v", testData[key], data)
			}
		}
	}

	t.Logf("Lookup ok: %d match", count)

	if c, err := hash.Count(); err != nil {
		t.Fatalf("Count failed: %v", err)
	} else {
		if c == count {
			t.Logf("Number of entries in hash table matches (%d)", count)
		} else {
			t.Fatalf("Number of entries mismatch (%d != %d)", count, c)
		}
	}

	count = 0
	for key := range testData {
		t.Logf("Delete: key=%x", key)
		rc, err := hash.DelKey(unsafe.Pointer(&key))
		if err != nil {
			if dpdkErr, ok := err.(Errno); ok {
				if dpdkErr.Errno() == syscall.ENOENT && key == badKey {
					t.Logf("Delete failed for bad key. Ok: 0x%x", key)
				} else {
					t.Fatalf("Delete failed: %v", err)
				}
			} else {
				t.Fatalf("Delete failed: %v", err)
			}
		} else {
			if testData[key].rc != rc {
				t.Fatalf("Data mismatch: key 0x%x @ %d", key, rc)
			}
			t.Logf("succeeded (rc=%d)", rc)
			count++
		}
	}

	t.Logf("Delete ok (deleted %d entries)", count)

	if c, err := hash.Count(); err != nil {
		t.Fatalf("Count failed: %v", err)
	} else {
		if c == 0 {
			t.Logf("No data left. ok")
		} else {
			t.Fatalf("Still have %d entries after deletion", c)
		}
	}

	hash.Free()
}
