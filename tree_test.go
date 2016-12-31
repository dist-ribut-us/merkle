package merkle

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/dist-ribut-us/crypto"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTree(t *testing.T) {
	data := make([]byte, (BlockSize*5)/2)
	rand.Read(data)

	reader := bytes.NewReader(data)

	dirStr := "treeTest"
	key, err := crypto.RandomShared()
	if !assert.NoError(t, err) {
		return
	}

	f, err := New(dirStr, key)
	if !assert.NoError(t, err) {
		return
	}

	td, err := f.BuildTree(reader)
	if !assert.NoError(t, err) {
		return
	}

	tr := f.GetTree(td.Digest())
	if tr == nil {
		t.Error("Tree is nil")
		return
	}

	// --- Test ReadAll ---
	assert.Equal(t, data, tr.ReadAll())
	assert.Equal(t, uint32(3), tr.leaves)

	// --- Test GetLeaf ---
	for i := 0; i < int(tr.leaves); i++ {
		vc, l, err := tr.GetLeaf(i)
		if !assert.NoError(t, err) {
			return
		}
		st := BlockSize * i
		ed := st + len(l)
		if len(data) < ed {
			t.Errorf("%d: Block is too short: is %d, should be at least %d (%d)", i, len(data), ed, len(l))
		} else if !bytes.Equal(data[st:ed], l) {
			t.Log(data[st : st+10])
			t.Log(l[:10])
			t.Errorf("Block %d is not equal", i)
		}
		assert.True(t, tr.ValidateLeaf(vc, l))
	}

	// --- Test File Size ---
	// Every file should be larger than the BlockSize because it should be a full
	// block plus the MAC.
	err = filepath.Walk(dirStr, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".db") || path == dirStr {
			return nil
		}
		if info.IsDir() {
			return fmt.Errorf("Should not have sub directory")
		}
		if info.Size() < BlockSize {
			return fmt.Errorf("Too Small; Expect: %d Got: %d", BlockSize, info.Size())
		}
		return nil
	})
	assert.NoError(t, err)

	// --- Test Read ---
	out := make([]byte, 1000)
	p := 0
	for l, err := tr.Read(out); err == nil; l, err = tr.Read(out) {
		if p+l > len(data) {
			t.Error("Wrong Length")
			break
		}
		if !bytes.Equal(out[:l], data[p:p+l]) {
			t.Errorf("Not Equal: %d:%d", p, p+l)
		}
		p += l
	}

	f.Close()
	assert.NoError(t, os.RemoveAll(dirStr))
}
