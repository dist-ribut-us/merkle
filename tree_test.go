package merkle

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/dist-ribut-us/crypto"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTree(t *testing.T) {
	dirStr := "treeTest"
	key, err := crypto.RandomShared()
	if !assert.NoError(t, err) {
		return
	}

	f, err := New(dirStr, key)
	if !assert.NoError(t, err) {
		return
	}

	// Code can take different paths depending on the size of the tree so we run
	// the test many times with different tree sizes to hit many different lengths
	for size := 1000; size < BlockSize*10; size += 4000 {
		data := make([]byte, size)
		rand.Read(data)

		reader := bytes.NewReader(data)

		tr, err := f.BuildTree(reader)
		if !assert.NoError(t, err) {
			return
		}

		tr = f.GetTree(tr.Digest())
		if tr == nil {
			t.Error("Tree is nil")
			return
		}

		// --- Test ReadAll ---
		dataOut, err := tr.ReadAll()
		if !assert.NoError(t, err) {
			break
		}
		assert.Equal(t, data, dataOut)

		// --- Test Len ---
		assert.Equal(t, size, tr.Len())

		// --- Test Seek ---
		pos, err := tr.Seek(10, io.SeekStart)
		assert.NoError(t, err)
		assert.Equal(t, int64(10), pos)
		b := make([]byte, 10)
		ln, err := tr.Read(b)
		assert.NoError(t, err)
		assert.Equal(t, 10, ln)
		assert.Equal(t, data[10:20], b)

		pos, err = tr.Seek(10, io.SeekCurrent)
		assert.NoError(t, err)
		assert.Equal(t, int64(30), pos)
		ln, err = tr.Read(b)
		assert.NoError(t, err)
		assert.Equal(t, 10, ln)
		assert.Equal(t, data[30:40], b)

		pos, err = tr.Seek(-10, io.SeekEnd)
		assert.NoError(t, err)
		assert.Equal(t, int64(size-10), pos)
		ln, err = tr.Read(b)
		assert.NoError(t, err)
		assert.Equal(t, 10, ln)
		assert.Equal(t, data[size-10:], b)

		tr.Seek(0, io.SeekStart)

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
			assert.True(t, tr.ValidateLeaf(vc, l, i))
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
	}

	f.Close()
	assert.NoError(t, os.RemoveAll(dirStr))
}

func TestSapling(t *testing.T) {
	fromDir := "fromDir"
	toDir := "toDir"

	fromKey, err := crypto.RandomShared()
	if !assert.NoError(t, err) {
		return
	}

	fFrom, err := New(fromDir, fromKey)
	if !assert.NoError(t, err) {
		return
	}

	toKey, err := crypto.RandomShared()
	if !assert.NoError(t, err) {
		return
	}

	fTo, err := New(toDir, toKey)
	if !assert.NoError(t, err) {
		return
	}

	data := make([]byte, (8*BlockSize)/3)
	rand.Read(data)

	reader := bytes.NewReader(data)

	tr, err := fFrom.BuildTree(reader)
	if !assert.NoError(t, err) {
		return
	}

	tOut := fTo.New(tr.Digest(), tr.leaves)
	for i := 0; i < int(tr.leaves); i++ {
		vc, l, err := tr.GetLeaf(i)
		assert.NoError(t, err)

		tOut.AddLeaf(vc, l, i)
		if i < int(tr.leaves)-1 {
			if tOut.complete {

				t.Error("Tree should not be complete")
			} else {
				// Confirm Read and ReadAll throw ErrIncomplete
				_, err := tOut.Read(make([]byte, 10))
				assert.Equal(t, ErrIncomplete, err)
				_, err = tOut.ReadAll()
				assert.Equal(t, ErrIncomplete, err)
			}
		}
	}
	assert.NotNil(t, tOut)

	assert.Equal(t, tr.lastBlockLen, tOut.lastBlockLen)

	tOutData, err := tOut.ReadAll()
	assert.NoError(t, err)
	assert.Equal(t, data, tOutData)

	fFrom.Close()
	assert.NoError(t, os.RemoveAll(fromDir))

	fTo.Close()
	assert.NoError(t, os.RemoveAll(toDir))
}
