package merkle

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/dist-ribut-us/crypto"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"
)

func TestLeafFilename(t *testing.T) {
	key, _ := crypto.RandomShared()
	l := make([]byte, BlockSize)
	_, err := rand.Read(l)
	assert.NoError(t, err)
	d := crypto.SHA256(l)
	cd := key.Seal(d, zeroNonce)[crypto.NonceLength:]
	filename := hex.EncodeToString(cd)
	if strings.HasPrefix(filename, "00000000000000") {
		t.Error([]byte(cd))
		t.Error("Bad filename: " + filename)
	}
}

func TestForest(t *testing.T) {
	dirStr := "TestForest"
	key, err := crypto.RandomShared()
	if !assert.NoError(t, err) {
		return
	}

	f, err := New(dirStr, key)
	if !assert.NoError(t, err) {
		return
	}

	d1 := crypto.SHA256([]byte("test 1"))
	d2 := crypto.SHA256([]byte("test 2"))

	s := make([]byte, crypto.DigestLength*2)
	copy(s, d1)
	copy(s[crypto.DigestLength:], d2)

	b1 := &branch{
		dig:     crypto.SHA256(s),
		left:    d1,
		right:   d2,
		pattern: both,
	}

	f.writeBranch(b1)
	f.Close()

	f, err = Open(dirStr, key)
	if !assert.NoError(t, err) {
		return
	}

	leaf := make([]byte, 1000)
	_, err = rand.Read(leaf)
	if !assert.NoError(t, err) {
		return
	}

	ld, err := f.writeLeaf(leaf, len(leaf))
	if !assert.NoError(t, err) {
		return
	}

	leaf2, err := f.readLeaf(ld)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, leaf, leaf2)

	b2 := f.readBranch(b1.dig)
	if b2 == nil {
		t.Error("b2 should not be nil")
	} else {
		assert.Equal(t, b1, b2)
	}

	f.Close()
	assert.NoError(t, os.RemoveAll(dirStr))
}

func TestValue(t *testing.T) {
	dirStr := "TestValue"
	key, err := crypto.RandomShared()
	if !assert.NoError(t, err) {
		return
	}

	f, err := New(dirStr, key)
	if !assert.NoError(t, err) {
		return
	}

	k := make([]byte, 20)
	v := make([]byte, 200)

	_, err = rand.Read(k)
	assert.NoError(t, err)
	_, err = rand.Read(v)
	assert.NoError(t, err)

	f.SetValue(k, v)
	out := f.GetValue(k)
	assert.Equal(t, v, out)

	f.Close()
	assert.NoError(t, os.RemoveAll(dirStr))
}
