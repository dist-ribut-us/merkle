package merkle

import (
	"bytes"
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
	d := crypto.GetDigest(l)
	cd := key.Seal(d, zeroNonce)[crypto.NonceLength:]
	filename := hex.EncodeToString(cd)
	if strings.HasPrefix(filename, "00000000000000") {
		t.Error([]byte(cd))
		t.Error("Bad filename: " + filename)
	}
}

func TestForest(t *testing.T) {
	dirStr := "TestForest"
	os.RemoveAll(dirStr)
	key, err := crypto.RandomShared()
	if !assert.NoError(t, err) {
		return
	}

	f, err := Open(dirStr, key)
	if !assert.NoError(t, err) {
		return
	}

	d1 := crypto.GetDigest([]byte("test 1"))
	d2 := crypto.GetDigest([]byte("test 2"))

	b1 := &branch{
		dig:     crypto.GetDigest(d1, d2),
		left:    d1,
		right:   d2,
		pattern: both,
	}

	f.writeBranch(b1)
	f.Close()

	// test bad key
	badkey, err := crypto.RandomShared()
	assert.NoError(t, err)
	f, err = Open(dirStr, badkey)
	assert.Equal(t, crypto.ErrDecryptionFailed, err)
	assert.Nil(t, f)

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

	f, err := Open(dirStr, key)
	if !assert.NoError(t, err) {
		return
	}

	k := make([]byte, 20)
	v := make([]byte, 200)

	_, err = rand.Read(k)
	assert.NoError(t, err)
	_, err = rand.Read(v)
	assert.NoError(t, err)

	bkt := []byte("valueTestBucket")
	f.SetValue(bkt, k, v)
	out, err := f.GetValue(bkt, k)
	assert.NoError(t, err)
	assert.Equal(t, v, out)

	k2 := make([]byte, 20)
	v2 := make([]byte, 200)
	_, err = rand.Read(k2)
	assert.NoError(t, err)
	_, err = rand.Read(v2)
	assert.NoError(t, err)
	f.SetValue(bkt, k2, v2)

	var otherk []byte
	var otherv []byte
	fk, fv, err := f.First(bkt)
	assert.NoError(t, err)
	if bytes.Equal(fk, k) {
		assert.Equal(t, fv, v)
		otherk = k2
		otherv = v2
	} else if bytes.Equal(fk, k2) {
		assert.Equal(t, fv, v2)
		otherk = k
		otherv = v
	} else {
		t.Error("First key did not match any key")
	}

	sk, sv, err := f.Next(bkt, fk)
	assert.NoError(t, err)
	assert.Equal(t, otherk, sk)
	assert.Equal(t, otherv, sv)

	tk, tv, err := f.Next(bkt, sk)
	assert.NoError(t, err)
	assert.Nil(t, tk)
	assert.Nil(t, tv)

	f.Close()
	assert.NoError(t, os.RemoveAll(dirStr))
}
