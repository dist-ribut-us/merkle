package merkle

import (
	"github.com/dist-ribut-us/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBranchMarshal(t *testing.T) {
	d1 := crypto.GetDigest([]byte("test 1"))
	d2 := crypto.GetDigest([]byte("test 2"))

	s := make([]byte, crypto.DigestLength*2)
	copy(s, d1.Slice())
	copy(s[crypto.DigestLength:], d2.Slice())

	b1 := &branch{
		dig:     crypto.GetDigest(s),
		left:    d1,
		right:   d2,
		pattern: both,
	}

	b2 := unmarshalBranch(b1.marshal())

	assert.Equal(t, b1, b2)
}
