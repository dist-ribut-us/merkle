package merkle

import (
	"github.com/dist-ribut-us/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBranchMarshal(t *testing.T) {
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

	b2 := unmarshalBranch(b1.marshal())

	assert.Equal(t, b1, b2)
}
