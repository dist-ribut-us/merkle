package merkle

import (
	"github.com/dist-ribut-us/crypto"
)

const (
	rMask = byte(1)
	lMask = byte(2)
	both  = rMask & lMask
)

type branch struct {
	dig         crypto.Digest
	left, right crypto.Digest
	pattern     byte
}

func (b *branch) val() crypto.Digest { return b.dig }

func (b *branch) lIsLeaf() bool { return b.pattern&lMask == lMask }
func (b *branch) rIsLeaf() bool { return b.pattern&rMask == rMask }

func (b *branch) marshal() []byte {
	s := make([]byte, crypto.DigestLength*2+1)
	s[0] = b.pattern
	copy(s[1:], b.left)
	copy(s[crypto.DigestLength+1:], b.right)
	return s
}

func unmarshalBranch(s []byte) *branch {
	if len(s) != crypto.DigestLength*2+1 {
		return nil
	}
	p := s[0]
	s = s[1:]
	return &branch{
		pattern: p,
		left:    s[:crypto.DigestLength],
		right:   s[crypto.DigestLength:],
		dig:     crypto.SHA256(s),
	}
}

func newBranch(l, r crypto.Digest, pattern byte) *branch {
	s := make([]byte, crypto.DigestLength*2)
	copy(s, l)
	copy(s[crypto.DigestLength:], r)

	return &branch{
		dig:     crypto.SHA256(s),
		left:    l,
		right:   r,
		pattern: pattern,
	}
}
