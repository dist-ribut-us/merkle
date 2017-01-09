package merkle

import (
	"github.com/dist-ribut-us/crypto"
)

const (
	rLeafMask = byte(1)
	lLeafMask = byte(2)
	both      = rLeafMask & lLeafMask
)

type branch struct {
	dig         crypto.Digest
	left, right crypto.Digest
	pattern     byte
}

func (b *branch) val() crypto.Digest { return b.dig }

func (b *branch) lIsLeaf() bool { return b.pattern&lLeafMask == lLeafMask }
func (b *branch) rIsLeaf() bool { return b.pattern&rLeafMask == rLeafMask }

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
		dig:     crypto.GetDigest(s),
	}
}

func newBranch(l, r crypto.Digest, pattern byte) *branch {
	return &branch{
		dig:     crypto.GetDigest(l, r),
		left:    l,
		right:   r,
		pattern: pattern,
	}
}
