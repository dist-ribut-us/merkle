package merkle

import (
	"github.com/dist-ribut-us/crypto"
	"io"
)

func (t *Tree) ReadAll() []byte {
	l := int(t.leaves-1)*BlockSize + int(t.lastBlockLen)
	b := make([]byte, l)
	startAt := 0
	recursiveRead(b, &startAt, t.dig, t.isLeaf, t.f, true, int(t.lastBlockLen))
	return b
}

type ValidationChain []*uncle

type uncle struct {
	dig  crypto.Digest
	left bool
}

func recursiveRead(b []byte, startAt *int, d crypto.Digest, isLeaf bool, f *Forest, rightMost bool, lastLen int) (int, error) {
	// startAt is a bit confusing, if we're starting at position 1000, we add the
	// data length to it, when it becomes <=0, then we start reading. The negative value is how far from the beginning to start
	if isLeaf {
		if rightMost {
			*startAt -= lastLen
			if (*startAt) >= 0 {
				return 0, io.EOF
			}
		} else {
			*startAt -= BlockSize
		}
		l := 0
		if *startAt <= 0 {
			lf, _ := f.readLeaf(d)
			if rightMost {
				lf = lf[:lastLen]
			}
			l = len(lf)
			s := l + *startAt
			if s < 0 {
				s = 0
			}
			lf = lf[s:]
			l = len(lf)
			if lb := len(b); l > lb {
				l = lb
			}
			copy(b, lf)
		}
		return l, nil
	}
	br := f.readBranch(d)
	lb := len(b)
	l := 0
	var err error
	if lb > 0 {
		l, _ = recursiveRead(b, startAt, br.left, br.lIsLeaf(), f, false, lastLen)
	}
	var r int
	if lb > l {
		r, err = recursiveRead(b[l:], startAt, br.right, br.rIsLeaf(), f, rightMost, lastLen)
	}
	return l + r, err
}

func (t *Tree) GetLeaf(lIdx int) (ValidationChain, []byte, error) {
	vc, l, err := recursiveGetLeaf(uint32(lIdx), 0, t.leaves-1, t.dig, t.isLeaf, t.f)
	if lbl := int(t.lastBlockLen); lIdx == int(t.leaves)-1 && len(l) > lbl {
		l = l[:lbl]
	}
	return vc, l, err
}

func recursiveGetLeaf(lIdx, start, end uint32, d crypto.Digest, isLeaf bool, f *Forest) ([]*uncle, []byte, error) {
	if isLeaf {
		l, err := f.readLeaf(d)
		return nil, l, err
	}
	b := f.readBranch(d)
	mid := (start + end) / 2
	if lIdx < mid || lIdx == start {
		us, l, err := recursiveGetLeaf(lIdx, start, mid, b.left, b.lIsLeaf(), f)
		u := &uncle{
			dig:  b.right,
			left: false,
		}
		return append(us, u), l, err
	}
	us, l, err := recursiveGetLeaf(lIdx, mid, end, b.right, b.rIsLeaf(), f)
	u := &uncle{
		dig:  b.left,
		left: true,
	}
	return append(us, u), l, err
}

func (t *Tree) ValidateLeaf(us ValidationChain, leaf []byte) bool {
	v := crypto.SHA256(leaf)
	b := make([]byte, crypto.DigestLength*2)
	for _, u := range us {
		if u.left {
			copy(b, u.dig)
			copy(b[crypto.DigestLength:], v)
		} else {
			copy(b, v)
			copy(b[crypto.DigestLength:], u.dig)
		}
		v = crypto.SHA256(b)
	}
	return v.Equal(t.dig)
}

func (t *Tree) Read(p []byte) (int, error) {
	startAt := t.pos
	n, err := recursiveRead(p, &startAt, t.dig, t.isLeaf, t.f, true, int(t.lastBlockLen))
	t.pos += n
	return n, err
}
