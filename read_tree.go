package merkle

import (
	"errors"
	"github.com/dist-ribut-us/crypto"
	"io"
)

var ErrIncomplete = errors.New("Tree is incomplete")

// ReadAll reads the contents of a tree into a byte slice
func (t *Tree) ReadAll() ([]byte, error) {
	if !t.complete {
		return nil, ErrIncomplete
	}
	l := int(t.leaves-1)*BlockSize + int(t.lastBlockLen)
	b := make([]byte, l)
	startAt := 0
	_, err := recursiveRead(b, &startAt, t.dig, t.leaves == 1, t.f, true, int(t.lastBlockLen))
	return b, err
}

// ValidationChain is used to validate that a leaf belongs to a tree. It
// includes all the Uncle digests and the position with in the tree.
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

// GetLeaf returns the ValidationChain and Leaf for a tree.
func (t *Tree) GetLeaf(lIdx int) (ValidationChain, []byte, error) {
	vc, l, err := recursiveGetLeaf(uint32(lIdx), 0, t.leaves, t.dig, t.leaves == 1, t.f)
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
	var left bool
	var ud crypto.Digest
	if lIdx < mid || lIdx == start {
		end = mid
		d = b.left
		ud = b.right
		isLeaf = b.lIsLeaf()
		left = true
	} else {
		start = mid
		d = b.right
		ud = b.left
		isLeaf = b.rIsLeaf()
	}
	us, l, err := recursiveGetLeaf(lIdx, start, end, d, isLeaf, f)
	u := &uncle{
		dig:  ud,
		left: left,
	}
	return append(us, u), l, err
}

// ValidateLeaf uses a ValidationChain to confirm that a leaf belongs to a tree
func (t *Tree) ValidateLeaf(vc ValidationChain, leaf []byte, lIdx int) bool {
	return validateLeaf(vc, leaf, lIdx, t.dig, t.leaves)
}

func validateLeaf(vc ValidationChain, leaf []byte, lIdx int, d crypto.Digest, ln uint32) bool {
	v := crypto.SHA256(leaf)
	b := make([]byte, crypto.DigestLength*2)
	dirs := dirChain(uint32(lIdx), 0, ln)
	if len(dirs) != len(vc) {
		return false
	}
	for i, u := range vc {
		if u.left != dirs[i] {
			return false
		}
		if u.left {
			copy(b, v)
			copy(b[crypto.DigestLength:], u.dig)
		} else {
			copy(b, u.dig)
			copy(b[crypto.DigestLength:], v)
		}
		v = crypto.SHA256(b)
	}

	return v.Equal(d)
}

func dirChain(lIdx, start, end uint32) []bool {
	if start == end {
		return nil
	}
	if end-start == 1 {
		return nil
	}
	mid := (start + end) / 2
	if lIdx < mid {
		return append(dirChain(lIdx, start, mid), true)
	}
	return append(dirChain(lIdx, mid, end), false)
}

// Read implements the io.Reader interface to allow a tree to be read into a
// byte slice
func (t *Tree) Read(p []byte) (int, error) {
	if !t.complete {
		return 0, ErrIncomplete
	}
	startAt := t.pos
	n, err := recursiveRead(p, &startAt, t.dig, t.leaves == 1, t.f, true, int(t.lastBlockLen))
	t.pos += n
	return n, err
}
