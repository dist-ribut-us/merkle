package merkle

import (
	"github.com/dist-ribut-us/crypto"
	"github.com/dist-ribut-us/errors"
	"io"
)

// ErrIncomplete is returned when trying to perform an operation limited to a
// complete Tree (Read or ReadAll). Check if the Tree is complete with
// Tree.Complete()
const ErrIncomplete = errors.String("Tree is incomplete")

// ReadAll reads the contents of a tree into a byte slice
func (t *Tree) ReadAll() ([]byte, error) {
	if !t.complete {
		return nil, ErrIncomplete
	}
	l := int(t.leaves-1)*BlockSize + int(t.lastBlockLen)
	b := make([]byte, l)
	var startAt int64
	_, err := recursiveRead(b, &startAt, t.dig, t.leaves == 1, t.f, true, int(t.lastBlockLen))
	return b, err
}

// ValidationChain is used to validate that a leaf belongs to a tree. It
// includes all the Uncle digests and the position with in the tree.
type ValidationChain []*crypto.Digest

func recursiveRead(b []byte, startAt *int64, d *crypto.Digest, isLeaf bool, f *Forest, rightMost bool, lastLen int) (int, error) {
	// startAt is a bit confusing, if we're starting at position 1000, we add the
	// data length to it, when it becomes <=0, then we start reading. The negative value is how far from the beginning to start
	if isLeaf {
		if rightMost {
			*startAt -= int64(lastLen)
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
			s := l + int(*startAt)
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

func recursiveGetLeaf(lIdx, start, end uint32, d *crypto.Digest, isLeaf bool, f *Forest) ([]*crypto.Digest, []byte, error) {
	if isLeaf {
		l, err := f.readLeaf(d)
		return nil, l, err
	}
	b := f.readBranch(d)
	mid := (start + end) / 2
	var ud *crypto.Digest
	if lIdx < mid || lIdx == start {
		end = mid
		d = b.left
		ud = b.right
		isLeaf = b.lIsLeaf()
	} else {
		start = mid
		d = b.right
		ud = b.left
		isLeaf = b.rIsLeaf()
	}
	us, l, err := recursiveGetLeaf(lIdx, start, end, d, isLeaf, f)
	return append(us, ud), l, err
}

// ValidateLeaf uses a ValidationChain to confirm that a leaf belongs to a tree
func (t *Tree) ValidateLeaf(vc ValidationChain, leaf []byte, lIdx int) bool {
	return validateLeaf(vc, leaf, lIdx, t.dig, t.leaves)
}

func validateLeaf(vc ValidationChain, leaf []byte, lIdx int, d *crypto.Digest, ln uint32) bool {
	v := crypto.GetDigest(leaf)
	dirs := dirChain(uint32(lIdx), 0, ln)
	if len(dirs) != len(vc) {
		return false
	}
	for i, vd := range vc {
		if dirs[i] {
			v = crypto.GetDigest(v.Slice(), vd.Slice())
		} else {
			v = crypto.GetDigest(vd.Slice(), v.Slice())
		}

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
	t.pos += int64(n)
	return n, err
}

// ErrBadWhence is returned if the whence value given to Seek is unknown
const ErrBadWhence = errors.String("Bad whence value")

// ErrNegativeOffset is returned if the result of a seek would set the tree
// offset position to a negative value.
const ErrNegativeOffset = errors.String("Attempting to Seek to negative offset")

// Seek implements io.Seeker
func (t *Tree) Seek(offset int64, whence int) (int64, error) {
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = t.pos + offset
	case io.SeekEnd:
		newPos = int64(t.Len()) + offset
	default:
		return t.pos, ErrBadWhence
	}
	if newPos < 0 {
		return t.pos, ErrNegativeOffset
	}
	t.pos = newPos
	return t.pos, nil
}

// Len returns the byte size of the tree
func (t *Tree) Len() int {
	return (int(t.leaves-1)*BlockSize + int(t.lastBlockLen))
}
