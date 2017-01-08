package merkle

import (
	"github.com/dist-ribut-us/crypto"
	"io"
)

// BuildTree takes a reader and saves the data read from it to a Merkle tree in
// the Forest.
func (f *Forest) BuildTree(r io.Reader) (*Tree, error) {
	buf := make([]byte, BlockSize)
	var err error
	var ls []crypto.Digest
	var lbl uint16
	for err == nil {
		cur, l := 0, 0
		for err == nil && cur < BlockSize {
			l, err = r.Read(buf[cur:])
			cur += l
		}
		d, _ := f.writeLeaf(buf, cur)
		lbl = uint16(cur)
		ls = append(ls, d)
	}
	if err.Error() == "EOF" {
		err = nil
	}
	d, _ := recursiveBuild(f, ls)
	t := &Tree{
		dig:          d,
		leaves:       uint32(len(ls)),
		lastBlockLen: lbl,
		f:            f,
	}
	f.writeTree(t)
	return t, err
}

func recursiveBuild(f *Forest, leaves []crypto.Digest) (crypto.Digest, bool) {
	l := len(leaves)
	if l == 1 {
		return leaves[0], true
	}
	ll := (l / 2)
	var p byte
	lb, isLeaf := recursiveBuild(f, leaves[:ll])
	if isLeaf {
		p |= lLeafMask
	}
	rb, isLeaf := recursiveBuild(f, leaves[ll:])
	if isLeaf {
		p |= rLeafMask
	}
	br := newBranch(lb, rb, p)
	f.writeBranch(br)
	return br.dig, false
}

// AddLeaf will add a validated leaf to a Sapling. If the sapling is completed
// by the action, the tree will be returned, otherwise nil is returned.
func (s *Sapling) AddLeaf(vc ValidationChain, leaf []byte, lIdx int) *Tree {
	if lIdx >= int(s.leaves) {
		return nil
	}
	if isSet := s.leavesComplete[lIdx]; isSet {
		return nil
	}
	if !s.ValidateLeaf(vc, leaf, lIdx) {
		return nil
	}
	l := len(leaf)
	if l < BlockSize {
		// the only block that can be less than BlockSize is the last block
		s.lastBlockLen = uint16(l)
		pad := make([]byte, BlockSize-l)
		leaf = append(leaf, pad...)
	}

	// save Leaf
	v, _ := s.f.writeLeaf(leaf, l)
	s.leavesComplete[lIdx] = true

	// save branches
	isLeaf := true
	var br *branch
	for _, u := range vc {
		var p byte
		if u.left {
			if isLeaf {
				p = lLeafMask
			}
			br = getOrCreateBranch(v, u.dig, p, s.f)
		} else {
			if isLeaf {
				p = rLeafMask
			}
			br = getOrCreateBranch(u.dig, v, p, s.f)
		}
		v = br.dig
		isLeaf = false
	}

	for _, leafComplete := range s.leavesComplete {
		if !leafComplete {
			return nil
		}
	}
	t := &Tree{
		dig:          s.dig,
		leaves:       s.leaves,
		lastBlockLen: s.lastBlockLen,
		f:            s.f,
	}
	s.f.writeTree(t)
	return t
}

func getOrCreateBranch(l, r crypto.Digest, p byte, f *Forest) *branch {
	b := make([]byte, crypto.DigestLength*2)
	copy(b, l)
	copy(b[crypto.DigestLength:], r)
	d := crypto.SHA256(b)
	br := f.readBranch(d)
	if br == nil {
		br = &branch{
			dig:     d,
			left:    l,
			right:   r,
			pattern: p,
		}
	} else {
		br.pattern |= p
	}
	f.writeBranch(br)

	return br
}
