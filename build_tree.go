package merkle

import (
	"github.com/dist-ribut-us/crypto"
	"io"
	"sync"
)

var blockPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, BlockSize)
	},
}

// BuildTree takes a reader and saves the data read from it to a Merkle tree in
// the Forest.
func (f *Forest) BuildTree(r io.Reader) (*Tree, error) {
	buf := blockPool.Get().([]byte)
	var err error
	var ls []*crypto.Digest
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
	blockPool.Put(buf)
	if err.Error() == "EOF" {
		err = nil
	} else {
		return nil, err
	}
	d, _ := recursiveBuild(f, ls)
	t := &Tree{
		dig:          d,
		leaves:       uint32(len(ls)),
		lastBlockLen: lbl,
		f:            f,
		complete:     true,
	}
	f.writeTree(t)
	return t, err
}

func recursiveBuild(f *Forest, leaves []*crypto.Digest) (*crypto.Digest, bool) {
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

// AddLeaf will add a validated leaf to a Sapling.
func (t *Tree) AddLeaf(vc ValidationChain, leaf []byte, lIdx int) {
	if lIdx >= int(t.leaves) {
		return
	}
	if isSet := t.leavesComplete[lIdx]; isSet {
		return
	}
	if !t.ValidateLeaf(vc, leaf, lIdx) {
		return
	}
	l := len(leaf)
	if l < BlockSize {
		// the only block that can be less than BlockSize is the last block
		t.lastBlockLen = uint16(l)
		pad := make([]byte, BlockSize-l)
		leaf = append(leaf, pad...)
	}

	// save Leaf
	v, _ := t.f.writeLeaf(leaf, l)
	t.leavesComplete[lIdx] = true

	// save branches
	isLeaf := true
	var br *branch
	dirs := dirChain(uint32(lIdx), 0, t.leaves)
	for i, vd := range vc {
		var p byte
		if dirs[i] {
			if isLeaf {
				p = lLeafMask
			}
			br = getOrCreateBranch(v, vd, p, t.f)
		} else {
			if isLeaf {
				p = rLeafMask
			}
			br = getOrCreateBranch(vd, v, p, t.f)
		}
		v = br.dig
		isLeaf = false
	}

	// compute if complete, save tree
	t.complete = true
	for _, leafComplete := range t.leavesComplete {
		if !leafComplete {
			t.complete = false
			break
		}
	}
	t.f.writeTree(t)
}

func getOrCreateBranch(l, r *crypto.Digest, p byte, f *Forest) *branch {
	d := crypto.GetDigest(l.Slice(), r.Slice())
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
