package merkle

import (
	"github.com/dist-ribut-us/crypto"
)

// BlockSize is the size of each leaf. The encryption adds about 40 bytes. Most
// disks have a physical sector size of 4096. The block size is designed to use
// 2 sectors per leaf, a compromize between current effiency and future-
// proofing. There's also 40 bytes extra (double the encryption overhead) to
// ensure that it doesn't go over and require a 3rd sector.
const BlockSize = 8112

// Tree is how a resource is stored. It represents the top level digest of a
// Merkle tree.
type Tree struct {
	dig            *crypto.Digest
	leaves         uint32
	f              *Forest
	lastBlockLen   uint16
	pos            int64
	complete       bool
	leavesComplete []bool
}

// Digest gives the Digest that identifies the tree. This can be used to request
// the tree from a forest.
func (t *Tree) Digest() *crypto.Digest { return t.dig }

// Complete returns true if the tree has all it's leaves.
func (t *Tree) Complete() bool { return t.complete }

// New returns a new Tree
func (f *Forest) New(d *crypto.Digest, l uint32) *Tree {
	t := &Tree{
		leaves:         l,
		dig:            d,
		f:              f,
		lastBlockLen:   BlockSize,
		leavesComplete: make([]bool, l),
	}
	f.writeTree(t)
	return t
}
