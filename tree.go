package merkle

import (
	"github.com/dist-ribut-us/crypto"
)

const BlockSize = 7500

type Tree struct {
	dig          crypto.Digest
	isLeaf       bool
	leaves       uint32
	f            *Forest
	lastBlockLen uint16
	pos          int
}

func (t *Tree) Digest() crypto.Digest { return t.dig }
