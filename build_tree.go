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
	lb, b := recursiveBuild(f, leaves[:ll])
	if b {
		p |= lMask
	}
	rb, b := recursiveBuild(f, leaves[ll:])
	if b {
		p |= rMask
	}
	br := newBranch(lb, rb, p)
	f.writeBranch(br)
	return br.dig, false
}
