package merkle

import (
	"encoding/hex"
	"github.com/boltdb/bolt"
	"github.com/dist-ribut-us/crypto"
	"github.com/dist-ribut-us/serial"
	"os"
)

// Forest is a directory used to store Merkle Trees. A Forest has a symmetric
// encryption key that is used to secure the data. It also has a Bolt DB file
// to store structural information (branches and roots).
type Forest struct {
	key *crypto.Shared
	dir *os.File
	db  *bolt.DB
}

var branchBkt = []byte("b")
var treeBkt = []byte("t")
var valBkt = []byte("v")

// New creates a new Forest
func New(dirStr string, key *crypto.Shared) (*Forest, error) {
	var err error
	var f *Forest
	if err = os.MkdirAll(dirStr, 0777); err == nil {
		if dir, err := os.Open(dirStr); err == nil {
			if db, err := bolt.Open(dir.Name()+"/merkle.db", 0777, nil); err == nil {
				db.Update(func(tx *bolt.Tx) error {
					tx.CreateBucketIfNotExists(branchBkt)
					tx.CreateBucketIfNotExists(treeBkt)
					tx.CreateBucketIfNotExists(valBkt)
					return nil
				})
				f = &Forest{
					key: key,
					db:  db,
					dir: dir,
				}
			}
		}
	}
	return f, err
}

// Open will open an existing Forest
func Open(dirStr string, key *crypto.Shared) (*Forest, error) {
	var err error
	var f *Forest
	var dir *os.File
	if dir, err = os.Open(dirStr); err == nil {
		var db *bolt.DB
		if db, err = bolt.Open(dir.Name()+"/merkle.db", 0777, nil); err == nil {
			f = &Forest{
				key: key,
				db:  db,
				dir: dir,
			}
		}
	}
	return f, err
}

// Close will close a Forest, specifically, it will close the Bolt DB and
// directory.
func (f *Forest) Close() {
	f.dir.Close()
	f.db.Close()
}

var zeroNonce = &crypto.Nonce{}

func (f *Forest) readBranch(d crypto.Digest) *branch {
	cd := f.key.Seal(d, zeroNonce)[crypto.NonceLength:]
	var s []byte
	f.db.View(func(tx *bolt.Tx) error {
		s = tx.Bucket(branchBkt).Get(cd)
		return nil
	})
	if s == nil {
		return nil
	}
	s, _ = f.key.Open(s)
	b := unmarshalBranch(s)
	if !b.dig.Equal(d) {
		// TODO: in this case something has gone very wrong, we should probably at
		// least delete the record.
		return nil
	}
	return b
}

func (f *Forest) writeBranch(b *branch) error {
	s := f.key.Seal(b.marshal(), nil)
	cd := f.key.Seal(b.dig, zeroNonce)[crypto.NonceLength:]
	return f.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(branchBkt).Put(cd, s)
	})
}

func (f *Forest) writeLeaf(b []byte, l int) (crypto.Digest, error) {
	d := crypto.GetDigest(b[:l])
	cd := f.key.Seal(d, zeroNonce)[crypto.NonceLength:]
	data := f.key.Seal(b, nil)

	filename := hex.EncodeToString(cd)
	var file *os.File
	var err error
	if file, err = os.Create(f.dir.Name() + "/" + filename); err == nil {
		_, err = file.Write(data)
		file.Close()
	}
	return d, err
}

func (f *Forest) readLeaf(d crypto.Digest) ([]byte, error) {
	cd := f.key.Seal(d, zeroNonce)[crypto.NonceLength:]
	filename := hex.EncodeToString(cd)
	var file *os.File
	var err error
	var b []byte
	buf := make([]byte, 1000)
	if file, err = os.Open(f.dir.Name() + "/" + filename); err == nil {
		var l int
		for l, err = file.Read(buf); err == nil; l, err = file.Read(buf) {
			b = append(b, buf[:l]...)
		}
		if err.Error() == "EOF" {
			err = nil
		}
		b, err = f.key.Open(b)
		file.Close()
	}
	return b, err
}

func (f *Forest) writeTree(t *Tree) {
	key := f.key.Seal(t.dig, zeroNonce)[crypto.NonceLength:]
	l := 7
	if !t.complete {
		l += 4 + (int(t.leaves) / 8)
		if t.leaves%8 != 0 {
			l++
		}
	}
	b := make([]byte, l)
	serial.MarshalUint32(t.leaves, b)
	serial.MarshalUint16(t.lastBlockLen, b[4:])
	if t.complete {
		b[6] = 1
	} else {
		serial.MarshalBoolSlice(t.leavesComplete, b[7:])
	}
	val := f.key.Seal(b, nil)
	f.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(treeBkt).Put(key, val)
	})
}

// GetTree will return a Tree from a Forest. It is only a reference to the
// Tree, not the data in the tree. If the tree is not found, it will return nil.
func (f *Forest) GetTree(d crypto.Digest) *Tree {
	key := f.key.Seal(d, zeroNonce)[crypto.NonceLength:]
	var b []byte
	f.db.View(func(tx *bolt.Tx) error {
		b = tx.Bucket(treeBkt).Get(key)
		return nil
	})
	if len(b) < 7 {
		return nil
	}
	val, _ := f.key.Open(b)
	l := serial.UnmarshalUint32(val)
	lbl := serial.UnmarshalUint16(val[4:])
	complete := val[6] == 1
	var leavesComplete []bool
	if !complete {
		leavesComplete = serial.UnmarshalBoolSlice(val[7:])
	}
	return &Tree{
		dig:            d,
		leaves:         l,
		f:              f,
		lastBlockLen:   lbl,
		complete:       complete,
		leavesComplete: leavesComplete,
	}
}

// SetValue saves a single value to the Bolt Database. It does not use the
// Merkle tree structure, but provides a simple method to store secure
// information in the same container as the trees
func (f *Forest) SetValue(key, value []byte) error {
	key = f.key.Seal(key, zeroNonce)[crypto.NonceLength:]
	value = f.key.Seal(value, nil)
	return f.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(valBkt).Put(key, value)
	})
}

// GetValue returns a single value from the Bolt Database stored with SetValue.
// It does not use the Merkle tree structure, but provides a simple method to
// store secure information in the same container as the trees
func (f *Forest) GetValue(key []byte) []byte {
	key = f.key.Seal(key, zeroNonce)[crypto.NonceLength:]
	var c []byte
	f.db.View(func(tx *bolt.Tx) error {
		c = tx.Bucket(valBkt).Get(key)
		return nil
	})
	value, _ := f.key.Open(c)
	return value
}
