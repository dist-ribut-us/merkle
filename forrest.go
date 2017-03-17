package merkle

import (
	"bytes"
	"encoding/hex"
	"github.com/boltdb/bolt"
	"github.com/dist-ribut-us/crypto"
	"github.com/dist-ribut-us/errors"
	"github.com/dist-ribut-us/serial"
	"os"
	"time"
)

// Forest is a directory used to store Merkle Trees. A Forest has a symmetric
// encryption key that is used to secure the data. It also has a Bolt DB file
// to store structural information (branches and roots).
type Forest struct {
	key *crypto.Shared
	dir string
	db  *bolt.DB
}

var branchBkt = []byte("b")
var treeBkt = []byte("t")
var validateKey = []byte("__key__")

// ErrBucketDoesNotExist is returned when trying to read from a bucket that does
// not exist.
const ErrBucketDoesNotExist = errors.String("Bucket does not exist")

var openOptions = &bolt.Options{
	Timeout: time.Second,
}

// Open will either open or creates a new Forest
func Open(dirStr string, key *crypto.Shared) (*Forest, error) {
	if err := os.MkdirAll(dirStr, 0777); err != nil {
		return nil, err
	}
	dir, err := os.Open(dirStr)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(dir.Name()+"/merkle.db", 0777, openOptions)
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucketIfNotExists(branchBkt)
		b, _ := tx.CreateBucketIfNotExists(treeBkt)
		// the key validation is stored in the treeBkt because it is unlikely
		// to collied with a tree
		v := b.Get(validateKey)
		if v == nil {
			b.Put(validateKey, key.Seal(validateKey, nil))
		} else {
			if v, err = key.Open(v); err != nil {
				return err
			} else if !bytes.Equal(v, validateKey) {
				return crypto.ErrDecryptionFailed
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	f := &Forest{
		key: key,
		db:  db,
		dir: dir.Name(),
	}

	err = dir.Close()

	return f, err
}

// Close will close a Forest, specifically, it will close the Bolt DB and
// directory.
func (f *Forest) Close() {
	f.db.Close()
}

var zeroNonce = &crypto.Nonce{}

func (f *Forest) readBranch(d *crypto.Digest) *branch {
	cd := f.key.Seal(d.Slice(), zeroNonce)[crypto.NonceLength:]
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
	cd := f.key.Seal(b.dig.Slice(), zeroNonce)[crypto.NonceLength:]
	return f.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(branchBkt).Put(cd, s)
	})
}

func (f *Forest) writeLeaf(b []byte, l int) (*crypto.Digest, error) {
	d := crypto.GetDigest(b[:l])
	cd := f.key.Seal(d.Slice(), zeroNonce)[crypto.NonceLength:]
	data := f.key.Seal(b, nil)

	filename := hex.EncodeToString(cd)
	var file *os.File
	var err error
	if file, err = os.Create(f.dir + "/" + filename); err == nil {
		_, err = file.Write(data)
		file.Close()
	}
	return d, err
}

const overhead = crypto.Overhead + crypto.NonceLength

func (f *Forest) readLeaf(d *crypto.Digest) ([]byte, error) {
	cd := f.key.Seal(d.Slice(), zeroNonce)[crypto.NonceLength:]
	filename := hex.EncodeToString(cd)
	// Not sure why, but if the block is exactly the right size it freezes during
	// read, so we tack one extra byte on, then remove it.
	b := make([]byte, BlockSize+overhead+1)
	file, err := os.Open(f.dir + "/" + filename)
	if err != nil {
		return nil, err
	}
	var l, i int
	for l, err = file.Read(b); err == nil; l, err = file.Read(b[i:]) {
		i += l
	}
	if err.Error() == "EOF" {
		err = nil
	}
	b = b[:i+l] // remove extra byte

	b, err = f.key.Open(b)
	if err != nil {
		return nil, err
	}
	err = file.Close()

	return b, err
}

func (f *Forest) writeTree(t *Tree) {
	key := f.key.Seal(t.dig.Slice(), zeroNonce)[crypto.NonceLength:]
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
func (f *Forest) GetTree(d *crypto.Digest) *Tree {
	key := f.key.Seal(d.Slice(), zeroNonce)[crypto.NonceLength:]
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
func (f *Forest) SetValue(bucket, key, value []byte) error {
	key = f.key.Seal(key, zeroNonce)[crypto.NonceLength:]
	value = f.key.Seal(value, nil)
	return f.db.Update(func(tx *bolt.Tx) error {
		btk, err := tx.CreateBucketIfNotExists(bucket)
		if err != nil {
			return err
		}
		return btk.Put(key, value)
	})
}

// GetValue returns a single value from the Bolt Database stored with SetValue.
// It does not use the Merkle tree structure, but provides a simple method to
// store secure information in the same container as the trees
func (f *Forest) GetValue(bucket, key []byte) ([]byte, error) {
	key = f.key.Seal(key, zeroNonce)[crypto.NonceLength:]
	var c []byte
	err := f.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bucket)
		if bkt == nil {
			return ErrBucketDoesNotExist
		}
		c = bkt.Get(key)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return f.key.Open(c)
}

// First returns the first key/value pair in the bucket
func (f *Forest) First(bucket []byte) ([]byte, []byte, error) {
	var (
		key []byte
		val []byte
	)
	f.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bucket)
		if bkt == nil {
			return ErrBucketDoesNotExist
		}
		key, val = bkt.Cursor().First()
		return nil
	})
	key, err := f.key.NonceOpen(key, nil)
	if err != nil {
		return nil, nil, err
	}
	val, err = f.key.Open(val)
	if err != nil {
		return nil, nil, err
	}
	return key, val, nil
}

// Next takes a searchKey and returns the next key/value after it
func (f *Forest) Next(bucket, searchKey []byte) ([]byte, []byte, error) {
	searchKey = f.key.Seal(searchKey, zeroNonce)[crypto.NonceLength:]
	var (
		key []byte
		val []byte
	)
	err := f.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bucket)
		if bkt == nil {
			return ErrBucketDoesNotExist
		}
		c := bkt.Cursor()
		key, val = c.Seek(searchKey)
		if !bytes.Equal(key, searchKey) {
			return nil
		}
		key, val = c.Next()
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	key, err = f.key.NonceOpen(key, nil)
	if err != nil {
		return nil, nil, err
	}
	val, err = f.key.Open(val)
	if err != nil {
		return nil, nil, err
	}
	return key, val, nil
}
