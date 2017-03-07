## Notes

A merkle forrest holds merkle trees. In practice, this will be a directory and a
bolt database in that directory. The leaves are stored as files and the branches
are stored in the bolt database. There's a trick to requesting a node from the
forrest. If the node already exists, we don't want to over write it.

A brand new tree is created from static data (a file). A reader is used for
this.

A tree can also be copied. This only requires a Digest. The tree will be
incomplete until all it's leaves are filled. An incomplete tree will accept a
new leaf and uncle digests, and will validate that the uncle digests match.

A completed tree acts as an io.ReaderSeeker.

Both a complete and incomplete tree can provide a leaf and all the uncle digests
that go with it.

A tree consists of branches and leaves, both fulfill node. A branch references
two other nodes. A leaf holds a block of data.

The tree needs to be lazy, it doesn't help to read the whole thing in and we
need to write to it from a Reader.

### Todo

I think AddLeaf needs work. Do we need lIdx? Also, is the validation chain
actually being validated?

### Later

#### TTL
Trees should have a TTL value. A value of a 0 means forever, anything else is a
UNIX timestamp, after that time, the tree will be deleted.

### Caching
Eventually...

Set a memory limit on the cache and keep blocks based on their access time and
frequency. These can even be settable configs (per forrest instance).