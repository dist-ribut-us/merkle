## Merkle Tree Storage
This may be replaced later. The merkle package stores data in Merkle trees. The
leaves are stored as files in a directory, and the branches are stored in a Bolt
database.

The logic is that this provides a few useful features. The data is more secure
at rest. Each forest (Merkle trees in a directory) has a key, the data cannot
be read without that key. Further, it is difficult to even gather meta-data
because the file names are the encrypted hashes and the data in the Bolt DB are
also encrypted. Any leaves that are smaller than a full block are padded to
length, to prevent IDing a file by it's size.

Storing the files this way also makes it easy to fulfill requests for segments
of a file. A leaf can be retrieved along with the validation chain necessary to
prove that the leaf belongs to the tree.

[![GoDoc](https://godoc.org/github.com/dist-ribut-us/merkle?status.svg)](https://godoc.org/github.com/dist-ribut-us/merkle)

### To-do
* Delete test data: if a test fails, the next round of tests will fail because
  they are reading the old database.

Someday
* pass a slice into readleaf, that could be way more efficient
* get many blocks and uncles
* timestamp on tree
  * ttl : erase tree after a certain point
  * accessed : erase oldest trees to clear space 
* err handling

Maybe store data is less than 4096 bytes (after encryption) in a separate
bucket. It would need to be padded to certain lengths, but it could help with
efficient storage.

#### Partial Trees
Read and ReadAll will simply not work on an incomplete tree.

#### Directed Encrypted Access
Just the fragment of a thought, but a Forrest could be stored remotely (and
distributed). Or at least any generic blob storage could be used to store
leaves. A user could securely store data on an untrusted location and leak very
little meta data.