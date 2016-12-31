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
* err handling
* get many blocks and uncles
* review exported methods
* meta-data and config storage
* seek
* build tree up from individual leaves

Maybe store data is less than 4096 bytes (after encryption) in a separate
bucket. It would need to be padded to certain lengths, but it could help with
efficient storage.