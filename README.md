# miniature-spoon

Provide a limited proxy for Bitcoin RPC.

* Only allows the limited set of RPC calls that bitmarkd requires.
* Allows round-robin sharing of multiple bitcoind to multiple bitmarkd.
* Retries failed bitcoind connections.
* Uses CA, server and client certificates for authenticated TLS connection.
* Checks that all bitcoind are on the same chain.
* Drops priviledges after opening socket (OK on FreeBSD, fails on Linux)
