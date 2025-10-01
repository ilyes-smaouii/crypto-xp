# crypto-xp
## Intro/context
Will try to experiment with cryptography here.

## File organization
- `src/` : contains source code
  - `*.cpp`, `*.hpp` : common code
  - `TEA/` : contains code to implement TEA specifically
  - `old/` : contains old code that's not used anymore (e.g. because it's been replaced with better code)
- `README.md` : file with useful information for future reader

## Ideas/things to explore
- Tiny Encryption Algorithm
- XXTEA ?
- AES, DES, RSA, SHA, etc.
- Different round counts
- zero-knowledge proofs
- post-quantum cryptography
Things to try : messages with signature, end-to-end encryption, checksums, etc.

## Journal/misc
### 2025/09/12
Started reading up on Tiny Ecryption Algorithm, which is apparently simpler than some of the more usual ones.
Will continue reading up on it, and if it seems relevant and reasonable, I'll try to implement it.\
Other encryption algorithms like Caeser's cipher, Vigenere, etc. would be even simpler, but I've already
had experience with those, and I don't think they're interesting enough to spend time on, considering I want
to move on to more "serious" and modern algorithms, such as AES, DES, etc.\
If I find that code, which I wrote a few years ago, maybe I'll upload it to my GitHub.
In the meantime, I'm focusing on other stuff.\
Update : just took a quick look at TEA implementation, and it seems even simpler than I imagined, which
is nice to start off easy.

### 2025/09/16
Wrote quite a bit of code already.\
TO-DO : clear up how I'm going to represent different number in memory (and byte order, most notably).

### 2025/09/26
Got a - seemingly - working implementation for TEA, and I'm now seeing a bit more clearly how I can make
some of my code more generic.\
Also added a `CMakeLists.txt` file to make building/running easier.\
TO-DO : make current code more generic.\
After that, I'll probably move on to another algorithm. Also, now that I think of it, I could try
to implement something more concrete/fun to test my algorithms, such as a messaging app or something,
rather than just write tests each time. Anyway, we'll see.

### 2025/10/01
Genericity has been implemented, and seems to work (for TEA, anyway).\
If my work has been done correctly, and I want to use another "block-type" algorithm, I'll just need
to create the corresponding struct and implement its `encryptBlockRaw()`/`decryptBlockRaw()` functions,
and I'll be able to use it directly on buffers and strings, and in whatevers applications I code in
the future (encrypted messaging app ?).