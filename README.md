# PaddingDialer
A Python framework to exploit AES CBC encryption with padding oracle attack vulnerability which decrypt the encrypted message without knowing the AES key.
This framework starts out to target AES (128/256 bits) CBC encryption with PKCS7 padding. I might work on more feature to target other padding algorithms.

See `example.py` for an example.

More on padding oracle attack:
https://en.wikipedia.org/wiki/Padding_oracle_attack

## Author
[Jeanno](https://jeanno.github.io/)

## Backlog
- Support edge cases where dialer can at the last byte dial into padding 02 02, 03 03 03, etc...
- Register as python module
- Create documentation site

