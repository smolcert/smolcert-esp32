# smolcert-esp32

This is a very simple implementation of [smolcert](https://github.com/smolcert) for the esp32
microcontroller. This implementation is based on the [ESP-IDF](https://github.com/espressif/esp-idf)
and should only depend on libsodium and tinycbor.

Currently implemented features:

[x] Parse a smolcert from a byte buffer
[x] Validate the signature of a smolcert with a given public ed25519 key