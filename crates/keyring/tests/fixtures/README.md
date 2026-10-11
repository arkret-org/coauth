# Encrypted secret fixtures

`encrypted_secrets.json` was generated before the Encrypter upgrade by
`coauth-keyring` with `chacha20poly1305 0.10.1` and `aead 0.5.2`, based on
Coauth `1c5b20e3`. Each case calls `Encrypter::encrypt` with key `[0x42; 32]`,
nonce `[7; 12]`, the UTF-8 plaintext listed in the fixture, and empty AAD.
`ciphertext_base64` contains ciphertext followed by the 16-byte tag;
`frame_base64` additionally prefixes the same 12-byte nonce. Tests independently
confirm both encodings rather than recomputing expected values at runtime.

All credentials are synthetic. The Apple case has a test-only P-256 PKCS#8
key derived from scalar `[3; 32]`, so the real provider adapter can parse the
credentials after decryption. No production key or provider secret is present.

The fixture was separately cross-checked using OpenSSL ChaCha20-Poly1305 through
Python `cryptography`, then exercised through committed OAuth client/provider
rows and a fresh repository transaction before the dependency change. The R06
AEAD acceptance artifact records the generation/baseline logs and file hashes.
This proves algorithm/framing equivalence; production has one reader and no
legacy branch or additional storage profile.
