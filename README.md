# Alt-crypt (working name)

My own opinionated abstraction library for working with cryptography

## ⚠️ You probably don't want to use this ⚠️
This library is public for my own convenience; you are fully responsible if anything happens when you use this library.

## Philosophies
- Overkill security
- Quantum resistance/immunity (Grover's Algorithm)
- Zeroize when possible
- TODO
## Stack
- #### Type: Technology (crate)
- Key Exchange: ML-KEM 1024 (ml-kem)
- Encryption: AES-256 (aws-lc-rs)
- Key derivation: Argon2id (argon2)
- Password hashing: Argon2id (argon2)
- Encoding: Deku (deku)
- String encoding: Base64 (base64)
