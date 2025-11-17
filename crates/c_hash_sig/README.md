# PQ Bindings C Rust

C bindings for the post-quantum cryptography library [hash-sig](https://github.com/b-wagn/hash-sig/).

## Description

This project provides a C API for working with post-quantum hash-based signature schemes. It implements bindings for the XMSS (eXtended Merkle Signature Scheme) using SHA-3 and Winternitz encoding.

## Features

### Data Structures

- **PQSignatureSchemeSecretKey** - wrapper for secret key
- **PQSignatureSchemePublicKey** - wrapper for public key  
- **PQSignature** - wrapper for signature
- **PQRange** - epoch range representation
- **PQSigningError** - error codes

### Core Functions

#### Key Management

```c
// Generate key pair
enum PQSigningError pq_key_gen(
    uintptr_t activation_epoch,
    uintptr_t num_active_epochs,
    struct PQSignatureSchemePublicKey **pk_out,
    struct PQSignatureSchemeSecretKey **sk_out
);

// Free memory
void pq_secret_key_free(struct PQSignatureSchemeSecretKey *key);
void pq_public_key_free(struct PQSignatureSchemePublicKey *key);
```

#### Signing and Verification

```c
// Sign message
enum PQSigningError pq_sign(
    const struct PQSignatureSchemeSecretKey *sk,
    uint32_t epoch,
    const uint8_t *message,
    uintptr_t message_len,
    struct PQSignature **signature_out
);

// Verify signature
int pq_verify(
    const struct PQSignatureSchemePublicKey *pk,
    uint32_t epoch,
    const uint8_t *message,
    uintptr_t message_len,
    const struct PQSignature *signature
);

// Free memory
void pq_signature_free(struct PQSignature *signature);
```

#### State Management

```c
// Get key activation interval
struct PQRange pq_get_activation_interval(const struct PQSignatureSchemeSecretKey *key);

// Get prepared interval
struct PQRange pq_get_prepared_interval(const struct PQSignatureSchemeSecretKey *key);

// Advance preparation to next interval
void pq_advance_preparation(struct PQSignatureSchemeSecretKey *key);

// Get maximum scheme lifetime
uint64_t pq_get_lifetime(void);
```

#### Serialization

```c
// Serialize/deserialize keys and signatures
enum PQSigningError pq_secret_key_serialize(...);
enum PQSigningError pq_secret_key_deserialize(...);
enum PQSigningError pq_public_key_serialize(...);
enum PQSigningError pq_public_key_deserialize(...);
enum PQSigningError pq_signature_serialize(...);
enum PQSigningError pq_signature_deserialize(...);
```

#### Error Handling

```c
// Get error description
char *pq_error_description(enum PQSigningError error);

// Free string
void pq_string_free(char *s);
```

## Important Notes

### Synchronized Signature Scheme

This implementation uses a **synchronized (stateful)** signature scheme where:

- Keys have a fixed lifetime divided into **epochs**
- Each epoch can be used for signing **only once**
- Reusing an epoch **compromises the security** of the scheme
- This model is ideal for consensus protocols where validators sign messages at regular intervals

### Managing Prepared Interval

The secret key at any given time can only sign for a limited interval of epochs (prepared interval). Use `pq_advance_preparation()` to move this window to the next interval when needed.

### Message Length

All messages must be **exactly 32 bytes**. To sign longer messages, first use a hash function (e.g., SHA-256 or SHA-3).

### Memory Management

- All objects created by the library (keys, signatures, strings) must be freed using the corresponding `*_free()` functions
- Never free pointers manually via `free()` - use only the provided functions
- After calling `*_free()`, the pointer becomes invalid and should not be used

## Security

- **Never use the same epoch twice** with the same key, even to sign the same message
- Store secret keys securely
- Use serialization to save keys between sessions
- Regularly backup secret keys

## Scheme Parameters

Current implementation uses:
- **Scheme**: Generalized XMSS (Winternitz encoding, w=4)
- **Hash function**: SHA-3 (SHAKE)
- **Lifetime**: 2^18 epochs (262,144 epochs)
- **Message length**: 32 bytes

## Project Statistics

- **Tests**: 12/12 passed (100% coverage)
- **API functions**: 20
- **Lines of code**: 980 (Rust) + 156 (C example)
- **Test execution time**: 0.94 sec (release), 79 sec (debug)

## License

This project uses the hash-sig library. See the license of the original project:
https://github.com/b-wagn/hash-sig/

## References

- [hash-sig repository](https://github.com/b-wagn/hash-sig/)
- [Hash-Based Multi-Signatures for Post-Quantum Ethereum [DKKW25a]](https://eprint.iacr.org/2025/055.pdf)
- [LeanSig for Post-Quantum Ethereum [DKKW25b]](https://eprint.iacr.org/2025/1332.pdf)
- [XMSS: eXtended Merkle Signature Scheme (RFC 8391)](https://tools.ietf.org/html/rfc8391)
