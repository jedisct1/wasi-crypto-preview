# WASI-Crypto

# Algorithms

An algorithm and its public parameters are represented by a unique string.

A WASI-crypto implementation MUST implement the following algorithms, and MUST represent them with the following string identifiers:

| Identifier              | Algorithm                                                                           |
| ----------------------- | ----------------------------------------------------------------------------------- |
| `ECDSA_P256_SHA256`     | ECDSA over the NIST p256 curve with the SHA-256 hash function                       |
| `ECDSA_K256_SHA256`     | ECDSA over the secp256k1 curve with the SHA-256 hash function                       |
| `Ed25519`               | Edwards Curve signatures over Edwards25519 (pure EdDSA) as specified in RFC8032     |
| `RSA_PKCS1_2048_SHA256` | RSA signatures with a 2048 bit modulus, PKCS1 padding and the SHA-256 hash function |
| `RSA_PKCS1_2048_SHA384` | RSA signatures with a 2048 bit modulus, PKCS1 padding and the SHA-384 hash function |
| `RSA_PKCS1_2048_SHA512` | RSA signatures with a 2048 bit modulus, PKCS1 padding and the SHA-512 hash function |
| `RSA_PKCS1_3072_SHA384` | RSA signatures with a 3072 bit modulus, PKCS1 padding and the SHA-384 hash function |
| `RSA_PKCS1_3072_SHA512` | RSA signatures with a 3072 bit modulus, PKCS1 padding and the SHA-512 hash function |
| `RSA_PKCS1_4096_SHA512` | RSA signatures with a 4096 bit modulus, PKCS1 padding and the SHA-512 hash function |
| `RSA_PSS_2048_SHA256`   | RSA signatures with a 2048 bit modulus, PSS padding and the SHA-256 hash function   |
| `RSA_PSS_2048_SHA384`   | RSA signatures with a 2048 bit modulus, PSS padding and the SHA-384 hash function   |
| `RSA_PSS_2048_SHA512`   | RSA signatures with a 2048 bit modulus, PSS padding and the SHA-512 hash function   |
| `RSA_PSS_3072_SHA384`   | RSA signatures with a 2048 bit modulus, PSS padding and the SHA-384 hash function   |
| `RSA_PSS_3072_SHA512`   | RSA signatures with a 3072 bit modulus, PSS padding and the SHA-512 hash function   |
| `RSA_PSS_4096_SHA512`   | RSA signatures with a 4096 bit modulus, PSS padding and the SHA-512 hash function   |
| `HKDF-EXTRACT/SHA-256`  | RFC5869 `EXTRACT` function using the SHA-256 hash function                          |
| `HKDF-EXTRACT/SHA-512`  | RFC5869 `EXTRACT` function using the SHA-512 hash function                          |
| `HKDF-EXPAND/SHA-256`   | RFC5869 `EXPAND` function using the SHA-256 hash function                           |
| `HKDF-EXPAND/SHA-512`   | RFC5869 `EXPAND` function using the SHA-512 hash function                           |
| `HMAC/SHA-256`          | RFC2104 MAC using the SHA-256 hash function                                         |
| `HMAC/SHA-512`          | RFC2104 MAC using the SHA-512 hash function                                         |
| `SHA-256`               | SHA-256 hash function                                                               |
| `SHA-512`               | SHA-512 hash function                                                               |
| `SHA-512/256`           | SHA-512/256 hash function with a specific IV                                        |
| `AES-128-GCM`           | AES-128-GCM AEAD cipher                                                             |
| `AES-256-GCM`           | AES-256-GCM AEAD cipher                                                             |
| `CHACHA20-POLY1305`     | ChaCha20-Poly1305 AEAD cipher as specified in RFC8439                               |
| `P256-SHA256`           | NIST p256 ECDH with the SHA-256 hash function                                       |
| `X25519`                | X25519 ECDH as specified in RFC7748                                                 |

Each algorithm belongs to one of these categories, represented by the `algorithm_type` type:

* `signatures` for signature systems
* `symmetric` for any symmetric primitive or construction
* `key_exhange` for key exchange mechanisms, including DH-based systems and KEMs.

Implementations are also encouraged to include the following algorithms in order to exercise additional features of the API:

| Identifier           | Algorithm                                                                                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `XOODYAK-128`        | XOODYAK lightweight scheme, as specified in the most recent submission to NIST competition for lightweight cryptography                          |
| `XCHACHA20-POLY1305` | ChaCha20-Poly1305 AEAD with ean xtended nonce, as specified in the most recent `draft-irtf-cfrg-xchacha` CFRG draft                              |
| `KYBER768`           | KYBER-768 post-quantum key encapsulation mechanism, as specified in the most recent submission to NIST competition for post-quantum cryptography |

Implementations are not limited to these algorithms, and the set of required algorithms will be revisited in every revision of the specification.

# Common types

## Errors

The WASI-crypto APIs share a unique error set, represented as the `crypto_errno` error type.

| Value                   | Descrpition                                                                                                                                                                                                                       |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `success`               | Operation succeeded.                                                                                                                                                                                                              |
| `guest_error`           | An error occurred when trying to during a conversion from a host type to a guest type. Only an internal bug can throw this error.                                                                                                 |
| `not_implemented`       | The requested operation is valid, but not implemented by the host.                                                                                                                                                                |
| `unsupported_feature`   | The requested feature is not supported by the chosen algorithm.                                                                                                                                                                   |
| `prohibited_operation`  | The requested operation is valid, but was administratively prohibited.                                                                                                                                                            |
| `unsupported_encoding`  | Unsupported encoding for an import or export operation.                                                                                                                                                                           |
| `unsupported_algorithm` | The requested algorithm is not supported by the host.                                                                                                                                                                             |
| `unsupported_option`    | The requested option is not supported by the currently selected algorithm                                                                                                                                                         |
| `invalid_key`           | An invalid or incompatible key was supplied. The key may not be valid, or was generated for a different algorithm or parameters set.                                                                                              |
| `invalid_length`        | The currently selected algorithm doesn't support the requested output length. This error is thrown by non-extensible hash functions, when requesting an output size larger than they produce out of a single block.               |
| `verification_failed`   | A signature or authentication tag verification failed.                                                                                                                                                                            |
| `rng_error`             | A secure random numbers generator is not available. The requested operation requires random numbers, but the host cannot securely generate them at the moment.                                                                    |
| `algorithm_failure`     | An error was returned by the underlying cryptography library. The host may be running out of memory, parameters may be incompatible with the chosen implementation of an algorithm or another unexpected error may have happened. |
| `invalid_signature`     | The supplied signature is invalid, or incompatible with the chosen algorithm.                                                                                                                                                     |
| `closed`                | An attempt was made to close a handle that was already closed.                                                                                                                                                                    |
| `invalid_handle`        | A function was called with an unassigned handle, a closed handle, or handle of an unexpected type.                                                                                                                                |
| `overflow`              | The host needs to copy data to a guest-allocated buffer, but that buffer is too small.                                                                                                                                            |
| `internal_error`        | An internal error occurred. This error is reserved to internal consistency checks, and must only be sent if the internal state of the host remains safe after an inconsistency was detected.                                      |
| `too_many_handles`      | Too many handles are currently open, and a new one cannot be created. Implementations are free to represent handles as they want, and to enforce limits to limit resources usage.                                                 |
| `key_not_supported`     | A key was provided, but the chosen algorithm doesn't support keys. This is returned by symmetric operations such as hash functions.                                                                                               |
| `key_required`          | A key is required for the chosen algorithm, but none was given.                                                                                                                                                                   |
| `invalid_tag`           | The provided authentication tag is invalid or incompatible with the current algorithm. Unlike `verification_failed`, this error code is returned when the tag cannot possibly verify for any input.                               |
| `invalid_operation`     | The requested operation is incompatible with the current scheme.                                                                                                                                                                  |
| `nonce_required`        | A nonce is required by a cipher.                                                                                                                                                                                                  |
| `invalid_nonce`         | The provided nonce doesn't have a correct size for the given cipher.                                                                                                                                                              |
| `option_not_set`        | The named option was not set.                                                                                                                                                                                                     |
| `not_found`             | A key or key pair matching the requested identifier cannot be found using the supplied information.                                                                                                                               |
| `parameters_missing`    | The algorithm requires parameters that haven't been set.                                                                                                                                                                          |
| `in_progress`           | A requested computation is not done yet, and additional calls to the function are required.                                                                                                                                       |
| `incompatible_keys`     | Multiple keys have been provided, but they do not share the same type.                                                                                                                                                            |
| `expired`               | A managed key or secret expired and cannot be used any more.                                                                                                                                                                      |

## Handles

All handle types MUST be thread-safe.

* Some objects cannot be reused. A handle to such an object will be automatically closed after the first successful function call consuming them. If the function returns an error, the handle remains valid.
* Other objects can be reused across multiple function calls, even in different threads. A handle to such an object can be explicitly closed by the guest application. The handle MUST be reference counted. A call to the `*_close()` function decrements the number of references, and the handle remains valid as long as references are still active, i.e. as long as functions are still using it. However, new function calls cannot use that handle as a parameter any longer.

## Encodings

Implementations can internally represent keys, group elements and signatures in any way.

Applications never access these representations directly. Keys, group elements and signatures can only be “imported” or “exported” using well-defined, standard encodings. A WASI-crypto implementation is responsible for converting these encodings from and into a possibly more efficient internal representation.

WASI-crypto implementations MUST define the following encodings:

* `raw`: raw byte strings, as defined by individual primitives.
* `pkcs8`: `PKCS#8`/`DER` encoding. Implementations MAY support encryption.
* `pem`: `PEM`-encoded `PKCS#8`/`DER` format. Implementations MAY support encryption.
* `sec`: Affine coordinates [`SEC-1`](https://www.secg.org/sec1-v2.pdf) elliptic curve point encoding.
* `compressec_sec`: Single-coordinate [`SEC-1`](https://www.secg.org/sec1-v2.pdf) elliptic curve point encoding.
* `local`: implemented-defined encoding. Such a representation can be more efficient than standard serialization formats, but is not defined not required by the WASI-crypto specification, and is thus not meant to be portable across implementations.

Encodings are specified as constants, which are defined for individual key types:

* `keypair_encoding`
* `publickey_encoding`
* `secretkey_encoding`
* `signature_encoding`

### Symmetric keys

Symmetric keys are of type `symmetric_key`.

A symmetric key must be encodable and decodable from/to a raw byte string.

Symmetric primitives have unique, well-defined representations of their input and outputs, and the WASI-crypto doesn't impose any modifications.

### Asymetric keys

#### Secret keys

A secret key may be representable as a fixed-size scalar. In that case, the WASI-crypto API requires a `raw` encoding type to be available both to import and export these keys.

`raw` encoding is the scalar encoded as simple a bit string. Some primitives traditionally use big-endian encoding, while others use little-end Ian. WASI-crypto defines a single `raw` encoding, corresponding to the most common representation.
In particular, for the curves currently required by the API:

* Scalars and field elements must be encoded using big-endian for NIST curves
* Scalars and field elements must be encoded using little-endian for the Edwards25519 and Curve25519 curves.

When a secret cannot be represented as a single, fixed-length scalar, importation and exportation must be possible using the standard `PKCS#8` encoding. This includes RSA. Support for key encryption is optional.

For convenience, `PEM` encoding MUST be also available whenever `PKCS#8` encoding is available.

An implementation MAY also support the `SEC-1` encoding if an elliptic curve point is used as a secret key.

In addition to these standard encodings, implementations MAY support an implemented-defined `local` encoding.

#### Public keys

If a public key can be represented as a fixed-size bit string, the API must support importation and exportation with a `raw` encoding. Such a bit string is usually the compressed representation of a group element, and is well-defined for every group.

In particular:

* A Curve25519 point is represented as its X coordinate in little-endian format. The top bit must be cleared.
* An Edwards25519 point is represented as its Y coordinate and the sign of the X coordinate.

Points on NIST curves must be importable/exportable using the standard `SEC-1` encoding, both with and without compression. The WASI-Crypto API defines the `sec` and `compressed_sec` encodings for that purpose.

Finally, implementations MAY support a non-portable, optimized representation for public keys, referred to as `local` in the set of possible encodings for a public key.

#### Key pairs for key exchange

A WASI-crypto implementation MUST be able to store a key pair as a unique handle, from which handles of individual keys can later be extracted.

For every supported key type, an implementation MAY allow importation and exportation of a key pair as a single operation, either using a local encoding, or using `PKCS#8` or `PEM`-encoded `PKCS#8`.

#### Key pairs for signatures

For signature, a `keypair` is an object with the following properties:

* A signature can be computed using this object and the data to be signed,
* A public key can be efficiently computed from it.

Internally, implementations are free to store an actual key pair, or just a secret key, according to what would be most efficient for each primitive. This choice doesn’t affect the behavior of the external APIs.

Some signature schemes require the presence of the public key in order to compute a new signature. In that case, a `keypair` object must include the public key. This prevents applications from having to supply it themselves, which would expose the scheme to leakage if the wrong public key was ever used.

EdDSA, in particular, has a well-defined format for encoding both the secret scalar and the public key as a 64 byte string. The `raw` encoding of an EdDSA key pair must use that format. Trying to decode a string that only includes the secret scalar results in an `invalid_key` error.

### Signatures

Signatures must be exportable and importable as a bit string (`raw`).

In addition, an implementation MAY allow these signatures to be serialized using the standard `DER` encoding.

## Required encodings and key types

|         | Signature key pair                                                                                                   | Secret key                                                                  | Public key                                                                  |
| ------- | -------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Ed25519 | raw (private key + secret key encoded as in RFC8032)                                                                 | raw (cf. RFC8032)                                                           | raw (cf. RFC8032)                                                           |
| X25519  | N/A                                                                                                                  | raw (cf. RFC7748)                                                           | raw (cf. RFC7748)                                                           |
| p256    | raw secret scalar encoded as big endian, SEC-1, compressed SEC-1, unencrypted PKCS#8, PEM-encoded unencrypted PKCS#8 | SEC-1, compressed SEC-1, unencrypted PKCS#8, PEM-encoded unencrypted PKCS#8 | SEC-1, compressed SEC-1, unencrypted PKCS#8, PEM-encoded unencrypted PKCS#8 |
| RSA     | unencrypted PKCS#8, PEM-encoded unencrypted PKCS#8                                                                   | unencrypted PKCS#8, PEM-encoded unencrypted PKCS#8                          | unencrypted PKCS#8, PEM-encoded unencrypted PKCS#8                          |


## Array outputs

Functions returning arrays whose size is not constant or too large to be safely allocated on the stack return a handle to an `array_ouptut` type.

Applications can obtain the length of the output (in bytes) using the `array_ouptut_len()` function, and/or copy the content using `array_output_pull()`.

Multiple calls to `array_output_pull()` are possible, so that large ouputs can be copied in a streaming fashion. The total number of bytes to be read is guaranteed to always match the value returned by `array_output_len()`. `array_output_pull()` never blocks, and always fills `min(requested_length, available_length)` bytes, returning the actual number of bytes having been copied.

The handle is automatically closed after all the data has been consumed, so this type doesn't have a `close()` function.

In practice, the output length is often constant for a given algorithm, so a single function call is enough to copy the data from the host to the guest:

```rust
let mut out = [0u8; 32];
array_output_pull(output_handle, &mut out)?;
```

If the length is not known in advance, an application can either use a heap allocation or a stack-alloced buffer that can later be resized:

```rust
let len = array_output_len(output_handle)?;
let mut out = vec![0u8; len];
array_output_pull(output_handle, &mut out)?;
```

```rust
let mut out = [0u8; 128];
let len = array_output_pull(output_handle, &mut out)?;
out = &out[..len];
```

## Options

Some functions support options. For example, options can be used to access features that are only relevant to specific ciphers and hash functions.

Options are represented as a `(key, value)` map, keys being strings. They are attached to a context, such as a cipher state. Applications can set, but also read the value associated with a key in order to either get the default value, or obtain runtime information.

For example, in the context of an AEAD, the `nonce` option can be set by the application in order to set the nonce. But if the runtime can safely compute a nonce for each encryption, an application may not set the nonce, and retrieve the actual nonce set by the runtime by reading the `nonce` option.

In WebAssembly, the overhead of a guest-host function call is negligible. The `option` API leverages this to only require simple types, so that bindings are simple to implement. This also allows the API to return an error code for an individual option trying to be set.

An `option` can be reused, but is tied to algorithm type.

Example usage (setting an option):

```rust
let options_handle = options_open(AlgorithmType::Symmetric)?;
options_set(options_handle, "nonce", nonce)?;
let state_handle = symmetric_state_open("AES-256-GCM", None, Some(options_handle));
options_close(options_handle)?;
```

Example usage (reading an option set by the runtime):

```rust
let options_handle = options_open(AlgorithmType::Symmetric)?;
let state_handle = symmetric_state_open("XChaCha20-Poly1305", None, Some(options_handle));
let nonce_handle = symmetric_state_options_get(state_handle, "nonce")?; // array_output handle
```

Three option types are supported and can be mixed and matched in an option set:

- Byte vectors, set with `<algorithm type>_options_set()`
- Unsigned integers, set with `<algorithm type>_options_set_u64()`
- Memory buffers, set with `<algorithm type>_set_guest_buffer()`

Some primitives may require a large scratch buffer, that should be accounted as guest memory. This is the case for memory-hard password hashing functions such as Scrypt or Argon2. The last option type (memory buffers) handles this use case.

Here is an example of an option set for a password hashing function:

```rust
let options_handle = symmetric_options_open()?;
symmetric_options_set_guest_buffer(options_handle, "memory", &mut memory)?;
symmetric_options_set_u64(options_handle, "opslimit", 5)?;
symmetric_options_set_u64(options_handle, "parallelism", 8)?;
let state_handle = symmetric_state_open("ARGON2-ID-13", None, Some(options))?;
```

# Asymmetric operations

Asymmetric operations depend on secret material, as well as a public counterpart.

They all share the same types:

* A `secretkey` object represents a secret key
* A `publickey` object represents a public key
* A `keypair` object represents a secret key, but can also efficiently return its public counterpart, either by recomputing it or by also storing it.

All these objects also store an algorithm identifier to prevent them from being used with the wrong algorithm.

## Secret keys

A secret key object can be created from a serialized representation with the `secretkey_import()` function:

```rust
let sk_handle = secretkey_import(AlgorithmType::Signatures, "RSA_PKCS1_2048_SHA256", SecretkeyEncoding::PKCS8)?;
```

In order to prevent misuse, the encoding and the algorithm the key will be used for must be specified.

Once imported, a secret key can be reused for multiple operations, as long as they share the same algorithm.

Given a handle, a secret key can also be serialized for long term storage by the guest application:

```rust
let serialized_sk_handle = secretkey_export(sk_handle, SecretkeyEncoding::PKCS8)?;
```

This returns an `array_output` handle.

After use, a secret key can be disposed with `secretkey_close()`:

```rust
secretkey_close(sk_handle)?;
```

The `secretkey_close()` function indicates that the secret key will not be needed any more. Once the number of references to the handle reaches `0`, the runtime SHOULD overwrite the internal representation of the secret in memory.

## Public keys

Public keys can be imported from a serialized representation:

```rust
let pk_handle = publickey_import(AlgorithmType::Signatures, "RSA_PKCS1_2048_SHA256", PublickeyEncoding::PKCS8)?;
```

A public key that deserializes successfully might not be safe to use with all protocols. In particular, when using elliptic curves, point coordinates may not be on the curve, or may not be on the main subgroup.

Applications can validate a public key with the `publickey_verify()` function. If a public key type doesn't need validation, the function MUST return a sucessful return code. If a public key MAY need validation to be safe to use, but a verification hasn't been implemented yet, the function MUST return a `not_implemented` error code.

A public key object can also be computed from a secret key handle:

```rust
let pk_handle = publickey_from_secretkey(sk_handle)?;
```

This operation MUST succeed if the secret key is valid. However, for some algorithms, it may be a computationally expensive operation. For these algorithms, applications are encouraged to use `keypair` objects instead, that MAY store a copy of the public key along with the secret key.

Given a handle, a public key can be serialized:

```rust
let serialized_pk_handle = secretkey_export(pk_handle, PublickeyEncoding::PKCS8)?;
```

## Key pairs

A `keypair` object is an efficient way to represent a secret key and its public material.

Key pairs can be imported from a serialized representation. If a serialization format cannot encode both keys, it must represent the secret key, the runtime being responsible for computing the public counterpart.

```rust
let kp_handle = keypair_import(AlgorithmType::Signatures, "RSA_PKCS1_2048_SHA256", KeypairEncoding::PKCS8)?;
```

A key pair can also be created from handles to a valid secret key and a valid public key. Both keys must have matching algorithms. If this is not the case, the function MUST return the `incompatible_keys` error code.

```rust
let kp_handle = keypair_from_pk_and_sk(pk_handle, sk_handle)?;
```

A WASI-crypto implementation can also create a new key pair. The key pair MUST be generated using a cryptographically-secure random number generator.

```rust
let kp_handle = keypair_generate("ECDSA_P256_SHA256")?;
```

That function returns:
* `success` if a key pair was generated
* `in_progress` if the function call would block for too long. The guest application MAY call the function again with the same parameters until it eventually succeeds. This return code is designed to avoid blocking runtimes doing cooperative scheduling. A guest application should not make any assertions about the maximum time a function can take to return, and a host is always allowed to block until completion.
* `unsupported_algorithm` is returned if the algorithm type is not implemented by the runtime
* `unsupported_feature` is returned if the algorithm type is supported by the runtime, but key pair generation is not, possibly due to the lack of a secure random number generator.

Once generated, a key pair and its components can be exported if necessary.

A key pair can be reused for multiple operations, as long as they share the same algorithm. A function expecting a different type of key pair MUST immediately return `invalid_key`.

After use, a key pair can be disposed with `keypair_close()`:

```rust
keypair_close(sk_handle)?;
```

The `keypair_close()` function indicates that the key pair will not be needed any more.

Closing a key pair decreases the reference count of the secret and private parts. Handles to these remain valid until their own reference count reaches `0`.

# Key exchange systems

A WASI-crypto implementation MUST support at least two different key exchange mechanisms:

* Diffie-Hellman based key agreement, returning a deterministic secret for a given (public key, secret key) pair
* Key encapsulation mechanisms, where the runtime is expected to generate a random secret, and encapsulate it using the recipient's public key.

Key exchange mechanisms use the common asymetric key types: `secretkey`, `publickey` and `keypair`.

Such keys can be created and exported using the common functions for handling asymmetric keys.

However, implementations are encouraged to use the type aliases defined in the WITX specification when they are used in a key exchange context.

| Type        | Alias          |
| ----------- | -------------- |
| `secretkey` | `kx_secretkey` |
| `publickey` | `kx_publickey` |
| `keypair`   | `kx_keypair`   |

## Diffie-Hellman based key agreement

```rust
let shared_secret_handle = kx_dh(pk_handle, sk_handle)?;
```

The `kx_dh()` function returns an `array_output` handle from which the shared secret can be copied.

If the public key is invalid or insecure (such as a low-order elliptic curve point), the `invalid_key` error code is returned instead.

## Key encapsulation mechanisms

The runtime is responsible for generating a random secret. The `kx_encapsulate()` function encapsulates it for a public key, and returns both the secret and its encrypted counterpart.

```rust
let (secret_handle, encapsulated_secret_handle) = kx_encapsulate(pk_handle)?;
```

Both returned values are `array_output` handles.

The recipient can then decrypt the shared secret (supplied as a byte string) using their secret key:

```rust
let secret_handle = kx_decapsulate(sk_handle, encapsulated_secret)?;
```

If the decapsulation fails, the `kx_decapsulate()` function MUST return `verification_failed`.

## Note on Hybrid Public Key Encryption

A WASI-crypto implementation is not required to expose a Hybrid Public Key Encryption interface. HPKE can be easily and securely be reimplemented using the existing APIs.

# Signatures

Signatures use asymetric key types: `secretkey`, `publickey` and `keypair`.

Such keys can be created and exported using the common functions for handling asymmetric keys.

However, implementations are encouraged to use the type aliases defined in the WITX specification when they are used in a signature context.

| Type        | Alias                 |
| ----------- | --------------------- |
| `secretkey` | `signature_secretkey` |
| `publickey` | `signature_publickey` |
| `keypair`   | `signature_keypair`   |

Signatures introduce an additional `signature` type. A signature can be imported and exported with different encodings.

A WASI-crypto implementation MUST support the `raw` encoding, that represents the signature as compact, a fixed-length byte sequence with a well-defined format for every algorithm. In addition, an implementation MAY support the `DER` format, or return `unsupported_encoding` if this is not the case.

## Signature creation

Signature computation requires the following steps:

1) `signature_state_open()` to create a new state
2) One of more calls to `signature_state_update()` to absorb a message to be signed
3) `signature_state_sign()` to compute a signature for all the data absorbed until that point
4) `signature_state_close()` to dispose the state

A WASI-crypto implementation is expected to support a streaming interface (`signature_state_update()`) for all the implemented algorithms.

However, doing so with two-pass algorithms such as EdDSA may require the runtime to accumulate a copy of the input until the signature is made. Implementations SHOULD limit the input length, and return the `overflow` error code if it is too long.
Guest applications should not make any assertion about the maximum supported length, and should use pre-hashed signature systems if the input is large or is not fully available.

`signature_state_sign()` does not reset the state.

Additional `signature_state_update()`+`signature_state_sign()` sequences can be made in order to incrementally sign the input since the beginning of the transcript.

```rust
let kp_handle = keypair_import(AlgorithmType::Signatures, "Ed25519", keypair, KeypairEncoding::Raw)?;
let state_handle = signature_state_open(kp_handle)?;
signature_state_update(state_handle, b"message part 1")?;
signature_state_update(state_handle, b"message part 2")?;
let sig_handle = signature_state_sign(state_handle)?;
let raw_sig = signature_export(sig_handle, SignatureEncoding::Raw)?;
```

## Signature verification

Signature verifiction requires the following steps:

1) `signature_verification_state_open()` to create a new state
2) One of more calls to `signature_verification_state_update()` to absorb a message to be verified
3) `signature_verification_state_verify()` to verify the signature of the entire input absorbed up to that point.
4) `signature_verification_state_close()` to dispose the state

States used for signature creation and verification are not interchangeable. An implementation MUST return the `invalid_handle` error if a verification function is called on a state originally opened for signature creation or the other way round.

```rust
let pk_handle = publickey_import(AlgorithmType::Signatures, "ECDSA_P256_SHA256", encoded_pk, PublicKeyEncoding::CompressedSec)?;
let signature_handle = signature_import(AlgorithmType::Signatures, "ECDSA_P256_SHA256", encoded_sig, SignatureEncoding::Der)?;
let state_handle = signature_verification_state_open(pk_handle)?;
signature_verification_state_update(state_handle, "message")?;
signature_verification_state_verify(signature_handle)?;
signature_verification_state_close(signature_handle)?;
```