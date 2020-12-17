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

# Symmetric operations

The WASI-crypto symmetric API was designed with the following constraints in mind:
- It should support a wide range of common primitives and construction
- It should be future proof and easy to extend without breaking changes
- The API should be generic without preventing access to additional features each algorithm may support
- The API should be small and consistent
- It should mitigate misuse without being restrictive.

In order to do so, it relies on three dedicated object types:
- a `symmetric_key` object represents a key and an algorithm
- a `symmetric_state` is created from key, and performs symmetric operations using the underlying algorithm
- a `symmetric_tag` is an authentication tag, that can be verified without channels using the provided API.

## Options

Function accepting symmetric keys can also accept option sets (optional `options` objects).

These options serve two different roles:
- To set parameters that are only supported by specific algorithms
- To retrieve information about the current state

The following set of option names are reserved:

| Option name    | Description                                | Type             |
| -------------- | ------------------------------------------ | ---------------- |
| `context`      | Context/domain for hash functions and XOFs | Byte string      |
| `salt`         | Salt for hash functions                    | Byte string      |
| `nonce`        | Nonce or IV for ciphers                    | Byte string      |
| `memory_limit` | Memory limit in bytes for memory-hard KDFs | Unsigned integer |
| `ops_limit`    | Computational cost for CPU-hard KDFs       | Unsigned integer |
| `parallelism`  | Number of threads to use                   | Unsigned integer |
| `buffer`       | Scratch buffer for memory-hard KDFs        | Memory           |

For the required set of algorithms, only the `nonce` option has to be implemented, and only for algorithms supporting encryption operations.

## Symmetric keys

Keys are represented by the `symmetric_key` type for all symmetric operations, and are tied to an algorithm. They can only be serialized as raw bytes, therefore, the import and export functions omit an encoding parameter.

A key can be imported from raw bytes:

```rust
let key_handle = symmetric_key_import("SHA-256", bytes)?;
```

The function returns:
- a `symmetric_key` handle on success. 
- an `unsupported_algorithm` error code if the algorithm is not supported by the host
- an `invalid_key` error code if the key size is invalid for the given algorithm

An existing key can also be exported as raw bytes:

```rust
let raw_handle = symmetric_key_export(key_handle)?;
```

The returned value is an `array_output` handle.

A new key can also be securely generated by the runtime:

```rust
let key_handle = symmetric_key_generate("SHA-256")?;
```

Some algorithm accept multiple key sizes. 

The table below lists the key sizes that a WASI-crypto implementation SHOULD choose for common algorithms with a non-fixed key size:

| Algorithm              | Runtime-generated key size (bytes) |
| ---------------------- | ---------------------------------- |
| `HKDF-EXTRACT/SHA-256` | 32                                 |
| `HKDF-EXTRACT/SHA-512` | 64                                 |
| `HMAC/SHA-256`         | 32                                 |
| `HMAC/SHA-512`         | 64                                 |

This function call always succeeds unless a secure random number generator is not available. On error, the function returns:

- `rng_error` if the internal random number generator is temporarily unavailable
- `unsupported_feature` if the algorithm is implemented except key generation
- `unsupported_algorithm` if the algorithm is not implemented.

Finally, a key handle can be closed after use. Once closed, using that handle as a parameter for a symmetric operation MUST return an `invalid_handle` error code.

## State

Symmetric operations must be done using the following pattern:

- `symmetric_state_open()`
- one or more `symmetric_state_*()` function calls
- `symmetric_state_close()`

In order to support incremental updates, multiple function calls can be done using the same state.

The `symmetric_state_open()` function creates a new state from a key and an algorithm:

```rust
let state = symmetric_state_open("HMAC/SHA-256", key_handle, None)?;
```

The function has two optional parameters: a key and an options set.

On success, the function returns a `symmetric_state` handle.

On error, it returns:
- A `key_not_supported` error code if a key was provided but the chosen algorithm doesn't support keys
- A `key_required` error code if a key is required, but was not provided
- A `parameters_missing` error code if some parameters are mandatory but were not set.

Ciphers may require a nonce or initialization vector, to be set using the `nonce` option.

However, if a nonce is required but was not supplied:

- If it is safe to do so, the host MUST generate a nonce. This is true for nonces that are large enough to be randomly generated, or if the host is able to maintain a global counter.
- If not, the function will fail and return the dedicated `nonce_required` error code.

A nonce that was automatically generated can be obtained by the guest application by reading the value of the `nonce` option using the `symmetric_state_get()` function.

A call to `symmetric_state_close()` indicates that the state will not be used any more. The host SHOULD overwrite internal sensitive data associated with the state before returning from that function.

## Symmetric operations

Symmetric operations are performed by composing the following functions:

* `symmetric_state_absorb()`: absorb data into the state.

  - **Hash functions:** adds data to be hashed.
  - **MAC functions:** adds data to be authenticated.
  - **Tuplehash-like constructions:** adds a new tuple to the state.
  - **Key derivation functions:** adds to the IKM or to the subkey information.
  - **AEAD constructions:** adds additional data to be authenticated.
  - **Stateful hash objects, permutation-based constructions:** absorbs.

If the chosen algorithm doesn't accept input data, the `invalid_operation` error code is returned.

If too much data has been fed for the algorithm, `overflow` MUST be thrown.

* `symmetric_state_squeeze()`: squeeze bytes from the state.

  - **Hash functions:** this tries to output an `out_len` bytes digest from the absorbed data. The hash function output will be truncated if necessary. If the requested size is too large, the `invalid_len` error code is returned.
  - **Key derivation functions:** : outputs an arbitrary-long derived key.
  - **RNGs, DRBGs, stream ciphers:**: outputs arbitrary-long data.
  - **Stateful hash objects, permutation-based constructions:** squeeze.

Other kinds of algorithms MUST return `invalid_operation` instead.

For password-stretching functions, the function MAY return `in_progress`.

In that case, the guest SHOULD retry with the same parameters until the function completes.

* `symmetric_state_squeeze_tag()`: compute and return a tag for all the data injected into the state so far.

  - **MAC functions**: returns a tag authenticating the absorbed data.
  - **Tuplehash-like constructions:** returns a tag authenticating all the absorbed tuples.
  - **Password-hashing functions:** returns a standard string containing all the required parameters for password verification.

Other kinds of algorithms MUST return `invalid_operation` instead.

For password-stretching functions, the function MAY return `in_progress`.
In that case, the guest SHOULD retry with the same parameters until the function completes.

* `symmetric_state_squeeze_key()`: use the current state to produce a key for a target algorithm.

For extract-then-expand constructions, this returns the PRK.

For session-base authentication encryption, this returns a key that can be used to resume a session without storing a nonce.

The output of this function is a `symmetric_key` handle.

`invalid_operation` MUST be returned for algorithms not supporting this operation.

* `symmetric_state_ratchet()`: make it impossible to recover the previous state.

This operation is supported by some systems keeping a rolling state over an entire session, for forward security.

`invalid_operation` MUST be returned for algorithms not supporting ratcheting.

* `symmetric_state_encrypt()`: encrypt data with an attached tag.

  - **Stream cipher:** adds the input to the stream cipher output.
  - **AEAD:** encrypts; the ciphertext MUST include the authentication tag. Additional data MAY have been previously absorbed using `symmetric_state_absorb()`.
  - **Session:** encrypts data, squeezes a tag and appends it to the output.

The function accepts input and output pointers. An implementation MUST support overlapping memory regions.

Modes requiring padding MUST include padding in the tag. Authentication tags MUST have a constant size.

The guest application is expected to supply an output buffer whose size exactly matches the size required to store the ciphertext and the tag.

The host MUST return an `overflow` error code if the output buffer is too small, and `invalid_length` if it is too large.

`invalid_operation` MUST be returned for algorithms not supporting encryption.

* `symmetric_state_decrypt()`: decrypt a ciphertext with an attached tag.

  - **Stream cipher:** adds the input to the stream cipher output.
  - **AEAD:** decrypt a ciphertext. Additional data MAY have been previously absorbed using `symmetric_state_absorb()`.
  - **Session:** decrypts data, squeezes a tag and verify that it matches the one that was appended to the ciphertext.

`invalid_tag` MUST be returned if the tag didn't verify.
  
`invalid_operation` MUST be returned for algorithms not supporting encryption.

The guest application is expected to supply an output buffer whose size exactly matches the size required to store the decrypted message, without the tag.

The host MUST return an `overflow` error code if the output buffer is too small, and `invalid_length` if it is too large.

`invalid_operation` MUST be returned for algorithms not supporting encryption.

The host SHOULD avoid side channels during tag verification.

* `symmetric_state_encrypt_detached()`: encrypt data and return the ciphertext and the authentication tag separately.

The guest application is expected to supply an output buffer whose size exactly matches the size required to store the encrypted message.

The host MUST return an `overflow` error code if the output buffer is too small, and `invalid_length` if it is too large.

  
* `symmetric_state_decrypt_detached()`: verify an authentication tag and decrypt the corresponding ciphertext if verification passes.

The host SHOULD avoid side channels during tag verification.

The guest application is expected to supply an output buffer whose size exactly matches the size required to store the decrypted message.

The host MUST return an `overflow` error code if the output buffer is too small, and `invalid_length` if it is too large.

## Authentication tags

An authentication tag is always returned as handle. WASI-crypto bindings SHOULD verify them with the `symmetric_tag_verify()` function instead of exporting them and doing the verification themselves.

Authentication tags are assumed to be very small. For this reason, copying the actual tag to the guest environment requires a single function call, which also immediately invalides the handle. Unlike `array_output` handles, no streaming interface is necessary. Implementation can directly map handles to the raw representation of a tag.

Checking that a computed tag matches an expected tag is made using the `symmetric_tag_verify()` function:

```rust
symmetric_tag_verify(tag_handle, expected_tag)?;
```

The expected tag is always supplied as a byte string. Implementations are not required to support any serialization format.

The function MUST return `invalid_tag` if the tags don't match.

A guest application can obtain the size of a tag in bytes using the `symmetric_tag_len()` function on an existing tag. For most algorithms, this is a constant.

Finally, guest applications can obtain the byte representation of a tag using `symmetric_tag_pull()`:

```rust
symmetric_tag_pull(tag_handle, &mut raw_bytes)?;
```

If this function succeeds, the tag handle is automatically closed.

The output buffer is expected to have a size that exactly matches the tag length, as returned by `symmetric_tag_len()`.

The host MUST return an `overflow` error code if the output buffer is too small, and `invalid_length` if it is too large.

## Patterns

Each algorithm type supports a subset of `symmetric_state_*()` functions.

If a function is not defined for an algorithm, it MUST unconditionally return an `unsupported_feature` error code.

### Hash functions

Hash functions MUST support the following set of operations:
- `aborb()`
- `squeeze()`

```rust
let mut out = [0u8; 64];
let state_handle = symmetric_state_open("SHA-256", None)?;
symmetric_state_absorb(state_handle, b"data")?;
symmetric_state_absorb(state_handle, b"more_data")?;
symmetric_state_squeeze(state_handle, &mut out)?;
```

`absorb()` adds input data to the state, and is equivalent to the `UPDATE()` function in NIST interfaces.

`squeeze()` returns a digest of the input received up to the function call.

If finalization is required, the implementation MUST duplicate the internal state and apply the finalization on the copy, leaving the state unchanged from the guest perspective.

This does not apply to hash functions designed to include `squeeze()` calls in a session transcript.

Implementations MUST support an arbitrary number of `absorb()` and `squeeze()` calls, in any order.

The output buffer given to the `squeeze` function can be smaller than the hash function output size. In that case, the implementation MUST truncate the output to the requested length.

If the requested size exceeds what the hash function can output, the `invalid_length` error code MUST be returned.

### Message Authentication Codes

MACs MUST support the following set of operations:
- `absorb()`
- `squeeze_tag()`

Tag generation:

```rust
let mut raw_tag = [0u8; 64];
let key_handle = symmetric_key_import("HMAC/SHA-512", b"key")?;
let state_handle = symmetric_state_open("HMAC/SHA-512", Some(key_handle), None)?;
symmetric_state_absorb(state_handle, b"data")?;
symmetric_state_absorb(state_handle, b"more_data")?;
let computed_tag_handle = symmetric_state_squeeze_tag(state_handle)?;
symmetric_tag_pull(computed_tag_handle, &mut raw_tag)?;
```

Tag verification:

```rust
let state_handle = symmetric_state_open("HMAC/SHA-512", Some(key_handle), None)?;
symmetric_state_absorb(state_handle, b"data")?;
symmetric_state_absorb(state_handle, b"more_data")?;
let computed_tag_handle = symmetric_state_squeeze_tag(state_handle)?;
symmetric_tag_verify(computed_tag_handle, expected_raw_tag)?;
```

`absorb()` adds input data to the state.

`squeeze_tag()` authenticates the input received up to the function call.

If finalization is required, the implementation MUST duplicate the internal state and apply the finalization on the copy, leaving the state unchanged from the guest perspective.

### Tuple hashing

NOTE: Tuple hashing is not required for a WASI-implementation. However, the following pattern SHOULD be used by implementations supporting this type of construction.

Required operations:
- `aborb()`
- `squeeze()`

```rust
let mut out = [0u8; 64];
let state_handle = symmetric_state_open("TupleHashXOF256", None, None)?;
symmetric_state_absorb(state_handle, b"value 1")?;
symmetric_state_absorb(state_handle, b"value 2")?;
symmetric_state_absorb(state_handle, b"value 3")?;
symmetric_state_squeeze(state_handle, &mut out)?;
```

Individual inputs to the `absorb()` function MUST be domain separated and MUST NOT be concatenateed.

### Key derivation using extract-and-expand

Extract-and-expand constructions MUST support the following operations:
- Extract:
  - `absorb()`
  - `squeeze_key()`
- Expand:
  - `absorb()`
  - `squeeze()`

Extract:

```rust
let mut prk = vec![0u8; 64];
let key_handle = symmetric_key_import("HKDF-EXTRACT/SHA-512", b"key")?;
let state_handle = symmetric_state_open("HKDF-EXTRACT/SHA-512", Some(key_handle), None)?;
symmetric_state_absorb(state_handle, b"salt")?;
let prk_handle = symmetric_state_squeeze_key(state_handle, "HKDF-EXPAND/SHA-512")?;
```

Expand:

```rust
let mut subkey = vec![0u8; 32];
let state_handle = symmetric_state_open("HKDF-EXPAND/SHA-512", Some(prk_handle), None)?;
symmetric_state_absorb(state_handle, b"info")?;
symmetric_state_squeeze(state_handle, &mut subkey)?;
```

`aborb()` absorbs the salt of the key information.

`squeeze_key()` returns the PRK, whose algorithm type is set to the EXPAND counterpart of the EXTRACT operation.

The absence of an `absorb()` call MUST be equivalent the an empty salt or key information.

Multiple calls to `absorb()` MUST be equivalent to a single call with the concatenation of the inputs.

### Key derivation using a XOF

XOFs MUST support the following operations:

- `absorb()`
- `squeeze()`

```rust
let mut subkey1 = vec![0u8; 32];
let mut subkey2 = vec![0u8; 32];
let key_handle = symmetric_key_import("BLAKE3", b"key")?;
let state_handle = symmetric_state_open("BLAKE3", Some(key_handle), None)?;
symmetric_absorb(state_handle, b"context")?;
squeeze(state_handle, &mut subkey1)?;
squeeze(state_handle, &mut subkey2)?;
```

WASI-crypto implementations MUST NOT copy the state. Repeated calls to the `squeeze()` function MUST produce different outputs.

### Password hashing functions

Password hashing functions MUST support the following operation:

- `absorb()`

And well as at least one of the following operations:

- `squeeze()`
- `squeeze_tag()`

```rust
let mut memory = vec![0u8; 1_000_000_000];
let options_handle = symmetric_options_open()?;
symmetric_options_set_guest_buffer(options_handle, "memory", &mut memory)?;
symmetric_options_set_u64(options_handle, "opslimit", 5)?;
symmetric_options_set_u64(options_handle, "parallelism", 8)?;

let state_handle = symmetric_state_open("ARGON2-ID-13", None, Some(options))?;
symmtric_state_absorb(state_handle, b"password")?;

let pw_str_handle = symmetric_state_squeeze_tag(state_handle)?;
let mut pw_str = vec![0u8; symmetric_tag_len(pw_str_handle)?];
symmetric_tag_pull(pw_str_handle, &mut pw_str)?;
```

`absorb()` absorbs the low-entropy input.

`squeeze()` returns a derived key stream when the function is used as a KDF

`squeeze_tag()` returns a string that can be used to verify the input. The algorithm must define a standard representation of such string.

Recommended setup for common password hashing functions:

| Function | `absorb()` | `squeeze()` | `squeeze_tag()` |
| -------- | ---------- | ----------- | --------------- |
| PBKDF2   | X          | X           |                 |
| Blowfish | X          |             | X               |
| Argon2   | X          | X           | X               |
| Scrypt   | X          | X           | X               |

The `squeeze()` and `squeeze_tag()` functions MAY return an `in_progress` code in order to avoid blocking for too long. The guest application is expected to perform the exact same function call later until the operation completes.

Implementations SHOULD NOT allocate host memory for memory-hard functions. Instead, they SHOULD require guests to provide a scratch buffer, specified as an option named `memory`.

### AEADs

AEADs MUST support the following operations:

- `absorb()`
- `max_tag_len()`
- `encrypt()`
- `encrypt_detached()`
- `decrypt()`
- `decrypt_detached()`

AEADs requiring a nonce MUST accept one as an option named `nonce`.

```rust
let key_handle = symmetric_key_generate("AES-256-GCM-SIV", None)?;
let message = b"test";
let mut nonce = [0u8; 24];

let state_handle = symmetric_state_open("AES-256-GCM-SIV", Some(key_handle), None)?;

let nonce_handle = symmetric_state_options_get(state_handle, "nonce")?;
array_output_pull(nonce_handle, &mut nonce)?;

let mut ciphertext = vec![0u8; message.len() + symmetric_state_max_tag_len(state_handle)?];
symmetric_state_absorb(state_handle, "additional data")?;
symmetric_state_encrypt(state_handle, &mut ciphertext, message)?;
```

`absorb()` absorbs additional data. Multiple calls to `absorb()` MUST be equivalent to a single call with a concatenation of the inputs.

`max_tag_len()` returns the length required to encode the authentication tag and optional padding bytes. The returned length MUST be constant for a given algorithm.
Guest applications are expected to provide an output buffer whose size is the size of the message, plus the `max_tag_len()` output value.

Decryption functions MUST check the authentication tag, and SHOULD NOT leave decrypted data in the output buffer if the authentication tag didn't verify. If this is the case, they SHOULD zero the entire output buffer and MUST return an `invalid_tag` error code.

If a nonce was provided, but doesn't have the expected size, the implementation MUST return an `invalid_nonce` error code.

The `nonce` option MAY not be set by a guest application. In that case:

- If random or static nonces can safely be used with the chosen algorithm, the runtime CAN that parameter automatically.
- If this is not the case, it MUST return the `nonce_required` error code.

Nonces MUST NOT be automatically generated for any of the algorithms currently required by this document.

However, they MAY be automatically generated for the `XCHACHA20-POLY1305` recommended addition, using a cryptographically-secure random number generator.

A runtime generating a nonce MUST define a `nonce` option set to that nonce, even if the guest application didn't provide that option when creating the state.

### Session authenticated modes

Permutation-based modes allow multiple types of operations over a rolling state authentication the entire transcript.

They MUST support the following operations:

- `absorb()`
- `squeeze()`

Additional operations are algorithm-dependant, and implementations including this type of algorithm MUST document the set of supported operations.

WASI-crypto implementers are encouraged to include the `XOODYAK-128` algorithm to exercices an externsive set of operations typically supported by this kind of construction.

```rust
let mut out = [0u8; 16];
let mut out2 = [0u8; 16];
let mut ciphertext = [0u8; 20];
let key_handle = symmetric_key_generate("XOODYAK-128", None)?;
let state_handle = symmetric_state_open("XOODYAK-128", Some(key_handle), None)?;
symmetric_state_absorb(state_handle, b"data")?;
symmetric_state_encrypt(state_handle, &mut ciphertext, b"abcd")?;
symmetric_state_absorb(state_handle, b"more data")?;
symmetric_state_squeeze(state_handle, &mut out)?;
symmetric_state_squeeze(state_handle, &mut out2)?;
symmetric_state_ratchet(state_handle)?;
symmetric_state_absorb(state_handle, b"more data")?;
let next_key_handle = symmetric_state_squeeze_key(state_handle, "XOODYAK-128")?;
// ...
```