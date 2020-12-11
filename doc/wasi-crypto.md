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
| `X25519`                | X25519 key exchange mechanism as specified in RFC7748                               |

Each algorithm belongs to one of these categories, represented by the `algorithm_type` type:

* `signatures` for signature systems
* `symmetric` for any symmetric primitive or construction
* `key_exhange` for key exchange mechanisms, including DH-based systems and KEMs.

Implementation MAY also include the following algorithms in order to exercise additional features of the API:

| Identifier           | Algorithm                                                                                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `XOODYAK-128`        | XOODYAK lightweight scheme, as specified in the most recent submission to NIST competition for lightweight cryptography                          |
| `XCHACHA20-POLY1305` | ChaCha20-Poly1305 AEAD with extended nonce, as specified in the most recent ` draft-irtf-cfrg-xchacha` CFRG draft                                |
| `KYBER768`           | KYBER-768 post-quantum key encapsulation mechanism, as specified in the most recent submission to NIST competition for post-quantum cryptography |


# Types

## Errors

The WASI-crypto APIs share a unique error set, represented as the `crypto_errno` error type.

The set of possible errors and their description can be found in the `witx` definition of the `common` module.

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

