# wasi-crypto

A proposal for a WASI cryptography API.

* [High-level goals](docs/HighLevelGoals.md)
* [Design](design/security.md)
* [Specification](docs/wasi-crypto.md)
* Interface definitions:
  * common types and functions ([witx](witx/proposal_common.witx), [doc](witx/proposal_common.md))
  * symmetric operations ([witx](witx/proposal_siymmetric.witx), [doc](witx/proposal_symmetric.md))
  * common types and functions for asymmetric operations ([witx](witx/proposal_asymmetric_common.witx), [doc](witx/proposal_asymmetric_common.md))
  * signatures ([witx](witx/proposal_signatures.witx), [doc](witx/proposal_signatures.md))
  * key exchange ([witx](witx/proposal_kx.witx), [doc](witx/proposal_kx.md))
  * external secrets ([witx](witx/proposal_external_secrets.witx), [doc](witx/proposal_external_secrets.md))
* [Short API overview](witx/wasi_ephemeral_crypto.txt)
* [Implementation](https://github.com/jedisct1/wasi-crypto-preview/tree/master/implementation)
* [Wasmtime integration](https://github.com/jedisct1/wasmtime-crypto)
* [Example AssemblyScript bindings](examples/assemblyscript)
* [Example Rust bindings](examples/rust)

## Testing the API

The example implementation exports:

* A Rust interface `CryptoCtx` modeled after the `witx` file, but that can be directly used without a WebAssembly runtime.
* A thin `WasiCryptoCtx` layer that directly maps that API to the WASI calling conventions, using `wiggle`.

`CryptoCtx` can be used to quickly experiment with the API in Rust.

Other languages can use the [`wasmtime` fork](https://github.com/jedisct1/wasmtime-crypto) above as a WebAssembly runtime in order to access the crypto API.

In that configuration, the API can be accessed via the exported `wasi_ephemeral_crypto` module.

See the AssemblyScript and Rust bindings as an example.

Currently supported algorithms as a proof of concept:

* `ECDSA_P256_SHA256`
* `ECDSA_K256_SHA256`
* `Ed25519`
* `RSA_PKCS1_2048_SHA256`
* `RSA_PKCS1_2048_SHA384`
* `RSA_PKCS1_2048_SHA512`
* `RSA_PKCS1_3072_SHA384`
* `RSA_PKCS1_3072_SHA512`
* `RSA_PKCS1_4096_SHA512`
* `RSA_PSS_2048_SHA256`
* `RSA_PSS_2048_SHA384`
* `RSA_PSS_2048_SHA512`
* `RSA_PSS_3072_SHA384`
* `RSA_PSS_3072_SHA512`
* `RSA_PSS_4096_SHA512`
* `HKDF-EXTRACT/SHA-256`
* `HKDF-EXTRACT/SHA-512`
* `HKDF-EXPAND/SHA-256`
* `HKDF-EXPAND/SHA-512`
* `HMAC/SHA-256`
* `HMAC/SHA-512`
* `SHA-256`
* `SHA-512`
* `SHA-512/256`
* `AES-128-GCM`
* `AES-256-GCM`
* `CHACHA20-POLY1305`
* `XCHACHA20-POLY1305`
* `XOODYAK-128`
* `XOODYAK-160`
* `X25519`
* `KYBER768`
