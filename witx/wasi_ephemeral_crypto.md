# Types
## <a href="#crypto_errno" name="crypto_errno"></a> `crypto_errno`: Enum(`u16`)

### Variants
- <a href="#crypto_errno.success" name="crypto_errno.success"></a> `success`

- <a href="#crypto_errno.guest_error" name="crypto_errno.guest_error"></a> `guest_error`

- <a href="#crypto_errno.not_implemented" name="crypto_errno.not_implemented"></a> `not_implemented`

- <a href="#crypto_errno.unsupported_feature" name="crypto_errno.unsupported_feature"></a> `unsupported_feature`

- <a href="#crypto_errno.prohibited_operation" name="crypto_errno.prohibited_operation"></a> `prohibited_operation`

- <a href="#crypto_errno.unsupported_encoding" name="crypto_errno.unsupported_encoding"></a> `unsupported_encoding`

- <a href="#crypto_errno.unsupported_algorithm" name="crypto_errno.unsupported_algorithm"></a> `unsupported_algorithm`

- <a href="#crypto_errno.unsupported_option" name="crypto_errno.unsupported_option"></a> `unsupported_option`

- <a href="#crypto_errno.invalid_key" name="crypto_errno.invalid_key"></a> `invalid_key`

- <a href="#crypto_errno.invalid_length" name="crypto_errno.invalid_length"></a> `invalid_length`

- <a href="#crypto_errno.verification_failed" name="crypto_errno.verification_failed"></a> `verification_failed`

- <a href="#crypto_errno.rng_error" name="crypto_errno.rng_error"></a> `rng_error`

- <a href="#crypto_errno.algorithm_failure" name="crypto_errno.algorithm_failure"></a> `algorithm_failure`

- <a href="#crypto_errno.invalid_signature" name="crypto_errno.invalid_signature"></a> `invalid_signature`

- <a href="#crypto_errno.closed" name="crypto_errno.closed"></a> `closed`

- <a href="#crypto_errno.invalid_handle" name="crypto_errno.invalid_handle"></a> `invalid_handle`

- <a href="#crypto_errno.overflow" name="crypto_errno.overflow"></a> `overflow`

- <a href="#crypto_errno.internal_error" name="crypto_errno.internal_error"></a> `internal_error`

- <a href="#crypto_errno.too_many_handles" name="crypto_errno.too_many_handles"></a> `too_many_handles`

- <a href="#crypto_errno.key_not_supported" name="crypto_errno.key_not_supported"></a> `key_not_supported`

- <a href="#crypto_errno.key_required" name="crypto_errno.key_required"></a> `key_required`

- <a href="#crypto_errno.invalid_tag" name="crypto_errno.invalid_tag"></a> `invalid_tag`

- <a href="#crypto_errno.invalid_operation" name="crypto_errno.invalid_operation"></a> `invalid_operation`

- <a href="#crypto_errno.nonce_required" name="crypto_errno.nonce_required"></a> `nonce_required`

- <a href="#crypto_errno.option_not_set" name="crypto_errno.option_not_set"></a> `option_not_set`

## <a href="#keypair_encoding" name="keypair_encoding"></a> `keypair_encoding`: Enum(`u16`)

### Variants
- <a href="#keypair_encoding.raw" name="keypair_encoding.raw"></a> `raw`

- <a href="#keypair_encoding.pkcs8" name="keypair_encoding.pkcs8"></a> `pkcs8`

- <a href="#keypair_encoding.der" name="keypair_encoding.der"></a> `der`

- <a href="#keypair_encoding.pem" name="keypair_encoding.pem"></a> `pem`

## <a href="#publickey_encoding" name="publickey_encoding"></a> `publickey_encoding`: Enum(`u16`)

### Variants
- <a href="#publickey_encoding.raw" name="publickey_encoding.raw"></a> `raw`

- <a href="#publickey_encoding.der" name="publickey_encoding.der"></a> `der`

- <a href="#publickey_encoding.pem" name="publickey_encoding.pem"></a> `pem`

- <a href="#publickey_encoding.sec" name="publickey_encoding.sec"></a> `sec`

- <a href="#publickey_encoding.compressed_sec" name="publickey_encoding.compressed_sec"></a> `compressed_sec`

## <a href="#signature_encoding" name="signature_encoding"></a> `signature_encoding`: Enum(`u16`)

### Variants
- <a href="#signature_encoding.raw" name="signature_encoding.raw"></a> `raw`

- <a href="#signature_encoding.der" name="signature_encoding.der"></a> `der`

## <a href="#options_type" name="options_type"></a> `options_type`: Enum(`u16`)

### Variants
- <a href="#options_type.signatures" name="options_type.signatures"></a> `signatures`

- <a href="#options_type.symmetric" name="options_type.symmetric"></a> `symmetric`

## <a href="#version" name="version"></a> `version`: Int(`u64`)

### Consts
- <a href="#version.unspecified" name="version.unspecified"></a> `unspecified`
Key doesn't support versioning.

- <a href="#version.latest" name="version.latest"></a> `latest`
Retrieve the latest version of a key.

- <a href="#version.all" name="version.all"></a> `all`
Perform an operation over all versions of a key.

## <a href="#size" name="size"></a> `size`: `usize`

## <a href="#array_output" name="array_output"></a> `array_output`

### Supertypes
## <a href="#options" name="options"></a> `options`

### Supertypes
## <a href="#signature_keypair_manager" name="signature_keypair_manager"></a> `signature_keypair_manager`

### Supertypes
## <a href="#signature_keypair" name="signature_keypair"></a> `signature_keypair`

### Supertypes
## <a href="#signature_state" name="signature_state"></a> `signature_state`

### Supertypes
## <a href="#signature" name="signature"></a> `signature`

### Supertypes
## <a href="#signature_publickey" name="signature_publickey"></a> `signature_publickey`

### Supertypes
## <a href="#signature_verification_state" name="signature_verification_state"></a> `signature_verification_state`

### Supertypes
## <a href="#symmetric_key_manager" name="symmetric_key_manager"></a> `symmetric_key_manager`

### Supertypes
## <a href="#symmetric_state" name="symmetric_state"></a> `symmetric_state`

### Supertypes
## <a href="#symmetric_key" name="symmetric_key"></a> `symmetric_key`

### Supertypes
## <a href="#symmetric_tag" name="symmetric_tag"></a> `symmetric_tag`

### Supertypes
## <a href="#opt_options_u" name="opt_options_u"></a> `opt_options_u`: Enum(`u8`)

### Variants
- <a href="#opt_options_u.some" name="opt_options_u.some"></a> `some`

- <a href="#opt_options_u.none" name="opt_options_u.none"></a> `none`

## <a href="#opt_options" name="opt_options"></a> `opt_options`: Union

### Union variants
- <a href="#opt_options.some" name="opt_options.some"></a> `some`: [`options`](#options)

- <a href="#opt_options.none" name="opt_options.none"></a> `none`

## <a href="#opt_symmetric_key_u" name="opt_symmetric_key_u"></a> `opt_symmetric_key_u`: Enum(`u8`)

### Variants
- <a href="#opt_symmetric_key_u.some" name="opt_symmetric_key_u.some"></a> `some`

- <a href="#opt_symmetric_key_u.none" name="opt_symmetric_key_u.none"></a> `none`

## <a href="#opt_symmetric_key" name="opt_symmetric_key"></a> `opt_symmetric_key`: Union

### Union variants
- <a href="#opt_symmetric_key.some" name="opt_symmetric_key.some"></a> `some`: [`symmetric_key`](#symmetric_key)

- <a href="#opt_symmetric_key.none" name="opt_symmetric_key.none"></a> `none`

# Modules
## <a href="#wasi_ephemeral_crypto" name="wasi_ephemeral_crypto"></a> wasi_ephemeral_crypto
### Imports
#### Memory
### Functions

---

#### <a href="#options_open" name="options_open"></a> `options_open(options_type: options_type) -> (crypto_errno, options)`
Create a new object to set options.

##### Params
- <a href="#options_open.options_type" name="options_open.options_type"></a> `options_type`: [`options_type`](#options_type)

##### Results
- <a href="#options_open.error" name="options_open.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#options_open.handle" name="options_open.handle"></a> `handle`: [`options`](#options)


---

#### <a href="#options_close" name="options_close"></a> `options_close(handle: options) -> crypto_errno`
Destroy an options object.

##### Params
- <a href="#options_close.handle" name="options_close.handle"></a> `handle`: [`options`](#options)

##### Results
- <a href="#options_close.error" name="options_close.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#options_set" name="options_set"></a> `options_set(handle: options, name: string, value: ConstPointer<u8>, value_len: size) -> crypto_errno`
Set or update an option.

##### Params
- <a href="#options_set.handle" name="options_set.handle"></a> `handle`: [`options`](#options)

- <a href="#options_set.name" name="options_set.name"></a> `name`: `string`

- <a href="#options_set.value" name="options_set.value"></a> `value`: `ConstPointer<u8>`

- <a href="#options_set.value_len" name="options_set.value_len"></a> `value_len`: [`size`](#size)

##### Results
- <a href="#options_set.error" name="options_set.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#options_set_u64" name="options_set_u64"></a> `options_set_u64(handle: options, name: string, value: u64) -> crypto_errno`
Set or update an integer option.

##### Params
- <a href="#options_set_u64.handle" name="options_set_u64.handle"></a> `handle`: [`options`](#options)

- <a href="#options_set_u64.name" name="options_set_u64.name"></a> `name`: `string`

- <a href="#options_set_u64.value" name="options_set_u64.value"></a> `value`: `u64`

##### Results
- <a href="#options_set_u64.error" name="options_set_u64.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#array_output_len" name="array_output_len"></a> `array_output_len(array_output: array_output) -> (crypto_errno, size)`
Return the length of an array_output object.

##### Params
- <a href="#array_output_len.array_output" name="array_output_len.array_output"></a> `array_output`: [`array_output`](#array_output)

##### Results
- <a href="#array_output_len.error" name="array_output_len.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#array_output_len.len" name="array_output_len.len"></a> `len`: [`size`](#size)


---

#### <a href="#array_output_pull" name="array_output_pull"></a> `array_output_pull(array_output: array_output, buf: Pointer<u8>, buf_len: size) -> crypto_errno`
Copy an array_output into an application-allocated buffer.
The array_output handle becomes invalid after this operation.

##### Params
- <a href="#array_output_pull.array_output" name="array_output_pull.array_output"></a> `array_output`: [`array_output`](#array_output)

- <a href="#array_output_pull.buf" name="array_output_pull.buf"></a> `buf`: `Pointer<u8>`

- <a href="#array_output_pull.buf_len" name="array_output_pull.buf_len"></a> `buf_len`: [`size`](#size)

##### Results
- <a href="#array_output_pull.error" name="array_output_pull.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#signature_keypair_manager_open" name="signature_keypair_manager_open"></a> `signature_keypair_manager_open(options: opt_options) -> (crypto_errno, signature_keypair_manager)`
[OPTIONAL IMPORT].
Create a context to the key manager.

##### Params
- <a href="#signature_keypair_manager_open.options" name="signature_keypair_manager_open.options"></a> `options`: [`opt_options`](#opt_options)

##### Results
- <a href="#signature_keypair_manager_open.error" name="signature_keypair_manager_open.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#signature_keypair_manager_open.handle" name="signature_keypair_manager_open.handle"></a> `handle`: [`signature_keypair_manager`](#signature_keypair_manager)


---

#### <a href="#signature_keypair_manager_close" name="signature_keypair_manager_close"></a> `signature_keypair_manager_close(kp_manager: signature_keypair_manager) -> crypto_errno`
[OPTIONAL IMPORT].
Destroy a key manager context.

##### Params
- <a href="#signature_keypair_manager_close.kp_manager" name="signature_keypair_manager_close.kp_manager"></a> `kp_manager`: [`signature_keypair_manager`](#signature_keypair_manager)

##### Results
- <a href="#signature_keypair_manager_close.error" name="signature_keypair_manager_close.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#signature_keypair_generate" name="signature_keypair_generate"></a> `signature_keypair_generate(algorithm: string, options: opt_options) -> (crypto_errno, signature_keypair)`
Generate a new key pair.
This function may return `$crypto_errno.unsupported_feature` if key
generation is not supported by the host for the chosen algorithm.

##### Params
- <a href="#signature_keypair_generate.algorithm" name="signature_keypair_generate.algorithm"></a> `algorithm`: `string`

- <a href="#signature_keypair_generate.options" name="signature_keypair_generate.options"></a> `options`: [`opt_options`](#opt_options)

##### Results
- <a href="#signature_keypair_generate.error" name="signature_keypair_generate.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#signature_keypair_generate.handle" name="signature_keypair_generate.handle"></a> `handle`: [`signature_keypair`](#signature_keypair)


---

#### <a href="#signature_keypair_import" name="signature_keypair_import"></a> `signature_keypair_import(algorithm: string, encoded: ConstPointer<u8>, encoded_len: size, encoding: keypair_encoding) -> (crypto_errno, signature_keypair)`
Import a key pair.
This function may return `$crypto_errno.unsupported_algorithm` if the
encoding scheme is not supported, or crypto_errno.invalid_key if the key
cannot be decoded.

##### Params
- <a href="#signature_keypair_import.algorithm" name="signature_keypair_import.algorithm"></a> `algorithm`: `string`

- <a href="#signature_keypair_import.encoded" name="signature_keypair_import.encoded"></a> `encoded`: `ConstPointer<u8>`

- <a href="#signature_keypair_import.encoded_len" name="signature_keypair_import.encoded_len"></a> `encoded_len`: [`size`](#size)

- <a href="#signature_keypair_import.encoding" name="signature_keypair_import.encoding"></a> `encoding`: [`keypair_encoding`](#keypair_encoding)

##### Results
- <a href="#signature_keypair_import.error" name="signature_keypair_import.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#signature_keypair_import.handle" name="signature_keypair_import.handle"></a> `handle`: [`signature_keypair`](#signature_keypair)


---

#### <a href="#signature_keypair_id" name="signature_keypair_id"></a> `signature_keypair_id(kp: signature_keypair, kp_id: Pointer<u8>, kp_id_max_len: size) -> (crypto_errno, size, version)`
[OPTIONAL IMPORT].
Return the key identifier and version, if these are available
or `$crypto_errno.unsupported_feature` if not.

##### Params
- <a href="#signature_keypair_id.kp" name="signature_keypair_id.kp"></a> `kp`: [`signature_keypair`](#signature_keypair)

- <a href="#signature_keypair_id.kp_id" name="signature_keypair_id.kp_id"></a> `kp_id`: `Pointer<u8>`

- <a href="#signature_keypair_id.kp_id_max_len" name="signature_keypair_id.kp_id_max_len"></a> `kp_id_max_len`: [`size`](#size)

##### Results
- <a href="#signature_keypair_id.error" name="signature_keypair_id.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#signature_keypair_id.kp_id_len" name="signature_keypair_id.kp_id_len"></a> `kp_id_len`: [`size`](#size)

- <a href="#signature_keypair_id.version" name="signature_keypair_id.version"></a> `version`: [`version`](#version)


---

#### <a href="#signature_keypair_from_id" name="signature_keypair_from_id"></a> `signature_keypair_from_id(kp_manager: signature_keypair_manager, kp_id: ConstPointer<u8>, kp_id_len: size, kp_version: version) -> (crypto_errno, signature_keypair)`
[OPTIONAL IMPORT].
Create a key pair using an opaque key identifier.
Return `$crypto_errno.unsupported_feature` if this operation is not
supported by the host, and `$crypto_errno.invalid_key` if the identifier
is invalid.
The version can be an actual version number or $version.latest .

##### Params
- <a href="#signature_keypair_from_id.kp_manager" name="signature_keypair_from_id.kp_manager"></a> `kp_manager`: [`signature_keypair_manager`](#signature_keypair_manager)

- <a href="#signature_keypair_from_id.kp_id" name="signature_keypair_from_id.kp_id"></a> `kp_id`: `ConstPointer<u8>`

- <a href="#signature_keypair_from_id.kp_id_len" name="signature_keypair_from_id.kp_id_len"></a> `kp_id_len`: [`size`](#size)

- <a href="#signature_keypair_from_id.kp_version" name="signature_keypair_from_id.kp_version"></a> `kp_version`: [`version`](#version)

##### Results
- <a href="#signature_keypair_from_id.error" name="signature_keypair_from_id.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#signature_keypair_from_id.handle" name="signature_keypair_from_id.handle"></a> `handle`: [`signature_keypair`](#signature_keypair)


---

#### <a href="#signature_keypair_invalidate" name="signature_keypair_invalidate"></a> `signature_keypair_invalidate(kp_manager: signature_keypair_manager, kp_id: ConstPointer<u8>, kp_id_len: size, kp_version: version) -> crypto_errno`
[OPTIONAL IMPORT].
Invalidate a key pair given a key identifier and a version.
Return `$crypto_errno.unsupported_feature` if this operation is not
supported by the host, and `$crypto_errno.invalid_key` if the identifier
is invalid.
The version can be a actual version number, as well as
`$version.latest` or `$version.all` .

##### Params
- <a href="#signature_keypair_invalidate.kp_manager" name="signature_keypair_invalidate.kp_manager"></a> `kp_manager`: [`signature_keypair_manager`](#signature_keypair_manager)

- <a href="#signature_keypair_invalidate.kp_id" name="signature_keypair_invalidate.kp_id"></a> `kp_id`: `ConstPointer<u8>`

- <a href="#signature_keypair_invalidate.kp_id_len" name="signature_keypair_invalidate.kp_id_len"></a> `kp_id_len`: [`size`](#size)

- <a href="#signature_keypair_invalidate.kp_version" name="signature_keypair_invalidate.kp_version"></a> `kp_version`: [`version`](#version)

##### Results
- <a href="#signature_keypair_invalidate.error" name="signature_keypair_invalidate.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#signature_keypair_export" name="signature_keypair_export"></a> `signature_keypair_export(kp: signature_keypair, encoding: keypair_encoding) -> (crypto_errno, array_output)`
[OPTIONAL IMPORT].
Export the key pair as the given encoding format.
May return `$crypto_errno.prohibited_operation` if this operation is
not available or `$crypto_errno.unsupported_encoding` if the encoding
is not supported.

##### Params
- <a href="#signature_keypair_export.kp" name="signature_keypair_export.kp"></a> `kp`: [`signature_keypair`](#signature_keypair)

- <a href="#signature_keypair_export.encoding" name="signature_keypair_export.encoding"></a> `encoding`: [`keypair_encoding`](#keypair_encoding)

##### Results
- <a href="#signature_keypair_export.error" name="signature_keypair_export.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#signature_keypair_export.encoded" name="signature_keypair_export.encoded"></a> `encoded`: [`array_output`](#array_output)


---

#### <a href="#signature_keypair_publickey" name="signature_keypair_publickey"></a> `signature_keypair_publickey(kp: signature_keypair) -> (crypto_errno, signature_publickey)`
Create a public key object from the key pair.

##### Params
- <a href="#signature_keypair_publickey.kp" name="signature_keypair_publickey.kp"></a> `kp`: [`signature_keypair`](#signature_keypair)

##### Results
- <a href="#signature_keypair_publickey.error" name="signature_keypair_publickey.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#signature_keypair_publickey.pk" name="signature_keypair_publickey.pk"></a> `pk`: [`signature_publickey`](#signature_publickey)


---

#### <a href="#signature_keypair_close" name="signature_keypair_close"></a> `signature_keypair_close(kp: signature_keypair) -> crypto_errno`
Destroys a key pair and wipe memory accordingly.

##### Params
- <a href="#signature_keypair_close.kp" name="signature_keypair_close.kp"></a> `kp`: [`signature_keypair`](#signature_keypair)

##### Results
- <a href="#signature_keypair_close.error" name="signature_keypair_close.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#signature_publickey_import" name="signature_publickey_import"></a> `signature_publickey_import(algorithm: string, encoded: ConstPointer<u8>, encoded_len: size, encoding: publickey_encoding) -> (crypto_errno, signature_publickey)`
Import a public key encoded.
Return `$crypto_errno.unsupported_encoding` if exporting
to the given format is not implemented or if the format is
incompatible with the key type.

##### Params
- <a href="#signature_publickey_import.algorithm" name="signature_publickey_import.algorithm"></a> `algorithm`: `string`

- <a href="#signature_publickey_import.encoded" name="signature_publickey_import.encoded"></a> `encoded`: `ConstPointer<u8>`

- <a href="#signature_publickey_import.encoded_len" name="signature_publickey_import.encoded_len"></a> `encoded_len`: [`size`](#size)

- <a href="#signature_publickey_import.encoding" name="signature_publickey_import.encoding"></a> `encoding`: [`publickey_encoding`](#publickey_encoding)

##### Results
- <a href="#signature_publickey_import.error" name="signature_publickey_import.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#signature_publickey_import.pk" name="signature_publickey_import.pk"></a> `pk`: [`signature_publickey`](#signature_publickey)


---

#### <a href="#signature_publickey_verify" name="signature_publickey_verify"></a> `signature_publickey_verify(pk: signature_publickey) -> crypto_errno`
Check that a public key is valid and in canonical form.
Return `$crypto_errno.invalid_key` if verification fails.

##### Params
- <a href="#signature_publickey_verify.pk" name="signature_publickey_verify.pk"></a> `pk`: [`signature_publickey`](#signature_publickey)

##### Results
- <a href="#signature_publickey_verify.error" name="signature_publickey_verify.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#signature_publickey_close" name="signature_publickey_close"></a> `signature_publickey_close(pk: signature_publickey) -> crypto_errno`
Destroys a public key.

##### Params
- <a href="#signature_publickey_close.pk" name="signature_publickey_close.pk"></a> `pk`: [`signature_publickey`](#signature_publickey)

##### Results
- <a href="#signature_publickey_close.error" name="signature_publickey_close.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#signature_export" name="signature_export"></a> `signature_export(signature: signature, encoding: signature_encoding) -> (crypto_errno, array_output)`
Export a signature in the given format.

##### Params
- <a href="#signature_export.signature" name="signature_export.signature"></a> `signature`: [`signature`](#signature)

- <a href="#signature_export.encoding" name="signature_export.encoding"></a> `encoding`: [`signature_encoding`](#signature_encoding)

##### Results
- <a href="#signature_export.error" name="signature_export.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#signature_export.encoded" name="signature_export.encoded"></a> `encoded`: [`array_output`](#array_output)


---

#### <a href="#signature_import" name="signature_import"></a> `signature_import(algorithm: string, encoding: signature_encoding, encoded: ConstPointer<u8>, encoded_len: size) -> (crypto_errno, signature)`
Create a signature object by importing a signature encoded
in a given format.
Return `$crypto_errno.invalid_signature` if the signature is incompatible
with the current content.

##### Params
- <a href="#signature_import.algorithm" name="signature_import.algorithm"></a> `algorithm`: `string`

- <a href="#signature_import.encoding" name="signature_import.encoding"></a> `encoding`: [`signature_encoding`](#signature_encoding)

- <a href="#signature_import.encoded" name="signature_import.encoded"></a> `encoded`: `ConstPointer<u8>`

- <a href="#signature_import.encoded_len" name="signature_import.encoded_len"></a> `encoded_len`: [`size`](#size)

##### Results
- <a href="#signature_import.error" name="signature_import.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#signature_import.signature" name="signature_import.signature"></a> `signature`: [`signature`](#signature)


---

#### <a href="#signature_state_open" name="signature_state_open"></a> `signature_state_open(kp: signature_keypair) -> (crypto_errno, signature_state)`
Create a new state to collect data to compute a signature on.

##### Params
- <a href="#signature_state_open.kp" name="signature_state_open.kp"></a> `kp`: [`signature_keypair`](#signature_keypair)

##### Results
- <a href="#signature_state_open.error" name="signature_state_open.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#signature_state_open.state" name="signature_state_open.state"></a> `state`: [`signature_state`](#signature_state)


---

#### <a href="#signature_state_update" name="signature_state_update"></a> `signature_state_update(state: signature_state, input: ConstPointer<u8>, input_len: size) -> crypto_errno`
Inject data into the state.

##### Params
- <a href="#signature_state_update.state" name="signature_state_update.state"></a> `state`: [`signature_state`](#signature_state)

- <a href="#signature_state_update.input" name="signature_state_update.input"></a> `input`: `ConstPointer<u8>`

- <a href="#signature_state_update.input_len" name="signature_state_update.input_len"></a> `input_len`: [`size`](#size)

##### Results
- <a href="#signature_state_update.error" name="signature_state_update.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#signature_state_sign" name="signature_state_sign"></a> `signature_state_sign(state: signature_state) -> (crypto_errno, array_output)`
Compute a signature for all the data collected until tht point.
The function can be called multiple times for incremental signing.
May return `$crypto_errno.overflow` is too much data has been processed
for the chosen algorithm or if system resources have been
exceeded.

##### Params
- <a href="#signature_state_sign.state" name="signature_state_sign.state"></a> `state`: [`signature_state`](#signature_state)

##### Results
- <a href="#signature_state_sign.error" name="signature_state_sign.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#signature_state_sign.signature" name="signature_state_sign.signature"></a> `signature`: [`array_output`](#array_output)


---

#### <a href="#signature_state_close" name="signature_state_close"></a> `signature_state_close(state: signature_state) -> crypto_errno`
Destroy a signature state.

##### Params
- <a href="#signature_state_close.state" name="signature_state_close.state"></a> `state`: [`signature_state`](#signature_state)

##### Results
- <a href="#signature_state_close.error" name="signature_state_close.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#signature_verification_state_update" name="signature_verification_state_update"></a> `signature_verification_state_update(state: signature_verification_state, input: ConstPointer<u8>, input_len: size) -> crypto_errno`
Create a new state to collect data to verify a signature on.

##### Params
- <a href="#signature_verification_state_update.state" name="signature_verification_state_update.state"></a> `state`: [`signature_verification_state`](#signature_verification_state)

- <a href="#signature_verification_state_update.input" name="signature_verification_state_update.input"></a> `input`: `ConstPointer<u8>`

- <a href="#signature_verification_state_update.input_len" name="signature_verification_state_update.input_len"></a> `input_len`: [`size`](#size)

##### Results
- <a href="#signature_verification_state_update.error" name="signature_verification_state_update.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#signature_verification_state_verify" name="signature_verification_state_verify"></a> `signature_verification_state_verify(state: signature_verification_state, signature: signature) -> crypto_errno`
Verify that the given signature is valid for the data collected
up to this point.

##### Params
- <a href="#signature_verification_state_verify.state" name="signature_verification_state_verify.state"></a> `state`: [`signature_verification_state`](#signature_verification_state)

- <a href="#signature_verification_state_verify.signature" name="signature_verification_state_verify.signature"></a> `signature`: [`signature`](#signature)

##### Results
- <a href="#signature_verification_state_verify.error" name="signature_verification_state_verify.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#signature_verification_state_close" name="signature_verification_state_close"></a> `signature_verification_state_close(state: signature_verification_state) -> crypto_errno`
Destroy a signature verification state.

##### Params
- <a href="#signature_verification_state_close.state" name="signature_verification_state_close.state"></a> `state`: [`signature_verification_state`](#signature_verification_state)

##### Results
- <a href="#signature_verification_state_close.error" name="signature_verification_state_close.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#signature_close" name="signature_close"></a> `signature_close(signature: signature) -> crypto_errno`
Destroy a signature.

##### Params
- <a href="#signature_close.signature" name="signature_close.signature"></a> `signature`: [`signature`](#signature)

##### Results
- <a href="#signature_close.error" name="signature_close.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#symmetric_tag_len" name="symmetric_tag_len"></a> `symmetric_tag_len(symmetric_tag: symmetric_tag) -> (crypto_errno, size)`
Return the length of an authentication tag.

##### Params
- <a href="#symmetric_tag_len.symmetric_tag" name="symmetric_tag_len.symmetric_tag"></a> `symmetric_tag`: [`symmetric_tag`](#symmetric_tag)

##### Results
- <a href="#symmetric_tag_len.error" name="symmetric_tag_len.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#symmetric_tag_len.len" name="symmetric_tag_len.len"></a> `len`: [`size`](#size)


---

#### <a href="#symmetric_tag_pull" name="symmetric_tag_pull"></a> `symmetric_tag_pull(symmetric_tag: symmetric_tag, buf: Pointer<u8>, buf_len: size) -> crypto_errno`
Copy an authentication tag into an application-allocated buffer.
The handle becomes invalid after this operation.

##### Params
- <a href="#symmetric_tag_pull.symmetric_tag" name="symmetric_tag_pull.symmetric_tag"></a> `symmetric_tag`: [`symmetric_tag`](#symmetric_tag)

- <a href="#symmetric_tag_pull.buf" name="symmetric_tag_pull.buf"></a> `buf`: `Pointer<u8>`

- <a href="#symmetric_tag_pull.buf_len" name="symmetric_tag_pull.buf_len"></a> `buf_len`: [`size`](#size)

##### Results
- <a href="#symmetric_tag_pull.error" name="symmetric_tag_pull.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#symmetric_tag_verify" name="symmetric_tag_verify"></a> `symmetric_tag_verify(symmetric_tag: symmetric_tag, expected_raw_tag_ptr: ConstPointer<u8>, expected_raw_tag_len: size) -> crypto_errno`
Verity that a computed tag matches an expected tag.
The reference tag is an object, but the expected tag
is a raw byte string.

##### Params
- <a href="#symmetric_tag_verify.symmetric_tag" name="symmetric_tag_verify.symmetric_tag"></a> `symmetric_tag`: [`symmetric_tag`](#symmetric_tag)

- <a href="#symmetric_tag_verify.expected_raw_tag_ptr" name="symmetric_tag_verify.expected_raw_tag_ptr"></a> `expected_raw_tag_ptr`: `ConstPointer<u8>`

- <a href="#symmetric_tag_verify.expected_raw_tag_len" name="symmetric_tag_verify.expected_raw_tag_len"></a> `expected_raw_tag_len`: [`size`](#size)

##### Results
- <a href="#symmetric_tag_verify.error" name="symmetric_tag_verify.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#symmetric_tag_close" name="symmetric_tag_close"></a> `symmetric_tag_close(symmetric_tag: symmetric_tag) -> crypto_errno`
Destroy an authentication tag.

##### Params
- <a href="#symmetric_tag_close.symmetric_tag" name="symmetric_tag_close.symmetric_tag"></a> `symmetric_tag`: [`symmetric_tag`](#symmetric_tag)

##### Results
- <a href="#symmetric_tag_close.error" name="symmetric_tag_close.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#symmetric_key_generate" name="symmetric_key_generate"></a> `symmetric_key_generate(algorithm: string, options: opt_options) -> (crypto_errno, symmetric_key)`
Generate a new symmetric key.
This function may return `$crypto_errno.unsupported_feature` if key
generation is not supported by the host for the chosen algorithm.

##### Params
- <a href="#symmetric_key_generate.algorithm" name="symmetric_key_generate.algorithm"></a> `algorithm`: `string`

- <a href="#symmetric_key_generate.options" name="symmetric_key_generate.options"></a> `options`: [`opt_options`](#opt_options)

##### Results
- <a href="#symmetric_key_generate.error" name="symmetric_key_generate.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#symmetric_key_generate.handle" name="symmetric_key_generate.handle"></a> `handle`: [`symmetric_key`](#symmetric_key)


---

#### <a href="#symmetric_key_import" name="symmetric_key_import"></a> `symmetric_key_import(algorithm: string, encoded: ConstPointer<u8>, encoded_len: size) -> (crypto_errno, symmetric_key)`
Import a symmetric key.

##### Params
- <a href="#symmetric_key_import.algorithm" name="symmetric_key_import.algorithm"></a> `algorithm`: `string`

- <a href="#symmetric_key_import.encoded" name="symmetric_key_import.encoded"></a> `encoded`: `ConstPointer<u8>`

- <a href="#symmetric_key_import.encoded_len" name="symmetric_key_import.encoded_len"></a> `encoded_len`: [`size`](#size)

##### Results
- <a href="#symmetric_key_import.error" name="symmetric_key_import.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#symmetric_key_import.handle" name="symmetric_key_import.handle"></a> `handle`: [`symmetric_key`](#symmetric_key)


---

#### <a href="#symmetric_key_close" name="symmetric_key_close"></a> `symmetric_key_close(symmetric_key: symmetric_key) -> crypto_errno`
Destroys a symmetric key.

##### Params
- <a href="#symmetric_key_close.symmetric_key" name="symmetric_key_close.symmetric_key"></a> `symmetric_key`: [`symmetric_key`](#symmetric_key)

##### Results
- <a href="#symmetric_key_close.error" name="symmetric_key_close.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#symmetric_key_manager_open" name="symmetric_key_manager_open"></a> `symmetric_key_manager_open(options: opt_options) -> (crypto_errno, symmetric_key_manager)`
[OPTIONAL IMPORT].
Create a context to access a key manager.

##### Params
- <a href="#symmetric_key_manager_open.options" name="symmetric_key_manager_open.options"></a> `options`: [`opt_options`](#opt_options)

##### Results
- <a href="#symmetric_key_manager_open.error" name="symmetric_key_manager_open.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#symmetric_key_manager_open.handle" name="symmetric_key_manager_open.handle"></a> `handle`: [`symmetric_key_manager`](#symmetric_key_manager)


---

#### <a href="#symmetric_key_manager_close" name="symmetric_key_manager_close"></a> `symmetric_key_manager_close(symmetric_key_manager: symmetric_key_manager) -> crypto_errno`
[OPTIONAL IMPORT].
Destroy a key manager.

##### Params
- <a href="#symmetric_key_manager_close.symmetric_key_manager" name="symmetric_key_manager_close.symmetric_key_manager"></a> `symmetric_key_manager`: [`symmetric_key_manager`](#symmetric_key_manager)

##### Results
- <a href="#symmetric_key_manager_close.error" name="symmetric_key_manager_close.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#symmetric_key_id" name="symmetric_key_id"></a> `symmetric_key_id(symmetric_key: symmetric_key, symmetric_key_id: Pointer<u8>, symmetric_key_id_max_len: size) -> (crypto_errno, size, version)`
[OPTIONAL IMPORT].
Return the symmetric key identifier and version, if these are available
or `$crypto_errno.unsupported_feature` if not.

##### Params
- <a href="#symmetric_key_id.symmetric_key" name="symmetric_key_id.symmetric_key"></a> `symmetric_key`: [`symmetric_key`](#symmetric_key)

- <a href="#symmetric_key_id.symmetric_key_id" name="symmetric_key_id.symmetric_key_id"></a> `symmetric_key_id`: `Pointer<u8>`

- <a href="#symmetric_key_id.symmetric_key_id_max_len" name="symmetric_key_id.symmetric_key_id_max_len"></a> `symmetric_key_id_max_len`: [`size`](#size)

##### Results
- <a href="#symmetric_key_id.error" name="symmetric_key_id.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#symmetric_key_id.symmetric_key_id_len" name="symmetric_key_id.symmetric_key_id_len"></a> `symmetric_key_id_len`: [`size`](#size)

- <a href="#symmetric_key_id.version" name="symmetric_key_id.version"></a> `version`: [`version`](#version)


---

#### <a href="#symmetric_key_from_id" name="symmetric_key_from_id"></a> `symmetric_key_from_id(symmetric_key_manager: symmetric_key_manager, symmetric_key_id: ConstPointer<u8>, symmetric_key_id_len: size, symmetric_key_version: version) -> (crypto_errno, symmetric_key)`
[OPTIONAL IMPORT].
Create a symmetric key using an opaque key identifier.
Return `$crypto_errno.unsupported_feature` if this operation is not
supported by the host, and crypto_errno.invalid_key if the identifier
is invalid.
The version can be an actual version number or `$version.latest`.

##### Params
- <a href="#symmetric_key_from_id.symmetric_key_manager" name="symmetric_key_from_id.symmetric_key_manager"></a> `symmetric_key_manager`: [`symmetric_key_manager`](#symmetric_key_manager)

- <a href="#symmetric_key_from_id.symmetric_key_id" name="symmetric_key_from_id.symmetric_key_id"></a> `symmetric_key_id`: `ConstPointer<u8>`

- <a href="#symmetric_key_from_id.symmetric_key_id_len" name="symmetric_key_from_id.symmetric_key_id_len"></a> `symmetric_key_id_len`: [`size`](#size)

- <a href="#symmetric_key_from_id.symmetric_key_version" name="symmetric_key_from_id.symmetric_key_version"></a> `symmetric_key_version`: [`version`](#version)

##### Results
- <a href="#symmetric_key_from_id.error" name="symmetric_key_from_id.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#symmetric_key_from_id.handle" name="symmetric_key_from_id.handle"></a> `handle`: [`symmetric_key`](#symmetric_key)


---

#### <a href="#symmetric_key_invalidate" name="symmetric_key_invalidate"></a> `symmetric_key_invalidate(symmetric_key_manager: symmetric_key_manager, symmetric_key_id: ConstPointer<u8>, symmetric_key_id_len: size, symmetric_key_version: version) -> crypto_errno`
[OPTIONAL IMPORT].
Invalidate a symmetric key given a key identifier and a version.
Return `$crypto_errno.unsupported_feature` if this operation is not
supported by the host, and `$crypto_errno.invalid_key` if the identifier
is invalid.
The version can be a actual version number, as well as
`$version.latest` or `$version.all`.

##### Params
- <a href="#symmetric_key_invalidate.symmetric_key_manager" name="symmetric_key_invalidate.symmetric_key_manager"></a> `symmetric_key_manager`: [`symmetric_key_manager`](#symmetric_key_manager)

- <a href="#symmetric_key_invalidate.symmetric_key_id" name="symmetric_key_invalidate.symmetric_key_id"></a> `symmetric_key_id`: `ConstPointer<u8>`

- <a href="#symmetric_key_invalidate.symmetric_key_id_len" name="symmetric_key_invalidate.symmetric_key_id_len"></a> `symmetric_key_id_len`: [`size`](#size)

- <a href="#symmetric_key_invalidate.symmetric_key_version" name="symmetric_key_invalidate.symmetric_key_version"></a> `symmetric_key_version`: [`version`](#version)

##### Results
- <a href="#symmetric_key_invalidate.error" name="symmetric_key_invalidate.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#symmetric_state_options_get" name="symmetric_state_options_get"></a> `symmetric_state_options_get(handle: symmetric_state, name: string, value: Pointer<u8>, value_max_len: size) -> (crypto_errno, size)`
Retrieve a parameter from the current state.
In particular, `symmetric_state_options_get("nonce")` can be used
to get a nonce that as automatically generated.

##### Params
- <a href="#symmetric_state_options_get.handle" name="symmetric_state_options_get.handle"></a> `handle`: [`symmetric_state`](#symmetric_state)

- <a href="#symmetric_state_options_get.name" name="symmetric_state_options_get.name"></a> `name`: `string`

- <a href="#symmetric_state_options_get.value" name="symmetric_state_options_get.value"></a> `value`: `Pointer<u8>`

- <a href="#symmetric_state_options_get.value_max_len" name="symmetric_state_options_get.value_max_len"></a> `value_max_len`: [`size`](#size)

##### Results
- <a href="#symmetric_state_options_get.error" name="symmetric_state_options_get.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#symmetric_state_options_get.value_len" name="symmetric_state_options_get.value_len"></a> `value_len`: [`size`](#size)


---

#### <a href="#symmetric_state_options_get_u64" name="symmetric_state_options_get_u64"></a> `symmetric_state_options_get_u64(handle: symmetric_state, name: string) -> (crypto_errno, u64)`
Retrieve an integer parameter from the current state.
In particular, `symmetric_state_options_get("nonce")` can be used
to get a nonce that as automatically generated.

##### Params
- <a href="#symmetric_state_options_get_u64.handle" name="symmetric_state_options_get_u64.handle"></a> `handle`: [`symmetric_state`](#symmetric_state)

- <a href="#symmetric_state_options_get_u64.name" name="symmetric_state_options_get_u64.name"></a> `name`: `string`

##### Results
- <a href="#symmetric_state_options_get_u64.error" name="symmetric_state_options_get_u64.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#symmetric_state_options_get_u64.value" name="symmetric_state_options_get_u64.value"></a> `value`: `u64`


---

#### <a href="#symmetric_state_close" name="symmetric_state_close"></a> `symmetric_state_close(handle: symmetric_state) -> crypto_errno`
Destroy a symmetric state.

##### Params
- <a href="#symmetric_state_close.handle" name="symmetric_state_close.handle"></a> `handle`: [`symmetric_state`](#symmetric_state)

##### Results
- <a href="#symmetric_state_close.error" name="symmetric_state_close.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#symmetric_state_absorb" name="symmetric_state_absorb"></a> `symmetric_state_absorb(handle: symmetric_state, data: ConstPointer<u8>, data_len: size) -> crypto_errno`
Absorb data into the state.
This can be data to be hashed for a hash function,
or additional data for an AEAD.

##### Params
- <a href="#symmetric_state_absorb.handle" name="symmetric_state_absorb.handle"></a> `handle`: [`symmetric_state`](#symmetric_state)

- <a href="#symmetric_state_absorb.data" name="symmetric_state_absorb.data"></a> `data`: `ConstPointer<u8>`

- <a href="#symmetric_state_absorb.data_len" name="symmetric_state_absorb.data_len"></a> `data_len`: [`size`](#size)

##### Results
- <a href="#symmetric_state_absorb.error" name="symmetric_state_absorb.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#symmetric_state_squeeze" name="symmetric_state_squeeze"></a> `symmetric_state_squeeze(handle: symmetric_state, out: Pointer<u8>, out_len: size) -> crypto_errno`
Squeeze bytes from the state.
This can be the output of a hash function (with limits on
the output length), a XOF, a stream cipher or a KDF.

##### Params
- <a href="#symmetric_state_squeeze.handle" name="symmetric_state_squeeze.handle"></a> `handle`: [`symmetric_state`](#symmetric_state)

- <a href="#symmetric_state_squeeze.out" name="symmetric_state_squeeze.out"></a> `out`: `Pointer<u8>`

- <a href="#symmetric_state_squeeze.out_len" name="symmetric_state_squeeze.out_len"></a> `out_len`: [`size`](#size)

##### Results
- <a href="#symmetric_state_squeeze.error" name="symmetric_state_squeeze.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#symmetric_state_squeeze_tag" name="symmetric_state_squeeze_tag"></a> `symmetric_state_squeeze_tag(handle: symmetric_state) -> (crypto_errno, symmetric_tag)`
Compute and return a tag for all the data injected into
the state so far. This can be a MAC or a self-contained
verification tag for a password hashing function.

##### Params
- <a href="#symmetric_state_squeeze_tag.handle" name="symmetric_state_squeeze_tag.handle"></a> `handle`: [`symmetric_state`](#symmetric_state)

##### Results
- <a href="#symmetric_state_squeeze_tag.error" name="symmetric_state_squeeze_tag.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#symmetric_state_squeeze_tag.symmetric_tag" name="symmetric_state_squeeze_tag.symmetric_tag"></a> `symmetric_tag`: [`symmetric_tag`](#symmetric_tag)


---

#### <a href="#symmetric_state_squeeze_key" name="symmetric_state_squeeze_key"></a> `symmetric_state_squeeze_key(handle: symmetric_state, raw: Pointer<u8>, raw_len: size) -> crypto_errno`
Compute a new key, that can be used to resume a session
without storing a nonce.

##### Params
- <a href="#symmetric_state_squeeze_key.handle" name="symmetric_state_squeeze_key.handle"></a> `handle`: [`symmetric_state`](#symmetric_state)

- <a href="#symmetric_state_squeeze_key.raw" name="symmetric_state_squeeze_key.raw"></a> `raw`: `Pointer<u8>`

- <a href="#symmetric_state_squeeze_key.raw_len" name="symmetric_state_squeeze_key.raw_len"></a> `raw_len`: [`size`](#size)

##### Results
- <a href="#symmetric_state_squeeze_key.error" name="symmetric_state_squeeze_key.error"></a> `error`: [`crypto_errno`](#crypto_errno)


---

#### <a href="#symmetric_state_max_tag_len" name="symmetric_state_max_tag_len"></a> `symmetric_state_max_tag_len(handle: symmetric_state) -> (crypto_errno, size)`
Return the maximum length of a for the current algorithm.

##### Params
- <a href="#symmetric_state_max_tag_len.handle" name="symmetric_state_max_tag_len.handle"></a> `handle`: [`symmetric_state`](#symmetric_state)

##### Results
- <a href="#symmetric_state_max_tag_len.error" name="symmetric_state_max_tag_len.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#symmetric_state_max_tag_len.len" name="symmetric_state_max_tag_len.len"></a> `len`: [`size`](#size)


---

#### <a href="#symmetric_state_encrypt" name="symmetric_state_encrypt"></a> `symmetric_state_encrypt(handle: symmetric_state, out: Pointer<u8>, out_len: size, data: ConstPointer<u8>, data_len: size) -> (crypto_errno, size)`
Encrypt data.
With authenticated encryption, the output will include
the authentication tag. Therefore, `$out_len` must be
at least `symmetric_state_max_tag_len()` byte larger than
the input.
If `out` and `data` are the same address, encryption may
happen in-place.

##### Params
- <a href="#symmetric_state_encrypt.handle" name="symmetric_state_encrypt.handle"></a> `handle`: [`symmetric_state`](#symmetric_state)

- <a href="#symmetric_state_encrypt.out" name="symmetric_state_encrypt.out"></a> `out`: `Pointer<u8>`

- <a href="#symmetric_state_encrypt.out_len" name="symmetric_state_encrypt.out_len"></a> `out_len`: [`size`](#size)

- <a href="#symmetric_state_encrypt.data" name="symmetric_state_encrypt.data"></a> `data`: `ConstPointer<u8>`

- <a href="#symmetric_state_encrypt.data_len" name="symmetric_state_encrypt.data_len"></a> `data_len`: [`size`](#size)

##### Results
- <a href="#symmetric_state_encrypt.error" name="symmetric_state_encrypt.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#symmetric_state_encrypt.actual_out_len" name="symmetric_state_encrypt.actual_out_len"></a> `actual_out_len`: [`size`](#size)


---

#### <a href="#symmetric_state_encrypt_detached" name="symmetric_state_encrypt_detached"></a> `symmetric_state_encrypt_detached(handle: symmetric_state, out: Pointer<u8>, out_len: size, data: ConstPointer<u8>, data_len: size) -> (crypto_errno, symmetric_tag)`
Encrypt data, with a detached tag.
If `out` and `data` are the same address, encryption may
happen in-place.

##### Params
- <a href="#symmetric_state_encrypt_detached.handle" name="symmetric_state_encrypt_detached.handle"></a> `handle`: [`symmetric_state`](#symmetric_state)

- <a href="#symmetric_state_encrypt_detached.out" name="symmetric_state_encrypt_detached.out"></a> `out`: `Pointer<u8>`

- <a href="#symmetric_state_encrypt_detached.out_len" name="symmetric_state_encrypt_detached.out_len"></a> `out_len`: [`size`](#size)

- <a href="#symmetric_state_encrypt_detached.data" name="symmetric_state_encrypt_detached.data"></a> `data`: `ConstPointer<u8>`

- <a href="#symmetric_state_encrypt_detached.data_len" name="symmetric_state_encrypt_detached.data_len"></a> `data_len`: [`size`](#size)

##### Results
- <a href="#symmetric_state_encrypt_detached.error" name="symmetric_state_encrypt_detached.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#symmetric_state_encrypt_detached.symmetric_tag" name="symmetric_state_encrypt_detached.symmetric_tag"></a> `symmetric_tag`: [`symmetric_tag`](#symmetric_tag)


---

#### <a href="#symmetric_state_decrypt" name="symmetric_state_decrypt"></a> `symmetric_state_decrypt(handle: symmetric_state, out: Pointer<u8>, out_len: size, data: ConstPointer<u8>, data_len: size) -> (crypto_errno, size)`
Decrypt data with an attached tag.
If `out` and `data` are the same address, decryption may
happen in-place.

##### Params
- <a href="#symmetric_state_decrypt.handle" name="symmetric_state_decrypt.handle"></a> `handle`: [`symmetric_state`](#symmetric_state)

- <a href="#symmetric_state_decrypt.out" name="symmetric_state_decrypt.out"></a> `out`: `Pointer<u8>`

- <a href="#symmetric_state_decrypt.out_len" name="symmetric_state_decrypt.out_len"></a> `out_len`: [`size`](#size)

- <a href="#symmetric_state_decrypt.data" name="symmetric_state_decrypt.data"></a> `data`: `ConstPointer<u8>`

- <a href="#symmetric_state_decrypt.data_len" name="symmetric_state_decrypt.data_len"></a> `data_len`: [`size`](#size)

##### Results
- <a href="#symmetric_state_decrypt.error" name="symmetric_state_decrypt.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#symmetric_state_decrypt.actual_out_len" name="symmetric_state_decrypt.actual_out_len"></a> `actual_out_len`: [`size`](#size)


---

#### <a href="#symmetric_state_decrypt_detached" name="symmetric_state_decrypt_detached"></a> `symmetric_state_decrypt_detached(handle: symmetric_state, out: Pointer<u8>, out_len: size, data: ConstPointer<u8>, data_len: size, raw_tag: ConstPointer<u8>, raw_tag_len: size) -> (crypto_errno, size)`
Decrypt data with a detached tag.
If `out` and `data` are the same address, decryption may
happen in-place.

##### Params
- <a href="#symmetric_state_decrypt_detached.handle" name="symmetric_state_decrypt_detached.handle"></a> `handle`: [`symmetric_state`](#symmetric_state)

- <a href="#symmetric_state_decrypt_detached.out" name="symmetric_state_decrypt_detached.out"></a> `out`: `Pointer<u8>`

- <a href="#symmetric_state_decrypt_detached.out_len" name="symmetric_state_decrypt_detached.out_len"></a> `out_len`: [`size`](#size)

- <a href="#symmetric_state_decrypt_detached.data" name="symmetric_state_decrypt_detached.data"></a> `data`: `ConstPointer<u8>`

- <a href="#symmetric_state_decrypt_detached.data_len" name="symmetric_state_decrypt_detached.data_len"></a> `data_len`: [`size`](#size)

- <a href="#symmetric_state_decrypt_detached.raw_tag" name="symmetric_state_decrypt_detached.raw_tag"></a> `raw_tag`: `ConstPointer<u8>`

- <a href="#symmetric_state_decrypt_detached.raw_tag_len" name="symmetric_state_decrypt_detached.raw_tag_len"></a> `raw_tag_len`: [`size`](#size)

##### Results
- <a href="#symmetric_state_decrypt_detached.error" name="symmetric_state_decrypt_detached.error"></a> `error`: [`crypto_errno`](#crypto_errno)

- <a href="#symmetric_state_decrypt_detached.actual_out_len" name="symmetric_state_decrypt_detached.actual_out_len"></a> `actual_out_len`: [`size`](#size)


---

#### <a href="#symmetric_state_ratchet" name="symmetric_state_ratchet"></a> `symmetric_state_ratchet(handle: symmetric_state) -> crypto_errno`
Make it impossible to recover the previous state.

##### Params
- <a href="#symmetric_state_ratchet.handle" name="symmetric_state_ratchet.handle"></a> `handle`: [`symmetric_state`](#symmetric_state)

##### Results
- <a href="#symmetric_state_ratchet.error" name="symmetric_state_ratchet.error"></a> `error`: [`crypto_errno`](#crypto_errno)


