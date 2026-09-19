# Safety invariants

This document records the current implementation's invariants. It is not an
independent audit or a claim that the complete requested API has been implemented.

## TLS, callbacks, and pyOpenSSL

`ContextBuilder` is exclusively mutable and consumed into a shared, immutable
`Context`. Connections retain their factory and credentials, own their native
SSL allocation, and require exclusive access for operations and metadata reads.
The factory never exposes a mutable certificate or trust-store alias. Store
verification uses a fresh native verification context; exported certificates
are deep copies. These restrictions also apply to Python trust-store proxies
obtained before the factory was frozen.

Stream TLS owns either memory BIOs or a duplicated Unix socket descriptor. The
descriptor outlives `SSL_free`, so closing the caller's socket cannot invalidate
native I/O. DTLS uses a packet queue BIO with preserved datagram boundaries,
bounded packet/queue sizes, native peek semantics, and explicit MTU. A short
application drain buffer leaves the datagram queued. Windows socket transport
and direct DTLS socket transport are not implemented; the memory/packet APIs
do not require operating-system handles.

A pending write owns erased-on-drop plaintext at a stable address. Retries must
supply identical bytes, including when native moving-buffer mode is enabled.
Unsupported asynchronous modes are rejected. Fatal TLS errors poison the
connection and prevent further I/O or shutdown; produced alerts can still be
drained. Error classification happens immediately on the initiating thread,
after clearing its prior native diagnostic queue and errno.

Native callbacks refer only to stable, shared callback storage, never to an
aliased mutable connection or a uniquely owned Rust allocation. Application
hooks receive copied metadata and return typed actions. Hooks execute without
internal bookkeeping locks, with panic containment and per-connection failure
storage. A scoped guard isolates their changes to the thread's error codes and
errno. ALPN selections must be offered and retain their allocation until SSL
destruction; OCSP responses transfer a separate native allocation. A selected
SNI context must use the same transport protocol.

Session installation checks the originating factory, credentials factory,
verification policy, reference DNS identity, SNI, role, and callback identity.
Configuration freezes before installing a session or starting I/O. SNI alone
does not authenticate a hostname: chain verification and the reference DNS
identity are explicit, separate settings. Verification callbacks can explicitly
override rejection; exported verification chains are diagnostic data, not proof
that a peer was authenticated.

The Python X.509 and TLS adapters forbid unsafe Rust. They own their native
objects behind exclusive locks; concurrent and reentrant connection operations
fail instead of aliasing or deadlocking. Blocking TLS calls release the GIL
before taking the connection lock. Python callbacks reattach using an operation
scope, so no persistent native-to-Python reference cycle is created. The original
Python exception is returned to the initiating operation after the C callback
has returned. Python `sendall` separately retains its offset across retries to
avoid repeating plaintext that was already accepted.

The deprecated RNG compatibility method treats bytes as additional input and
never accepts caller-supplied entropy credit. TLS key logging and secret exports
remain explicit operations; consumers must protect the resulting material.

## Ownership and lifetimes

The safe crate does not expose foreign pointers. Native allocations enter a
`NonNull` owning wrapper immediately, before any subsequent fallible operation.
Each wrapper calls exactly its matching native destructor. Initialization failure
therefore drops partially initialized allocations rather than leaking them.

Digest descriptors come exclusively from backend getters returning immutable
process-lifetime descriptors. There is no safe constructor from an arbitrary
pointer. Keys are immutable after construction; every signature, verification,
and exchange operation allocates its own operation context.

## Context state

Hash, HMAC, and CMAC finalization consumes the owning context. Native context
copying is fallible and never hidden in a `Clone` implementation. A failed update
poisons the context. Further updates, copying, and finalization return errors.
An XOF tracks whether squeezing started and refuses further absorption or a
second form of finalization.

Stateful conventional ciphers select the algorithm, direction, key, IV, and
padding at construction. No uninitialized cipher context, arbitrary control,
unchecked update, or operation after finalization is public. AEAD uses a separate
API and cannot be mistaken for an unauthenticated conventional cipher.

## Bounds and native writes

Slice lengths are checked against native integer types before FFI. Digest and
MAC output sizes come from the selected algorithm. Native in/out size parameters
receive the actual destination capacity; returned lengths are checked as well.

Padded conventional cipher output capacity includes a **full block** of slack,
except for stream modes. Unpadded block modes reserve block size minus one. This covers intermediate writes, not just reported output.
The regression test enumerates partial-block splits in padded CBC decryption and
checks canaries around the exact supplied output slice. LibreSSL writes the
withheld block before determining the returned length, including on an empty
update. Using only `input.len() + block_size - 1` failed that test.

One-shot AEAD dispatches through a closed algorithm set and separate protocol
paths. GCM writes exactly the input length; buffered protocols reserve additional
block space. Authentication failure erases pending plaintext; callers receive
plaintext only after successful verification. The explicitly named unverified
streaming GCM interface has a different contract, described below.

## Concurrency and secrets

Explicit Send/Sync implementations are limited to descriptors and contexts whose
shared methods do not mutate native state. Operation methods requiring mutation
take `&mut self` or consume the owner. Sharing a context permits metadata reads
and the explicitly reviewed native copy operations, never concurrent mutation.

Secret Curve25519 exports and shared secrets erase their storage on drop and
implement neither Debug nor Clone. X25519 rejects an all-zero shared secret even
if a backend were to return one as success. Ed25519 signing and verifying keys
are separate types, distinct from X25519 keys.

## Backend assumptions and validation

Bindgen reads the selected installation's headers. No struct layout or native
function signature is hand-transcribed. The small C shim evaluates native macros
under those same headers. The safe wrappers rely on each native implementation
honoring its documented pointer, ownership, and length contracts.

Known-answer vectors, wrong signatures/tags, split updates, boundary checks,
compile-fail lifecycle examples, and the upstream integration suites provide
different kinds of evidence. Passing one category does not substitute for another.

## RSA construction and decryption

Private RSA imports own every component separately until each successful native
set0 transfer. Constructors always require complete positive components, bounded
bit lengths, valid ranges, odd private factors, and n = p * q. Full validation
also invokes the native mathematical key check. Explicit structural validation
omits primality and exponent consistency checks, preserving cryptography's
existing validation-skip option without allowing incomplete native objects.
Public imports preserve cryptography's permissive modulus handling; native
operations can reject mathematically unsuitable public parameters.

Signature and encryption padding have distinct types. Automatic PSS salt
recovery is available only for verification. OAEP label ownership is transferred
only after successful native configuration; empty labels use NULL because
LibreSSL does not retain a zero-length allocation. Private exports and decrypted
plaintext erase their owned initialized bytes when dropped.

The caller-buffer decryption method validates capacity, erases failed native
output, and erases unused output bytes before returning. Cryptography retains
its allocation step for both successful and failed PKCS1 v1.5 decryption.
This is not a claim of constant-time PKCS1 v1.5 decryption or padding-oracle
resistance on backends without native mitigations.

Configuration discovery checks final preprocessor state, including macros that
were defined empty or later undefined. Clippy exceptions for bindgen bitfield
patterns are confined to generated bindings. ABI-dependent integer conversions
remain checked even on forks where the source and destination types coincide.

## Conventional ciphers and GCM

Cipher selection is a closed enum. Arbitrary provider names, TLS composite
ciphers, AEAD, and XTS cannot be passed to `Stream`. Key and IV sizes are checked
before native initialization, with explicit bounds for legacy variable-key
algorithms. The context cannot be reconfigured except for a checked CTR/ChaCha20
nonce reset. ChaCha20 refuses 32-bit counter carry. XTS consumes the context in
one data-unit operation, bounds the unit to 2^20 AES blocks, and rejects equal
key halves on all backends.

Unpadded block updates reserve input length plus block size minus one. Padded
updates reserve an entire additional block, covering LibreSSL's withheld-block
write even on empty input. Limits cover native signed output lengths before C
is called. Finalization consumes the context and cleanses unused scratch bytes.

GCM accepts only its own algorithm enum. AAD must precede payload, byte limits
are checked, and failed operations poison the context. Encryption finalization
returns a 128-bit tag. `UnverifiedGcmDecrypt` explicitly exposes untrusted output
for cryptography's existing streaming protocol; it cannot be finalized without
an expected tag. Authentication failure cannot revoke bytes already observed by
a streaming caller. The one-shot `AesGcm::open` interface withholds plaintext
and erases it on authentication failure.

Streaming GCM requires at least a four-byte tag, matching the existing Python
API. One-to-three-byte tags are rejected before native verification even when
their bytes match the authentic tag prefix. New protocols should use the full
16-byte tag returned by encryption; truncation exists for legacy compatibility.

OpenSSL cipher descriptors own a fetched reference and remain alive with the
context. Fork descriptors are immutable static objects. Context `Sync` is sound
because metadata is cached in Rust and shared native access is limited to
copying pristine `CipherKey` schedules through a const source. Mutating native
operations require exclusive access or consume ownership. Inputs and outputs
must be valid disjoint Rust borrows.

## One-shot AEAD and Poly1305

AEAD keys are owned and immutable. Cipher modes and tag lengths are validated
before any operation, with separate CCM setup, SIV associated-data components,
and BoringSSL/AWS-LC AEAD calls. Every operation owns its native context and
keeps unauthenticated output in an erased-on-drop temporary buffer. Caller
output is copied only after successful authentication. Descriptor parameters,
nonce lengths, CCM size bounds, integer limits, and output lengths are checked.

The native Poly1305 state uses bindgen's actual backend type inside a heap-owned
`MaybeUninit` allocation. Its address does not change when the Rust wrapper
moves; unused native storage is never assumed to contain initialized Rust
values. Finalization consumes the wrapper, and Drop erases the whole allocation.
OpenSSL uses the owned EVP_MAC API instead. Each Poly1305 key remains a one-time
key: callers must not reuse its bytes to create another independent MAC.

`CipherKey` retains pristine, immutable encryption and decryption key schedules.
Starting an operation fallibly copies the appropriate native state and requires
a full IV before returning a stream. Native copy reads a const source; all
payload operations use a distinct context. Private scratch allocations used for
password-encrypted keys are erased on both success and failure.

## Named-curve EC keys

The EC API admits only the listed prime-field named curves and checks their
native cofactor is one. Public imports accept canonical compressed or
uncompressed encodings, reject infinity and off-curve points, and run the native
key check before publishing a key. Coordinates are encoded at their exact field
width; native point parsing rejects values outside the field rather than reducing
them modulo the field. Private imports require `1 <= scalar < order` and derive
the public point internally, so callers cannot supply inconsistent components.
The scalar range also meets OpenSSL's documented precondition for constant-time
single-scalar `EC_POINT_mul`; no arbitrary multi-scalar operation is exposed.
See https://docs.openssl.org/3.0/man3/EC_POINT_add/.

Key objects remain immutable after construction and each ECDSA/ECDH operation
owns a fresh native context. ECDH requires the same curve on both keys and returns
an erased-on-drop secret of the full field width. Its inputs have already passed
point and cofactor validation; native peer validation is also left enabled.
ECDSA accepts a prehash with a checked fixed digest length, returns bounded DER,
and confines deterministic nonce controls to supported OpenSSL signing contexts.
Private scalar exports and native temporary BIGNUMs are erased on destruction.
No raw key pointer, arbitrary curve, generator, or unvalidated peer crosses the
safe public interface.

## Finite-field DH

DH parameters are bounded to 512–10,000 bits and pass native parameter checks
before key operations. Private exponents are positive and below the subgroup
order when supplied, or below the modulus otherwise. Public construction
checks the range and native subgroup constraints. Private construction derives
the public value using constant-time Montgomery exponentiation and verifies
any supplied public component. Agreement requires identical parameters and
rechecks the peer before creating a complete, privately owned EVP operation.
The result is padded to the full modulus width and stored in an erased buffer.
EVP is used for agreement so OpenSSL provider policy remains in effect.

The legacy Python API also permits round trips of inconsistent components.
`PrivateKeyMaterial` and `PublicKeyMaterial` hold these bounded encodings as
Rust data, with no cryptographic methods. Their explicit, fallible `validate`
methods are required to obtain operational keys. No incomplete or unvalidated
native key object escapes the implementation. Every agreement builds fresh
native state; concurrently shared Rust key data is immutable.

## DSA

Operational DSA keys require bounded prime p and q, q dividing p-1, a nontrivial
generator of the q-order subgroup, and checked scalar/public relationships.
Private construction derives the public component with constant-time modular
exponentiation. Public keys are range- and subgroup-checked. Each signature or
verification owns a fresh EVP context, preserving native provider policy and
avoiding shared mutable signing state. Digest and DER lengths are bounded.

Separate material types preserve legacy parsing of malformed keys without
claiming cryptographic validity. They have no signing or verification methods.
Explicit validation produces operational types and caches its result. Secret
scalars use erased storage, including temporary native BIGNUMs.

## ML-DSA and ML-KEM

Private and public roles are separate. Seeds have fixed array sizes; variants
form closed enums. Shared key objects contain immutable Rust encodings, not
shared native state. Each operation constructs its own native key and context.
Input lengths, context strings, and output capacities are checked before FFI.
Seed temporaries, expanded BoringSSL ML-DSA keys, and shared secrets are erased.
BoringSSL's expanded structs stay in aligned stable heap storage; no Rust value
is assumed initialized from native writes or copied with uninitialized padding.

ML-DSA message signing and external-mu signing are separate methods. The latter
takes exactly 64 bytes and documents the required public-key and context domain
separation. Normal signing limits context strings to 255 bytes. Native randomized
nonce generation remains enabled. ML-KEM rejects incorrect ciphertext lengths;
correctly sized invalid ciphertexts retain native implicit-rejection semantics.
Returned shared secrets do not imply ciphertext authentication.

AWS-LC experimental KEM declarations are generated from its installed header.
The only added C compatibility function evaluates BoringSSL's inline CBS_init.
Known-answer tests independently check seed expansion, signature verification,
external mu, decapsulation, and the deterministic implicit-rejection secret.

## Serialization integration

Cryptography's Rust ASN.1 codecs consume algorithm-specific key data and borrowed
serialization views. They no longer reconstruct generic native PKey objects or
accept an independently supplied algorithm id. PKCS#8 v2 public components are
compared through canonical public encodings after parsing both key roles.

RSA container parsing retains bounded erased components until the caller chooses
its existing explicit validation policy. EC private imports derive their own
public point and compare any encoded public component. Legacy DSA/DH private
encodings with implicit public values use bounded constant-time exponentiation
to form passive material; that calculation does not grant operational validity.

Unsupported MAC keys and arbitrary curves cannot inhabit the serialization view.
The old internal panic tests are replaced by compile-fail coverage and explicit
unsupported-algorithm parser checks; Python capability skips are unchanged.


## Container decoding and runtime

PKCS#12 and legacy BER PKCS#7 decoding publish owned encodings, never native
handles or borrowed stack members. Partially populated parse outputs enter RAII
owners before the status is checked. Password pointers originate from `CStr`;
Python adapters reject embedded NUL before making that value. PKCS#7 verification
uses explicit trust anchors and a fixed flag set with no verification bypass.

Private PKCS#8 output uses erased Rust buffers. OpenSSL and LibreSSL erase the
intermediate PKCS8_PRIV_KEY_INFO through their native ASN.1 destructor callback.
The other forks marshal directly into bounded caller-owned CBB storage because
their generic PKCS#8 destructor does not erase the private octets. A failed CBB
is only cleaned up, never queried or flushed; the entire output allocation is
erased before retry or return.

Every standalone operation that needs algorithm registration explicitly enters
the shared initialization routine. The CMAC first-operation test runs in its own
executable so another test cannot mask initialization-order dependencies.
Fetched provider references are retained for process lifetime. There is no safe
provider unload or default FIPS property setter. Configure FIPS before process
startup: OpenSSL documents default-property mutation as incompatible with
concurrent native operations, including operations in other libraries.

Argon2 validates lane, memory, salt, and output limits. Writable OSSL_PARAM data
has owned erased backing storage for the complete synchronous call. Using one
worker preserves lane semantics without mutating a process-wide thread pool.
Error records copy the calling thread's native diagnostic queue into Rust data.

## Python buffer boundary

The integration's crypto backend, key codecs, and buffer adapter forbid unsafe
Rust. Python bytes are immutable and may be borrowed. Other input buffers,
including readonly views of mutable storage, are copied through memoryview into
immutable Python bytes before Rust obtains a slice. A snapshot is not guaranteed
to be atomic under external mutation; buffer exporters retain their own protocol
and synchronization obligations.

Python output views pin their exports. Native operations write exclusively owned,
erased Rust staging buffers. Only the successfully produced prefix is published
through the interpreter after the operation succeeds. This permits overlapping
Python input/output views without creating aliased Rust references. One-shot
AEAD commits only after authentication; failed or abandoned operations leave
Python destinations unchanged. Explicit streaming GCM remains unverified until
its final tag check, as required by the existing Python API.


Repeated DSA parameter imports reuse at most 32 fully validated groups. The
cache contains canonical public p, q, and g bytes and uses exact equality,
including every component. Cache misses retain the same primality and subgroup
checks. Changed public keys still undergo range and subgroup validation. No
private key, native object, or provider-policy decision enters the cache; native
operations continue to enforce provider policy. Locks cover only lookup and
insertion, and a poisoned cache is bypassed. Concurrent misses may repeat work.
The maximum retained component payload is 33,792 bytes plus Rust metadata.

AEAD's Python payload and associated-data extractors inspect the actual buffer
export byte count before copying. Oversized inputs receive the existing
OverflowError without materializing a large mapping. Rust-to-Rust callers retain
the operation's length checks. This does not relax the ownership boundary.

## Native link identity

The sys crate reserves Cargo's `links = "openssl"` identity, shared by the
original openssl-sys crate. Cargo therefore rejects a graph containing both
bindings before linking. Their unprefixed native symbols must not select
conflicting implementations or layouts. This is a dependency conflict check,
not an attempt to provide interoperability with the old Rust wrapper. Metadata
for direct dependents uses the corresponding `DEP_OPENSSL_*` namespace. See
[Cargo's links contract](https://doc.rust-lang.org/cargo/reference/build-scripts.html#the-links-manifest-key).
