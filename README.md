# WebAuthn.jl

[![CI](https://github.com/JuliaServices/WebAuthn.jl/actions/workflows/ci.yml/badge.svg)](https://github.com/JuliaServices/WebAuthn.jl/actions/workflows/ci.yml)

Check passkey (WebAuthn) responses from browsers on a Julia server.

The package covers relying parties that ask for `attestation: "none"` and read the
new credential's public key with the browser's `getPublicKey()`, which hands over
a DER SubjectPublicKeyInfo. It supports ES256 (ECDSA P-256) and RS256 (RSA, 2048
bits or more), which covers the platform authenticators in current browsers. It
has no CBOR decoder and does not verify attestation statements.

## Use

Decode the base64url fields the browser sends, then check them. Every failed
check throws a `WebAuthn.VerificationError` whose message you can show the person
signing in.

Registration (`navigator.credentials.create()`):

```julia
using WebAuthn

data = WebAuthn.verify_registration(client_data_json, authenticator_data;
    rp_id = "example.com",
    origin = "https://example.com",
    challenge = challenge -> consume_stored_challenge!(challenge),  # or the expected string
    credential_id = raw_id,
    public_key = public_key_der,         # response.getPublicKey()
    algorithm = public_key_algorithm)    # response.getPublicKeyAlgorithm(): WebAuthn.ES256 or WebAuthn.RS256

save(raw_id, public_key_der, data.sign_count, WebAuthn.backup_eligible(data))
```

Authentication (`navigator.credentials.get()`), with the public key saved above:

```julia
data = WebAuthn.verify_authentication(client_data_json, authenticator_data, signature;
    rp_id = "example.com",
    origin = "https://example.com",
    challenge = challenge -> consume_stored_challenge!(challenge),
    public_key = saved.public_key)

# Device-bound credentials must count up; synced passkeys may report 0.
saved.backup_eligible || data.sign_count > saved.sign_count ||
    data.sign_count == 0 == saved.sign_count || error("possible cloned authenticator")
```

`origin` and `challenge` each take the expected string, or a function that gets the
response's value and returns whether it is acceptable. A challenge function is the
place to look up and delete a stored challenge, so each challenge works once.

The building blocks are public too: `WebAuthn.client_data`,
`WebAuthn.authenticator_data` (with `user_present`, `user_verified`,
`backup_eligible`, `backed_up`), `WebAuthn.public_key_matches`, and
`WebAuthn.signature_valid`.
