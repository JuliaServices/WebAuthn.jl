"""
    WebAuthn

Checks the passkey responses that browsers return from
`navigator.credentials.create()` (registration) and `navigator.credentials.get()`
(authentication), for relying parties that ask for `attestation: "none"`.

The browser hands over the new credential's public key as a DER
SubjectPublicKeyInfo (`AuthenticatorAttestationResponse.getPublicKey()`), so this
package reads authenticator data at its fixed byte offsets and never decodes
CBOR. Supported algorithms are ES256 (ECDSA P-256 with SHA-256) and RS256 (RSA
PKCS #1 v1.5 with SHA-256, keys of at least 2048 bits), which together cover
the platform authenticators in current browsers.

Every check failure throws a [`VerificationError`](@ref) whose message is plain
enough to show the person signing in.
"""
module WebAuthn

using JSON, SHA, StructUtils, OpenSSL_jll

"COSE algorithm number for ECDSA P-256 with SHA-256."
const ES256 = -7
"COSE algorithm number for RSA PKCS #1 v1.5 with SHA-256."
const RS256 = -257

const _FLAG_USER_PRESENT = 0x01
const _FLAG_USER_VERIFIED = 0x04
const _FLAG_BACKUP_ELIGIBLE = 0x08
const _FLAG_BACKED_UP = 0x10
const _FLAG_ATTESTED_CREDENTIAL = 0x40

"""
    VerificationError(msg)

A passkey response failed a check. `msg` says which, in words fit to show the
person signing in.
"""
struct VerificationError <: Exception
    msg::String
end

Base.showerror(io::IO, e::VerificationError) = print(io, "WebAuthn.VerificationError: ", e.msg)

"""
    ClientData

The fields of the browser's `clientDataJSON` that a relying party checks. Field
names follow the JSON keys in the WebAuthn specification.
"""
StructUtils.@kwarg struct ClientData
    type::String = ""
    challenge::String = ""
    origin::String = ""
    crossOrigin::Bool = false
end

"""
    client_data(client_data_json::AbstractVector{UInt8}) -> ClientData

Read the browser's `clientDataJSON` bytes.
"""
function client_data(client_data_json::AbstractVector{UInt8})
    try
        return JSON.parse(String(copy(client_data_json)), ClientData)
    catch
        throw(VerificationError("The passkey response is not valid"))
    end
end

"""
    AuthenticatorData

The parsed `authenticatorData`. `aaguid` and `credential_id` are empty unless the
data carries an attested credential, which a registration response does.
"""
struct AuthenticatorData
    rp_id_hash::Vector{UInt8}
    flags::UInt8
    sign_count::UInt32
    aaguid::Vector{UInt8}
    credential_id::Vector{UInt8}
end

"Whether the person touched or otherwise confirmed the authenticator."
user_present(data::AuthenticatorData) = data.flags & _FLAG_USER_PRESENT != 0
"Whether the authenticator checked who the person is (biometric or PIN)."
user_verified(data::AuthenticatorData) = data.flags & _FLAG_USER_VERIFIED != 0
"Whether the credential may sync between devices (a synced passkey)."
backup_eligible(data::AuthenticatorData) = data.flags & _FLAG_BACKUP_ELIGIBLE != 0
"Whether the credential is currently backed up or synced."
backed_up(data::AuthenticatorData) = data.flags & _FLAG_BACKED_UP != 0

"""
    authenticator_data(bytes::AbstractVector{UInt8}) -> AuthenticatorData

Parse `authenticatorData`: the RP ID hash (32 bytes), flags (1), and signature
counter (4, big-endian), then, when the attested-credential flag is set, the
AAGUID (16), the credential ID length (2, big-endian), and the credential ID.
Anything after the credential ID (its COSE public key, extensions) is ignored.
"""
function authenticator_data(bytes::AbstractVector{UInt8})
    data = Vector{UInt8}(bytes)
    length(data) >= 37 || throw(VerificationError("The passkey response is too short"))
    flags = data[33]
    sign_count = (UInt32(data[34]) << 24) | (UInt32(data[35]) << 16) |
                 (UInt32(data[36]) << 8) | UInt32(data[37])
    aaguid = UInt8[]
    credential_id = UInt8[]
    if flags & _FLAG_ATTESTED_CREDENTIAL != 0
        length(data) >= 55 || throw(VerificationError("The passkey response is too short"))
        aaguid = data[38:53]
        id_length = (Int(data[54]) << 8) | Int(data[55])
        1 <= id_length <= 1023 && length(data) >= 55 + id_length ||
            throw(VerificationError("The passkey response has a bad credential ID"))
        credential_id = data[56:(55 + id_length)]
    end
    return AuthenticatorData(data[1:32], flags, sign_count, aaguid, credential_id)
end

# OpenSSL reads a DER SubjectPublicKeyInfo into a key; C_NULL when it isn't one.
function _load_public_key(der::Vector{UInt8})
    pkey = GC.@preserve der begin
        cursor = Ref{Ptr{UInt8}}(pointer(der))
        ccall((:d2i_PUBKEY, OpenSSL_jll.libcrypto), Ptr{Cvoid},
            (Ptr{Cvoid}, Ptr{Ptr{UInt8}}, Clong), C_NULL, cursor, length(der))
    end
    # A failed parse leaves errors on OpenSSL's per-thread queue, where a TLS
    # library sharing libcrypto would read them as its own.
    pkey == C_NULL && ccall((:ERR_clear_error, OpenSSL_jll.libcrypto), Cvoid, ())
    return pkey
end

"""
    public_key_matches(public_key::AbstractVector{UInt8}, algorithm::Integer) -> Bool

Whether a DER SubjectPublicKeyInfo is the kind of key `algorithm` names: a P-256
key for [`ES256`](@ref), or an RSA key of at least 2048 bits for [`RS256`](@ref).
"""
function public_key_matches(public_key::AbstractVector{UInt8}, algorithm::Integer)
    algorithm == ES256 || algorithm == RS256 || return false
    pkey = _load_public_key(Vector{UInt8}(public_key))
    pkey == C_NULL && return false
    try
        kind = ccall((:EVP_PKEY_get_base_id, OpenSSL_jll.libcrypto), Cint, (Ptr{Cvoid},), pkey)
        if algorithm == RS256
            bits = ccall((:EVP_PKEY_get_bits, OpenSSL_jll.libcrypto), Cint, (Ptr{Cvoid},), pkey)
            return kind == 6 && bits >= 2048  # EVP_PKEY_RSA
        end
        kind == 408 || return false  # EVP_PKEY_EC
        curve = zeros(UInt8, 32)
        curve_length = Ref{Csize_t}(0)
        ccall((:EVP_PKEY_get_group_name, OpenSSL_jll.libcrypto), Cint,
            (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ref{Csize_t}),
            pkey, curve, length(curve), curve_length) == 1 || return false
        return String(curve[1:Int(curve_length[])]) == "prime256v1"
    finally
        ccall((:ERR_clear_error, OpenSSL_jll.libcrypto), Cvoid, ())
        ccall((:EVP_PKEY_free, OpenSSL_jll.libcrypto), Cvoid, (Ptr{Cvoid},), pkey)
    end
end

"""
    signature_valid(public_key, message, signature) -> Bool

Whether `signature` signs `message` under the DER public key: ECDSA with SHA-256
(a DER-encoded signature, as authenticators produce) for an EC key, or RSA
PKCS #1 v1.5 with SHA-256 for an RSA key.
"""
function signature_valid(public_key::AbstractVector{UInt8}, message::AbstractVector{UInt8},
                         signature::AbstractVector{UInt8})
    pkey = _load_public_key(Vector{UInt8}(public_key))
    pkey == C_NULL && return false
    message_bytes = Vector{UInt8}(message)
    signature_bytes = Vector{UInt8}(signature)
    ctx = ccall((:EVP_MD_CTX_new, OpenSSL_jll.libcrypto), Ptr{Cvoid}, ())
    try
        ctx == C_NULL && return false
        # Looked up on every call: a pointer kept in a top-level constant would be
        # stale in a precompiled or native-compiled program.
        sha256_md = ccall((:EVP_sha256, OpenSSL_jll.libcrypto), Ptr{Cvoid}, ())
        ccall((:EVP_DigestVerifyInit, OpenSSL_jll.libcrypto), Cint,
            (Ptr{Cvoid}, Ptr{Ptr{Cvoid}}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            ctx, C_NULL, sha256_md, C_NULL, pkey) == 1 || return false
        return ccall((:EVP_DigestVerify, OpenSSL_jll.libcrypto), Cint,
            (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t),
            ctx, signature_bytes, length(signature_bytes), message_bytes, length(message_bytes)) == 1
    finally
        ccall((:ERR_clear_error, OpenSSL_jll.libcrypto), Cvoid, ())
        ctx == C_NULL || ccall((:EVP_MD_CTX_free, OpenSSL_jll.libcrypto), Cvoid, (Ptr{Cvoid},), ctx)
        ccall((:EVP_PKEY_free, OpenSSL_jll.libcrypto), Cvoid, (Ptr{Cvoid},), pkey)
    end
end

_expected(expected::AbstractString, value::String) = value == expected
_expected(expected::F, value::String) where {F} = expected(value)::Bool

function _constant_time_equal(a::Vector{UInt8}, b::Vector{UInt8})
    length(a) == length(b) || return false
    difference = UInt8(0)
    @inbounds for i in eachindex(a, b)
        difference |= xor(a[i], b[i])
    end
    return iszero(difference)
end

# The checks both ceremonies share, in the order the specification lists them.
# `O` and `C` make Julia specialize on the `origin` and `challenge` functions it
# only passes along, which `juliac --trim` needs to resolve the calls.
function _verify_common(client_data_json, authenticator_data_bytes, ceremony::String,
                        rp_id::AbstractString, origin::O, challenge::C,
                        require_user_verification::Bool) where {O,C}
    client = client_data(client_data_json)
    client.type == ceremony || throw(VerificationError("The passkey response is for a different step"))
    _expected(challenge, client.challenge) ||
        throw(VerificationError("The passkey request expired or was already used. Try again."))
    _expected(origin, client.origin) && !client.crossOrigin ||
        throw(VerificationError("The passkey response came from another website"))
    data = authenticator_data(authenticator_data_bytes)
    _constant_time_equal(data.rp_id_hash, sha256(String(rp_id))) ||
        throw(VerificationError("The passkey belongs to another website"))
    user_present(data) || throw(VerificationError("The passkey didn't confirm you were there"))
    !require_user_verification || user_verified(data) ||
        throw(VerificationError("The passkey didn't confirm it was you"))
    return data
end

"""
    verify_registration(client_data_json, authenticator_data; rp_id, origin, challenge,
                        credential_id, public_key, algorithm,
                        require_user_verification = false) -> AuthenticatorData

Check a registration response (`navigator.credentials.create()`), given its raw
`clientDataJSON` and `authenticatorData` bytes, the raw credential ID, and the DER
public key and COSE algorithm from `getPublicKey()` and
`getPublicKeyAlgorithm()`. Returns the parsed authenticator data; save its
`sign_count` and [`backup_eligible`](@ref) with the key.

`origin` and `challenge` each take the expected string, or a function that gets
the response's value and returns whether it is acceptable. The challenge string
is base64url without `=` padding, the form `clientDataJSON` carries. A challenge
function is the place to look up and consume a stored challenge, so each works
once. Responses made in a cross-origin iframe are rejected.
"""
function verify_registration(client_data_json::AbstractVector{UInt8}, authenticator_data::AbstractVector{UInt8};
                             rp_id::AbstractString, origin::O, challenge::C,
                             credential_id::AbstractVector{UInt8}, public_key::AbstractVector{UInt8},
                             algorithm::Integer, require_user_verification::Bool = false) where {O,C}
    data = _verify_common(client_data_json, authenticator_data, "webauthn.create",
                          rp_id, origin, challenge, require_user_verification)
    !isempty(data.credential_id) && data.credential_id == credential_id ||
        throw(VerificationError("The passkey response doesn't match its ID"))
    public_key_matches(public_key, algorithm) ||
        throw(VerificationError("The passkey's public key doesn't match its kind"))
    return data
end

"""
    verify_authentication(client_data_json, authenticator_data, signature; rp_id, origin,
                          challenge, public_key,
                          require_user_verification = false) -> AuthenticatorData

Check an authentication response (`navigator.credentials.get()`) against the
credential's saved DER public key: the shared checks, then the signature over
`authenticatorData` followed by the SHA-256 of `clientDataJSON`. `origin` and
`challenge` work as in [`verify_registration`](@ref).

The signature counter is left to the caller, because its rule depends on what
was saved: a device-bound credential's `sign_count` must grow past the saved one
(unless both are 0), while a synced one may report 0 or a separate count on each
device.
"""
function verify_authentication(client_data_json::AbstractVector{UInt8}, authenticator_data::AbstractVector{UInt8},
                               signature::AbstractVector{UInt8}; rp_id::AbstractString, origin::O, challenge::C,
                               public_key::AbstractVector{UInt8}, require_user_verification::Bool = false) where {O,C}
    data = _verify_common(client_data_json, authenticator_data, "webauthn.get",
                          rp_id, origin, challenge, require_user_verification)
    message = vcat(Vector{UInt8}(authenticator_data), sha256(Vector{UInt8}(client_data_json)))
    signature_valid(public_key, message, signature) ||
        throw(VerificationError("The passkey's signature didn't check out. Try again."))
    return data
end

end # module
