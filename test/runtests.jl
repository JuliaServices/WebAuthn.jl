using Test, WebAuthn, SHA, OpenSSL_jll

const RP_ID = "example.com"
const ORIGIN = "https://example.com"

const libcrypto = OpenSSL_jll.libcrypto

# A fresh key made with libcrypto: the private key handle and the public key as
# DER SubjectPublicKeyInfo.
function keypair(kind, param)
    pkey = kind == "EC" ?
        @ccall(libcrypto.EVP_PKEY_Q_keygen(C_NULL::Ptr{Cvoid}, C_NULL::Ptr{Cvoid}, kind::Cstring; param::Cstring)::Ptr{Cvoid}) :
        @ccall(libcrypto.EVP_PKEY_Q_keygen(C_NULL::Ptr{Cvoid}, C_NULL::Ptr{Cvoid}, kind::Cstring; param::Csize_t)::Ptr{Cvoid})
    pkey == C_NULL && error("key generation failed")
    der = zeros(UInt8, @ccall(libcrypto.i2d_PUBKEY(pkey::Ptr{Cvoid}, C_NULL::Ptr{Ptr{UInt8}})::Cint))
    GC.@preserve der @ccall(libcrypto.i2d_PUBKEY(pkey::Ptr{Cvoid}, Ref(pointer(der))::Ref{Ptr{UInt8}})::Cint)
    return (; pkey, der)
end

function sign(key, message)
    ctx = @ccall libcrypto.EVP_MD_CTX_new()::Ptr{Cvoid}
    md = @ccall libcrypto.EVP_sha256()::Ptr{Cvoid}
    @ccall(libcrypto.EVP_DigestSignInit(ctx::Ptr{Cvoid}, C_NULL::Ptr{Cvoid}, md::Ptr{Cvoid}, C_NULL::Ptr{Cvoid},
                                        key.pkey::Ptr{Cvoid})::Cint) == 1 || error("sign init failed")
    len = Ref{Csize_t}(0)
    @ccall libcrypto.EVP_DigestSign(ctx::Ptr{Cvoid}, C_NULL::Ptr{UInt8}, len::Ref{Csize_t},
                                    message::Ptr{UInt8}, length(message)::Csize_t)::Cint
    signature = zeros(UInt8, len[])
    @ccall(libcrypto.EVP_DigestSign(ctx::Ptr{Cvoid}, signature::Ptr{UInt8}, len::Ref{Csize_t},
                                    message::Ptr{UInt8}, length(message)::Csize_t)::Cint) == 1 || error("sign failed")
    @ccall libcrypto.EVP_MD_CTX_free(ctx::Ptr{Cvoid})::Cvoid
    return signature[1:len[]]
end

client_json(type; challenge = "chal", origin = ORIGIN, extra = "") =
    Vector{UInt8}("{\"type\":\"$type\",\"challenge\":\"$challenge\",\"origin\":\"$origin\"$extra}")

function auth_data(; rp_id = RP_ID, flags = 0x05, sign_count = 7, credential_id = nothing)
    bytes = vcat(sha256(rp_id), [flags], reinterpret(UInt8, [hton(UInt32(sign_count))]))
    credential_id === nothing && return bytes
    return vcat(bytes, zeros(UInt8, 16), UInt8[length(credential_id) >> 8, length(credential_id) & 0xff],
                credential_id, UInt8[0xa5, 0x01, 0x02])  # trailing bytes stand in for the COSE key
end

@testset "WebAuthn" begin
    ec = keypair("EC", "P-256")
    ec384 = keypair("EC", "P-384")
    rsa = keypair("RSA", 2048)
    rsa1024 = keypair("RSA", 1024)
    credential_id = rand(UInt8, 16)

    @testset "registration" begin
        reg(; json = client_json("webauthn.create"), data = auth_data(; flags = 0x4d, credential_id),
              id = credential_id, key = ec.der, algorithm = WebAuthn.ES256, kw...) =
            WebAuthn.verify_registration(json, data; rp_id = RP_ID, origin = ORIGIN, challenge = "chal",
                                         credential_id = id, public_key = key, algorithm, kw...)
        data = reg()
        @test data.credential_id == credential_id
        @test data.sign_count == 7
        @test WebAuthn.user_verified(data) && WebAuthn.backup_eligible(data) && !WebAuthn.backed_up(data)
        @test reg(; key = rsa.der, algorithm = WebAuthn.RS256).credential_id == credential_id
        @test_throws WebAuthn.VerificationError("The passkey response doesn't match its ID") reg(; id = credential_id .⊻ 0xff)
        @test_throws WebAuthn.VerificationError("The passkey response doesn't match its ID") reg(; data = auth_data(; flags = 0x05))
        @test_throws WebAuthn.VerificationError("The passkey's public key doesn't match its kind") reg(; key = rsa.der)
        @test_throws WebAuthn.VerificationError("The passkey's public key doesn't match its kind") reg(; key = ec384.der)
        @test_throws WebAuthn.VerificationError("The passkey's public key doesn't match its kind") reg(; key = rsa1024.der, algorithm = WebAuthn.RS256)
        @test_throws WebAuthn.VerificationError("The passkey's public key doesn't match its kind") reg(; key = UInt8[1, 2, 3])
        @test_throws WebAuthn.VerificationError("The passkey's public key doesn't match its kind") reg(; algorithm = -8)  # EdDSA
        @test_throws WebAuthn.VerificationError("The passkey response is for a different step") reg(; json = client_json("webauthn.get"))
        @test_throws WebAuthn.VerificationError("The passkey response has a bad credential ID") reg(; data = auth_data(; flags = 0x45, credential_id)[1:60])
    end

    @testset "authentication" begin
        function auth(; json = client_json("webauthn.get"), data = auth_data(), signer = ec,
                        signature = nothing, challenge = "chal", origin = ORIGIN, kw...)
            signature = something(signature, sign(signer, vcat(data, sha256(json))))
            return WebAuthn.verify_authentication(json, data, signature; rp_id = RP_ID, origin,
                                                  challenge, public_key = signer.der, kw...)
        end
        @test auth().sign_count == 7
        @test auth(; signer = rsa).sign_count == 7
        @test auth(; json = client_json("webauthn.get"; extra = ",\"crossOrigin\":false")).flags == 0x05

        # Expected values may be functions; a challenge function sees each challenge once.
        seen = String[]
        @test auth(; challenge = c -> (push!(seen, c); true), origin = o -> startswith(o, "https://")).flags == 0x05
        @test seen == ["chal"]
        @test_throws WebAuthn.VerificationError("The passkey request expired or was already used. Try again.") auth(; challenge = c -> false)
        @test_throws WebAuthn.VerificationError("The passkey request expired or was already used. Try again.") auth(; challenge = "other")
        # The challenge is compared as text, so a padded copy of the expected one does not match.
        @test_throws WebAuthn.VerificationError("The passkey request expired or was already used. Try again.") auth(; json = client_json("webauthn.get"; challenge = "chal="))

        @test_throws WebAuthn.VerificationError("The passkey response came from another website") auth(; origin = "https://evil.example")
        @test_throws WebAuthn.VerificationError("The passkey response came from another website") auth(; json = client_json("webauthn.get"; extra = ",\"crossOrigin\":true"))
        @test_throws WebAuthn.VerificationError("The passkey belongs to another website") auth(; data = auth_data(; rp_id = "evil.example"))
        @test_throws WebAuthn.VerificationError("The passkey didn't confirm you were there") auth(; data = auth_data(; flags = 0x04))
        @test_throws WebAuthn.VerificationError("The passkey didn't confirm it was you") auth(; data = auth_data(; flags = 0x01), require_user_verification = true)
        @test_throws WebAuthn.VerificationError("The passkey's signature didn't check out. Try again.") auth(; signature = sign(ec, UInt8[1, 2, 3]))
        @test_throws WebAuthn.VerificationError("The passkey's signature didn't check out. Try again.") auth(; signature = sign(rsa, UInt8[1, 2, 3]))
        @test_throws WebAuthn.VerificationError("The passkey response is not valid") auth(; json = Vector{UInt8}("not json"))
        @test_throws WebAuthn.VerificationError("The passkey response is too short") auth(; data = auth_data()[1:20])
    end
end
