# Compiled with `juliac --trim=safe` in CI to check that WebAuthn.jl stays
# trim-safe when callers pass functions for `origin` and `challenge`.
using WebAuthn

function (@main)(args::Vector{String})::Cint
    seen = String[]
    client = Vector{UInt8}("{\"type\":\"webauthn.get\",\"challenge\":\"c\",\"origin\":\"https://example.com\"}")
    data = zeros(UInt8, 37)
    for verify in (:authentication, :registration)
        try
            if verify === :authentication
                WebAuthn.verify_authentication(client, data, UInt8[1]; rp_id = "example.com",
                    origin = o -> startswith(o, "https://"), challenge = c -> (push!(seen, c); true),
                    public_key = UInt8[1])
            else
                WebAuthn.verify_registration(client, data; rp_id = "example.com",
                    origin = "https://example.com", challenge = "c", credential_id = UInt8[1],
                    public_key = UInt8[1], algorithm = WebAuthn.ES256)
            end
        catch e
            e isa WebAuthn.VerificationError || rethrow()
            println(Core.stdout, verify, ": ", e.msg)
        end
    end
    println(Core.stdout, "challenges seen: ", length(seen))
    return 0
end
