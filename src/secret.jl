module RapidHashSecret

using Base.MultiplicativeInverses: _mul_high as mul_hi
rapid_mix(A, B) = mul_hi(A, B) ⊻ (A * B)

function wyrand(seed::UInt64)
    seed += 0x2d358dccaa6c78a5
    return rapid_mix(seed, seed ⊻ 0x8bb84b93962eacc9)
end

function sprp(n::UInt64, a::UInt64)
    d = n - 1
    s = UInt8(0)

    while (d & 0xff) == 0
        d >>= 8
        s += 8
    end
    if (d & 0xf) == 0
        d >>= 4
        s += 4
    end
    if (d & 0x3) == 0
        d >>= 2
        s += 2
    end
    if (d & 0x1) == 0
        d >>= 1
        s += 1
    end

    b = powermod(a, d, n)
    if b == 1 || b == (n - 1)
        return true
    end

    for _ in 1:UInt8(s)-1
        b = powermod(b, 2, n)
        if b <= 1
            return false
        end
        if b == (n - 1)
            return true
        end
    end
    return false
end

function is_prime(n::UInt64)::Bool
    if n < 2 || (n & 1) == 0
        return false
    end
    if n < 4
        return true
    end
    if !sprp(n, UInt64(2))
        return false
    end
    if n < 2047
        return true
    end
    for a in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
        if !sprp(n, UInt64(a))
            return false
        end
    end
    return true
end

const C_TABLE = UInt8[
    15, 23, 27, 29, 30, 39, 43, 45, 46, 51, 53, 54,
    57, 58, 60, 71, 75, 77, 78, 83, 85, 86, 89, 90,
    92, 99, 101, 102, 105, 106, 108, 113, 114, 116,
    120, 135, 139, 141, 142, 147, 149, 150, 153, 154,
    156, 163, 165, 166, 169, 170, 172, 177, 178, 180,
    184, 195, 197, 198, 201, 202, 204, 209, 210, 212,
    216, 225, 226, 228, 232, 240
]

function make_secret(seed::UInt64)
    secrets = Vector{UInt64}(undef, 4)
    for i in 1:4
        while true
            x = zero(UInt64)
            for shift in 0:8:56
                seed = wyrand(seed)
                idx = seed % length(C_TABLE) + 1
                x |= (UInt64(C_TABLE[idx]) << shift)
            end

            iseven(x) && continue

            ok = true
            for j in 1:(i-1)
                if count_ones(x ⊻ secrets[j]) != 32
                    ok = false
                    break
                end
            end
            if !ok
                continue
            end

            is_prime(x) || continue
            secrets[i] = x
            break
        end
    end

    return (secrets[1], secrets[2], secrets[3], secrets[4])
end

end
