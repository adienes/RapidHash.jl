module RapidHash
export rapidhash

const RAPID_SEED = UInt64(0xbdd89aa982704029)
const RAPID_SECRET = tuple(
    0x2d358dccaa6c78a5,
    0x8bb84b93962eacc9,
    0x4b33a62ed433d4a3,
)

using Base.MultiplicativeInverses: _mul_high as mul_hi
rapid_mix(A, B) = mul_hi(A, B) ⊻ (A * B)

read_u32_le(ptr::Ptr{UInt8}, i) = unsafe_load(Ptr{UInt32}(ptr + i))
read_u64_le(ptr::Ptr{UInt8}, i) = unsafe_load(Ptr{UInt64}(ptr + i))

function read_small(ptr::Ptr{UInt8}, n::Int)
    first_b = unsafe_load(ptr)
    middle_b = unsafe_load(ptr + div(n, 2))
    last_b = unsafe_load(ptr + (n - 1))
    return (UInt64(first_b) << 56) | (UInt64(middle_b) << 32) | UInt64(last_b)
end

function rapidhash(
        ptr::Ptr{UInt8},
        n::Int,
        seed::UInt64,
        secret::NTuple{3, UInt64}
    )
    buflen = UInt64(n)

    secret1, secret2, secret3 = secret
    seed = seed ⊻ (rapid_mix(seed ⊻ secret1, secret2) ⊻ buflen)

    a = zero(UInt64)
    b = zero(UInt64)

    if buflen ≤ 16
        if buflen ≥ 4
            a = (UInt64(read_u32_le(ptr, 1)) << 32) |
                UInt64(read_u32_le(ptr, n - 4 + 1))

            delta = (buflen & 24) >> (buflen >> 3)
            b = (UInt64(read_u32_le(ptr, delta + 1)) << 32) |
                UInt64(read_u32_le(ptr, n - 4 - delta + 1))
        elseif buflen > 0
            a = read_small(ptr, n)
        end
    else
        pos = 1
        i = buflen
        if i > 48
            see1 = seed
            see2 = seed
            while i ≥ 48
                seed = rapid_mix(
                    read_u64_le(ptr, pos) ⊻ secret1,
                    read_u64_le(ptr, pos + 8) ⊻ seed
                )
                see1 = rapid_mix(
                    read_u64_le(ptr, pos + 16) ⊻ secret2,
                    read_u64_le(ptr, pos + 24) ⊻ see1
                )
                see2 = rapid_mix(
                    read_u64_le(ptr, pos + 32) ⊻ secret3,
                    read_u64_le(ptr, pos + 40) ⊻ see2
                )
                pos += 48
                i -= 48
            end
            seed = seed ⊻ see1 ⊻ see2
        end
        if i > 16
            seed = rapid_mix(
                read_u64_le(ptr, pos) ⊻ secret3,
                read_u64_le(ptr, pos + 8) ⊻ seed ⊻ secret2
            )
            if i > 32
                seed = rapid_mix(
                    read_u64_le(ptr, pos + 16) ⊻ secret3,
                    read_u64_le(ptr, pos + 24) ⊻ seed
                )
            end
        end

        a = read_u64_le(ptr, n - 16 + 1)
        b = read_u64_le(ptr, n - 8 + 1)
    end

    a = a ⊻ secret2
    b = b ⊻ seed
    a, b = a * b, mul_hi(a, b)
    return rapid_mix(a ⊻ secret1 ⊻ buflen, b ⊻ secret2)
end


function rapidhash(data::UInt64, seed::UInt64, secret::NTuple{3, UInt64})
    seed = seed ⊻ (rapid_mix(seed ⊻ secret[1], secret[2]) ⊻ 8)

    a = (UInt64(bswap((data >> 32) % UInt32)) << 32) | UInt64(bswap(data % UInt32))
    b = (a << 32) | (a >> 32)
    a = a ⊻ secret[2]
    b = b ⊻ seed
    a, b = a * b, mul_hi(a, b)
    return rapid_mix(a ⊻ secret[1] ⊻ 8, b ⊻ secret[2])
end


function rapidhash(data::UInt32, seed::UInt64, secret::NTuple{3, UInt64})
    seed = seed ⊻ (rapid_mix(seed ⊻ secret[1], secret[2]) ⊻ 4)

    a = (UInt64(bswap(data)) << 32) | UInt64(bswap(data))

    b = a ⊻ seed
    a = a ⊻ secret[2]
    a, b = a * b, mul_hi(a, b)
    return rapid_mix(a ⊻ secret[1] ⊻ 4, b ⊻ secret[2])
end


function rapidhash(data::UInt16, seed::UInt64, secret::NTuple{3, UInt64})
    secret1, secret2, _ = secret
    seed = seed ⊻ (rapid_mix(seed ⊻ secret1, secret2) ⊻ 2)

    b2 = data % UInt16
    a = (UInt64(data >> 8) << 56) | (UInt64(b2) << 32) | UInt64(b2)
    a = a ⊻ secret2
    a, b = a * seed, mul_hi(a, seed)
    return rapid_mix(a ⊻ secret1 ⊻ 2, b ⊻ secret2)
end


function rapidhash(data::UInt8, seed::UInt64, secret::NTuple{3, UInt64})
    secret1, secret2, _ = secret
    seed = seed ⊻ (rapid_mix(seed ⊻ secret1, secret2) ⊻ 1)
    u64data = UInt64(data)
    a = (u64data << 56) | (u64data << 32) | u64data
    a = a ⊻ secret2
    a, b = a * seed, mul_hi(a, seed)
    return rapid_mix(a ⊻ secret1 ⊻ 1, b ⊻ secret2)
end

function rapidhash(data::T, seed::UInt64, secret::NTuple{3, UInt64}) where {T <: Union{Int8, Int16, Int32, Int64}}
    return rapidhash(reinterpret(unsigned(T), data), seed, secret)
end

rapidhash(data::Char, seed::UInt64, secret::NTuple{3, UInt64}) =
    rapidhash(UInt(Base.bitcast(UInt32, data)), seed, secret)
rapidhash(data::String, seed::UInt64, secret::NTuple{3, UInt64}) =
    GC.@preserve s rapidhash(pointer(data), sizeof(data), seed, secret)


rapidhash(w::WeakRef, seed::UInt64, secret::NTuple{3, UInt64}) = rapid(w.value, seed, secret)
function rapidhash(T::Type, seed::UInt64, secret::NTuple{3, UInt64})
    return rapidhash((Base.@assume_effects :total ccall(:jl_type_hash, UInt, (Any,), T)), seed, secret)
end

# generic dispatch
rapidhash(data, seed::UInt64) = rapidhash(data, seed ⊻ RAPID_SEED, RAPID_SECRET)
rapidhash(data) = rapidhash(data, zero(UInt64))

end
