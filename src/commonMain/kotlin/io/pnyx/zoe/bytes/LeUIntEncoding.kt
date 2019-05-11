package io.pnyx.zoe.bytes


interface Bytes32: Bytes

interface LeUInt32: Bytes32



class UInt256(bytes: ByteArray): LeUInt32, BytesWrap(bytes) {
    fun toUInt512(): UInt512 = UInt512 of bytes.copyOf(64)

//    fun castScal(): EcScalar = bytes.asEcScalar()

    companion object {
        infix fun of(b: ByteArray): UInt256 = b.asUInt256()
    }
}

@Suppress("NOTHING_TO_INLINE")
inline fun ByteArray.asUInt256(): UInt256 {
    require(size == 32) { "expected 32 bytes, found ${size}" }
    return UInt256(this)
}


//a[0]+256*a[1]+...+256^63*a[63]
inline class UInt512(val bytes: ByteArray) {
    companion object {
        infix fun of(b: ByteArray): UInt512 = b.asUInt512()
    }
}

@Suppress("NOTHING_TO_INLINE")
inline fun ByteArray.asUInt512(): UInt512 {
    require(size == 64) { "expected 64 bytes, found ${size}" }
    return UInt512(this)
}
