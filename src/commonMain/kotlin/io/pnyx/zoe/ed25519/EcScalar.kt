package io.pnyx.zoe.ed25519

import io.pnyx.zoe.bytes.BytesWrap
import io.pnyx.zoe.bytes.LeUInt32
import io.pnyx.zoe.bytes.UInt256
import io.pnyx.zoe.bytes.hexDec
import io.pnyx.zoe.util.Rand
import kotlin.experimental.and
import kotlin.experimental.or


fun scEquals(a: EcScalar, b: EcScalar) = a.bytes contentEquals b.bytes

infix fun EcScalar.eq(other: EcScalar) = scEquals(this, other)

expect fun scalarAdd(a: EcScalar, b: EcScalar): EcScalar


operator fun EcScalar.plus(other: EcScalar): EcScalar = scalarAdd(this, other)

operator fun EcScalar.minus(other: EcScalar): EcScalar = EcScalar(
    sc_sub(
        bytes.asUByteArray(),
        other.bytes.asUByteArray()
    ).asByteArray())

operator fun EcScalar.times(other: EcScalar): EcScalar = EcScalar(
    sc_mul(
        bytes.asUByteArray(),
        other.bytes.asUByteArray()
    ).asByteArray())

operator fun EcScalar.times(point: P3): P3 = point.scalarMultiply(this)

infix fun EcScalar.pow(exp: Int): EcScalar {//TODO optimized mul number
    when (exp) {
        0 -> return EcScalar.SC_ONE
        1 -> return this
        else -> {
            var res = this
            for(i in 2..exp) {
                res = res * this
            }
            return res
        }
    }
}

fun EcScalar.sq(): EcScalar = this * this


fun randEcScalar(): EcScalar {
    val h = Rand.get().randomBytes(32)
    h[0] = (h[0].toUByte() and 248.toUByte()).toByte()
    h[31] = h[31] and 63
    h[31] = h[31] or 64
    return EcScalar(h)
}

//(c-ab) mod l
expect fun scalarMulSub(a: EcScalar, b: EcScalar, c: EcScalar): EcScalar

//(c+ab) mod l
expect fun scalarMulAdd(a: EcScalar, b: EcScalar, c: EcScalar): EcScalar

//fun UInt256.sc_check(): Boolean = sc_check(ubytes)



class EcScalar(bytes: ByteArray): LeUInt32, BytesWrap(bytes) {
    companion object {
        infix fun of(b: ByteArray) = b.asEcScalar()
        infix fun ofUInt(i: UInt): EcScalar {
            val result = ByteArray(32)
            result[3] = (i shr 24).toByte()
            result[2] = (i shr 16).toByte()
            result[1] = (i shr  8).toByte()
            result[0] = i/*shr 0*/.toByte()
            return EcScalar(result)
        }
        val SC_ZERO = EcScalar("0000000000000000000000000000000000000000000000000000000000000000".hexDec())
        val SC_ONE = EcScalar("0100000000000000000000000000000000000000000000000000000000000000".hexDec())
        val SC_TWO = EcScalar("0200000000000000000000000000000000000000000000000000000000000000".hexDec())
        val SC_FOUR = EcScalar("0400000000000000000000000000000000000000000000000000000000000000".hexDec())
        val SC_EIGHT = EcScalar("0800000000000000000000000000000000000000000000000000000000000000".hexDec())

    }
}

fun LeUInt32.castEcScalar(): EcScalar = bytes.asEcScalar()

@Suppress("NOTHING_TO_INLINE")
inline fun ByteArray.asEcScalar(): EcScalar {
    require(size == 32) { "expected 32 bytes, found ${size}" }
    require(sc_check(asUByteArray())) { "exp ected little endian encoding of num < l the group order" }
    return EcScalar(this)
}

fun isLessThan22519(_uint256: UInt256): Boolean {// TODO test against sc_check
    val uint256 = _uint256.bytes
    return ((uint256[31] and 0x80.toByte()) != 0x80.toByte())
            && ((uint256[31] != 0x8F.toByte())
            || (uint256[30] != 0xFF.toByte())
            || (uint256[29] != 0xFF.toByte())
            || (uint256[28] != 0xFF.toByte())
            || (uint256[27] != 0xFF.toByte())
            || (uint256[26] != 0xFF.toByte())
            || (uint256[25] != 0xFF.toByte())
            || (uint256[24] != 0xFF.toByte())
            || (uint256[23] != 0xFF.toByte())
            || (uint256[22] != 0xFF.toByte())
            || (uint256[21] != 0xFF.toByte())
            || (uint256[20] != 0xFF.toByte())
            || (uint256[19] != 0xFF.toByte())
            || (uint256[18] != 0xFF.toByte())
            || (uint256[17] != 0xFF.toByte())
            || (uint256[16] != 0xFF.toByte())
            || (uint256[15] != 0xFF.toByte())
            || (uint256[14] != 0xFF.toByte())
            || (uint256[13] != 0xFF.toByte())
            || (uint256[12] != 0xFF.toByte())
            || (uint256[11] != 0xFF.toByte())
            || (uint256[10] != 0xFF.toByte())
            || (uint256[9] != 0xFF.toByte())
            || (uint256[8] != 0xFF.toByte())
            || (uint256[7] != 0xFF.toByte())
            || (uint256[6] != 0xFF.toByte())
            || (uint256[5] != 0xFF.toByte())
            || (uint256[4] != 0xFF.toByte())
            || (uint256[3] != 0xFF.toByte())
            || (uint256[2] != 0xFF.toByte())
            || (uint256[1] != 0xFF.toByte())
            || (uint256[0] < (0xF3.toByte())))
}


