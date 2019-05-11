package io.pnyx.zoe.ed25519

import io.pnyx.zoe.bytes.*

expect object FeVal {
    val fe0: Fe
    val fe1: Fe
    val fe2: Fe
    val fe_d: Fe
    val fe_sqrtm1: Fe
    fun parse(bytes: ByteArray): Fe
    fun parse(ints: IntArray): Fe

}
//
interface Fe: Bytes {
    val isNonZero: Boolean
    val isZero get() = ! isNonZero
    val isNegative: Boolean
    fun invert(): Fe
    fun add(value: Fe): Fe
    //    fun addOne(): Fe
    fun subtract(value: Fe): Fe
    //    fun subtractOne(): Fe
    fun negate(): Fe
    fun multiply(value: Fe): Fe
    fun square(): Fe
    fun squareAndDouble(): Fe
    fun pow22523(): Fe
//    fun divPowM1(u: Fe, v: Fe): Fe

    operator fun plus(value: Fe) = add(value)
    operator fun minus(value: Fe) = subtract(value)
    operator fun times(value: Fe) = multiply(value)

}

fun divPowM1(u: Fe, v: Fe): Fe {
    val v3 = v.square().multiply(v)/* v3 = v^3 */
    val uv7 = v3.square().multiply(v).multiply(u)
    val t0 = uv7.pow22523()
    /* t0 = (uv^7)^((q-5)/8) */
    return t0.multiply(v3).multiply(u)/* u^(m+1)v^(-(m+1)) */
}

@Suppress("NOTHING_TO_INLINE")
inline fun ByteArray.asFeUInt(): FeLeUInt {
    require(size == 32) { "expected 32 bytes, found ${size}" }
    require(isLessThan22519(UInt256(this))) { "bigger than 2^255 - 19" }
    return FeLeUInt(this)
}

@Suppress("NOTHING_TO_INLINE")
inline fun UInt256.castFeUInt(): FeLeUInt {
    require(isLessThan22519(this)) { "bigger than 2^255 - 19" }
    return FeLeUInt(bytes)
}

class FeLeUInt(bytes: ByteArray): LeUInt32, BytesWrap(bytes) {

    companion object {
        infix fun of(b: ByteArray): FeLeUInt = b.asFeUInt()
    }
}

