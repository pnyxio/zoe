package io.pnyx.zoe.bytes



abstract class ComparableBytes(): Bytes {

    override fun equals(other: Any?): Boolean {
        return when {
            other is Bytes -> {
                other::class == this::class
                bytes contentEquals other.bytes
            }
            else -> false
        }
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }

    infix fun rawBytesEquals(other: Bytes) = bytes contentEquals other.bytes

}

open class BytesWrap(override val bytes: ByteArray): ComparableBytes()

fun ByteArray.toBytes() = BytesWrap(this)
fun Array<out Byte>.toBytes() = BytesWrap(this.toByteArray())
fun Collection<Byte>.toBytes() = BytesWrap(this.toByteArray())

interface Bytes {
    val bytes: ByteArray
    val size: Int get() = bytes.size
    companion object {
        //TODO test
        /**
         * Get the i'th bit of a byte array.
         * @param h the byte array.
         * @param i the bit index.
         * @return 0 or 1, the value of the i'th bit in h
         */
        fun bitAt(h: ByteArray, i: Int): Int {
            return h[i shr/*miki*/ 3].toInt() shr (i and 7).toInt() and 1
        }

    }
}
inline val Bytes.ubytes get() = bytes.asUByteArray()

fun byteArrayEquals(b1: ByteArray, b2: ByteArray): Boolean {
    if(b1.size != b2.size) {
        return false
    }
    for(i in 0 until b1.size) {
        if (b1[i] != b2[i]) {
            return false
        }
    }
    return true
}


fun bigEndianToLong(bs: ByteArray, off: Int): Long {
    val hi = bigEndianToInt(bs, off)
    val lo = bigEndianToInt(bs, off + 4)
    return (hi.toLong() and 0xffffffffL).toLong() shl 32 or (lo.toLong() and 0xffffffffL).toLong()
}
fun bigEndianToInt(bs: ByteArray, off: Int): Int {
    var _off = off
    var n = bs[_off].toInt() shl 24
    n = n or (bs[++_off].toInt() and 0xff shl 16)
    n = n or (bs[++_off].toInt() and 0xff shl 8)
    n = n or (bs[++_off].toInt() and 0xff)
    return n
}

fun longToBigEndian(n: Long): ByteArray {
    val bs = ByteArray(8)
    longToBigEndian(n, bs, 0)
    return bs
}
fun longToBigEndian(n: Long, bs: ByteArray, off: Int) {
    intToBigEndian(n.ushr(32).toInt(), bs, off)
    intToBigEndian((n and 0xffffffffL).toInt(), bs, off + 4)
}
fun intToBigEndian(n: Int, bs: ByteArray, off: Int) {
    var _off = off
    bs[_off] = n.ushr(24).toByte()
    bs[++_off] = n.ushr(16).toByte()
    bs[++_off] = n.ushr(8).toByte()
    bs[++_off] = n.toByte()
}

fun longToLittleEndian(n: Long): ByteArray {
    val bs = ByteArray(8)
    longToLittleEndian(n, bs, 0)
    return bs
}

fun longToLittleEndian(ns: LongArray, nsOff: Int, nsLen: Int, bs: ByteArray, _bsOff: Int) {
    var bsOff = _bsOff
    for (i in 0 until nsLen) {
        longToLittleEndian(ns[nsOff + i], bs, bsOff)
        bsOff += 8
    }
}

fun longToLittleEndian(n: Long, bs: ByteArray, off: Int) {
    intToLittleEndian((n and 0xffffffffL).toInt(), bs, off)
    intToLittleEndian(n.ushr(32).toInt(), bs, off + 4)
}

//TODO sure ? check original
fun intToLittleEndian(n: Int, bs: ByteArray, _off: Int) {
    var off = _off
    bs[off] = n.toByte()
    bs[++off] = n.ushr(8).toByte()
    bs[++off] = n.ushr(16).toByte()
    bs[++off] = n.ushr(24).toByte()
}

fun littleEndianToLong(bs: ByteArray, off: Int): Long {
    val lo = littleEndianToInt(bs, off)
    val hi = littleEndianToInt(bs, off + 4)
    return (hi.toLong() and 0xffffffffL) shl 32 or (lo.toLong() and 0xffffffffL)
}

fun littleEndianToInt(bs: ByteArray, _off: Int): Int {
    var off = _off
    var n = bs[off].toInt() and 0xff
    n = n or (bs[++off].toInt() and 0xff shl 8)
    n = n or (bs[++off].toInt() and 0xff shl 16)
    n = n or (bs[++off].toInt() shl 24)
    return n
}
