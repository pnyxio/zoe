package io.pnyx.keddsa.math.bigint


import io.pnyx.keddsa.math.Encoding
import io.pnyx.keddsa.math.Field
import io.pnyx.keddsa.math.FieldElement
import java.math.BigInteger


class BigIntegerLittleEndianEncoding : Encoding() {
    /**
     * Mask where only the first b-1 bits are set.
     */
    private var mask: BigInteger? = null

    @Synchronized
    override fun setField(f: Field) {
        super.setField(f)
        mask = BigInteger.ONE.shiftLeft(f.getb() - 1).subtract(BigInteger.ONE)
    }

    override fun encode(x: FieldElement): ByteArray {
        return encode((x as BigIntegerFieldElement).bi.and(mask!!))
    }

    /**
     * Convert $x$ to little endian.
     * Constant time.
     *
     * @param x the BigInteger value to encode
     * @return array of length $b/8$
     * @throws IllegalStateException if field not set
     */
    fun encode(x: BigInteger): ByteArray {
        if (f == null)
            throw IllegalStateException("field not set")
        val `in` = x.toByteArray()
        val out = ByteArray(f!!.getb() / 8)
        for (i in `in`.indices) {
            out[i] = `in`[`in`.size - 1 - i]
        }
        for (i in `in`.size until out.size) {
            out[i] = 0
        }
        return out
    }

    /**
     * Decode a FieldElement from its $(b-1)$-bit encoding.
     * The highest bit is masked out.
     *
     * @param in the $(b-1)$-bit encoding of a FieldElement.
     * @return the FieldElement represented by 'val'.
     * @throws IllegalStateException if field not set
     * @throws IllegalArgumentException if encoding is invalid
     */
    override fun decode(`in`: ByteArray): FieldElement {
        if (f == null)
            throw IllegalStateException("field not set")
        if (`in`.size != f!!.getb() / 8)
            throw IllegalArgumentException("Not a valid encoding")
        return BigIntegerFieldElement(f!!, toBigInteger(`in`).and(mask!!))
    }

    /**
     * Convert in to big endian
     *
     * @param in the $(b-1)$-bit encoding of a FieldElement.
     * @return the decoded value as a BigInteger
     */
    fun toBigInteger(`in`: ByteArray): BigInteger {
        val out = ByteArray(`in`.size)
        for (i in `in`.indices) {
            out[i] = `in`[`in`.size - 1 - i]
        }
        return BigInteger(1, out)
    }

    /**
     * From the Ed25519 paper:<br></br>
     * $x$ is negative if the $(b-1)$-bit encoding of $x$ is lexicographically larger
     * than the $(b-1)$-bit encoding of $-x$. If $q$ is an odd prime and the encoding
     * is the little-endian representation of $\{0, 1,\dots, q-1\}$ then the negative
     * elements of $F_q$ are $\{1, 3, 5,\dots, q-2\}$.
     * @return true if negative
     */
    override fun isNegative(x: FieldElement): Boolean {
        return (x as BigIntegerFieldElement).bi.testBit(0)
    }
}
