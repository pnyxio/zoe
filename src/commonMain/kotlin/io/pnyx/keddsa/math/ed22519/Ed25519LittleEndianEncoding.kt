package io.pnyx.keddsa.math.ed22519

import io.pnyx.keddsa.math.Encoding
import io.pnyx.keddsa.math.FieldElement
import kotlin.experimental.and

/**
 * Helper class for encoding/decoding from/to the 32 byte representation.
 *
 *
 * Reviewed/commented by Bloody Rookie (nemproject@gmx.de)
 */
class Ed25519LittleEndianEncoding : Encoding() {
    /**
     * Encodes a given field element in its 32 byte representation. This is done in two steps:
     *
     *  1. Reduce the value of the field element modulo $p$.
     *  1. Convert the field element to the 32 byte representation.
     *
     *
     * The idea for the modulo $p$ reduction algorithm is as follows:
     *
     * <h2>Assumption:</h2>
     *
     *  * $p = 2^{255} - 19$
     *  * $h = h_0 + 2^{25} * h_1 + 2^{(26+25)} * h_2 + \dots + 2^{230} * h_9$ where $0 \le |h_i| \lt 2^{27}$ for all $i=0,\dots,9$.
     *  * $h \cong r \mod p$, i.e. $h = r + q * p$ for some suitable $0 \le r \lt p$ and an integer $q$.
     *
     *
     * Then $q = [2^{-255} * (h + 19 * 2^{-25} * h_9 + 1/2)]$ where $[x] = floor(x)$.
     *
     * <h2>Proof:</h2>
     *
     *
     * We begin with some very raw estimation for the bounds of some expressions:
     *
     *
     * $$
     * \begin{equation}
     * |h| \lt 2^{230} * 2^{30} = 2^{260} \Rightarrow |r + q * p| \lt 2^{260} \Rightarrow |q| \lt 2^{10}. \\
     * \Rightarrow -1/4 \le a := 19^2 * 2^{-255} * q \lt 1/4. \\
     * |h - 2^{230} * h_9| = |h_0 + \dots + 2^{204} * h_8| \lt 2^{204} * 2^{30} = 2^{234}. \\
     * \Rightarrow -1/4 \le b := 19 * 2^{-255} * (h - 2^{230} * h_9) \lt 1/4
     * \end{equation}
     * $$
     *
     *
     * Therefore $0 \lt 1/2 - a - b \lt 1$.
     *
     *
     * Set $x := r + 19 * 2^{-255} * r + 1/2 - a - b$. Then:
     *
     *
     * $$
     * 0 \le x \lt 255 - 20 + 19 + 1 = 2^{255} \\
     * \Rightarrow 0 \le 2^{-255} * x \lt 1.
     * $$
     *
     *
     * Since $q$ is an integer we have
     *
     *
     * $$
     * [q + 2^{-255} * x] = q \quad (1)
     * $$
     *
     *
     * Have a closer look at $x$:
     *
     *
     * $$
     * \begin{align}
     * x &amp;= h - q * (2^{255} - 19) + 19 * 2^{-255} * (h - q * (2^{255} - 19)) + 1/2 - 19^2 * 2^{-255} * q - 19 * 2^{-255} * (h - 2^{230} * h_9) \\
     * &amp;= h - q * 2^{255} + 19 * q + 19 * 2^{-255} * h - 19 * q + 19^2 * 2^{-255} * q + 1/2 - 19^2 * 2^{-255} * q - 19 * 2^{-255} * h + 19 * 2^{-25} * h_9 \\
     * &amp;= h + 19 * 2^{-25} * h_9 + 1/2 - q^{255}.
     * \end{align}
     * $$
     *
     *
     * Inserting the expression for $x$ into $(1)$ we get the desired expression for $q$.
     */
    override fun encode(x: FieldElement): ByteArray {
        val h = (x as Ed25519FieldElement).t
        var h0 = h[0]
        var h1 = h[1]
        var h2 = h[2]
        var h3 = h[3]
        var h4 = h[4]
        var h5 = h[5]
        var h6 = h[6]
        var h7 = h[7]
        var h8 = h[8]
        var h9 = h[9]
        var q: Int
        val carry0: Int
        val carry1: Int
        val carry2: Int
        val carry3: Int
        val carry4: Int
        val carry5: Int
        val carry6: Int
        val carry7: Int
        val carry8: Int
        val carry9: Int

        // Step 1:
        // Calculate q
        q = 19 * h9 + (1 shl 24) shr 25
        q = h0 + q shr 26
        q = h1 + q shr 25
        q = h2 + q shr 26
        q = h3 + q shr 25
        q = h4 + q shr 26
        q = h5 + q shr 25
        q = h6 + q shr 26
        q = h7 + q shr 25
        q = h8 + q shr 26
        q = h9 + q shr 25

        // r = h - q * p = h - 2^255 * q + 19 * q
        // First add 19 * q then discard the bit 255
        h0 += 19 * q

        carry0 = h0 shr 26
        h1 += carry0
        h0 -= carry0 shl 26
        carry1 = h1 shr 25
        h2 += carry1
        h1 -= carry1 shl 25
        carry2 = h2 shr 26
        h3 += carry2
        h2 -= carry2 shl 26
        carry3 = h3 shr 25
        h4 += carry3
        h3 -= carry3 shl 25
        carry4 = h4 shr 26
        h5 += carry4
        h4 -= carry4 shl 26
        carry5 = h5 shr 25
        h6 += carry5
        h5 -= carry5 shl 25
        carry6 = h6 shr 26
        h7 += carry6
        h6 -= carry6 shl 26
        carry7 = h7 shr 25
        h8 += carry7
        h7 -= carry7 shl 25
        carry8 = h8 shr 26
        h9 += carry8
        h8 -= carry8 shl 26
        carry9 = h9 shr 25
        h9 -= carry9 shl 25

        // Step 2 (straight forward conversion):
        val s = ByteArray(32)
        s[0] = h0.toByte()
        s[1] = (h0 shr 8).toByte()
        s[2] = (h0 shr 16).toByte()
        s[3] = (h0 shr 24 or (h1 shl 2)).toByte()
        s[4] = (h1 shr 6).toByte()
        s[5] = (h1 shr 14).toByte()
        s[6] = (h1 shr 22 or (h2 shl 3)).toByte()
        s[7] = (h2 shr 5).toByte()
        s[8] = (h2 shr 13).toByte()
        s[9] = (h2 shr 21 or (h3 shl 5)).toByte()
        s[10] = (h3 shr 3).toByte()
        s[11] = (h3 shr 11).toByte()
        s[12] = (h3 shr 19 or (h4 shl 6)).toByte()
        s[13] = (h4 shr 2).toByte()
        s[14] = (h4 shr 10).toByte()
        s[15] = (h4 shr 18).toByte()
        s[16] = h5.toByte()
        s[17] = (h5 shr 8).toByte()
        s[18] = (h5 shr 16).toByte()
        s[19] = (h5 shr 24 or (h6 shl 1)).toByte()
        s[20] = (h6 shr 7).toByte()
        s[21] = (h6 shr 15).toByte()
        s[22] = (h6 shr 23 or (h7 shl 3)).toByte()
        s[23] = (h7 shr 5).toByte()
        s[24] = (h7 shr 13).toByte()
        s[25] = (h7 shr 21 or (h8 shl 4)).toByte()
        s[26] = (h8 shr 4).toByte()
        s[27] = (h8 shr 12).toByte()
        s[28] = (h8 shr 20 or (h9 shl 6)).toByte()
        s[29] = (h9 shr 2).toByte()
        s[30] = (h9 shr 10).toByte()
        s[31] = (h9 shr 18).toByte()
        return s
    }

    /**
     * Decodes a given field element in its 10 byte $2^{25.5}$ representation.
     *
     * @param in The 32 byte representation.
     * @return The field element in its $2^{25.5}$ bit representation.
     */
    override fun decode(`in`: ByteArray): FieldElement {
        var h0 = load_4(`in`, 0)
        var h1 = (load_3(`in`, 4) shl 6).toLong()
        var h2 = (load_3(`in`, 7) shl 5).toLong()
        var h3 = (load_3(`in`, 10) shl 3).toLong()
        var h4 = (load_3(`in`, 13) shl 2).toLong()
        var h5 = load_4(`in`, 16)
        var h6 = (load_3(`in`, 20) shl 7).toLong()
        var h7 = (load_3(`in`, 23) shl 5).toLong()
        var h8 = (load_3(`in`, 26) shl 4).toLong()
        var h9 = (load_3(`in`, 29) and 0x7FFFFF shl 2).toLong()
        val carry0: Long
        val carry1: Long
        val carry2: Long
        val carry3: Long
        val carry4: Long
        val carry5: Long
        val carry6: Long
        val carry7: Long
        val carry8: Long
        val carry9: Long

        // Remember: 2^255 congruent 19 modulo p
        carry9 = h9 + (1 shl 24).toLong() shr 25
        h0 += carry9 * 19
        h9 -= carry9 shl 25
        carry1 = h1 + (1 shl 24).toLong() shr 25
        h2 += carry1
        h1 -= carry1 shl 25
        carry3 = h3 + (1 shl 24).toLong() shr 25
        h4 += carry3
        h3 -= carry3 shl 25
        carry5 = h5 + (1 shl 24).toLong() shr 25
        h6 += carry5
        h5 -= carry5 shl 25
        carry7 = h7 + (1 shl 24).toLong() shr 25
        h8 += carry7
        h7 -= carry7 shl 25

        carry0 = h0 + (1 shl 25).toLong() shr 26
        h1 += carry0
        h0 -= carry0 shl 26
        carry2 = h2 + (1 shl 25).toLong() shr 26
        h3 += carry2
        h2 -= carry2 shl 26
        carry4 = h4 + (1 shl 25).toLong() shr 26
        h5 += carry4
        h4 -= carry4 shl 26
        carry6 = h6 + (1 shl 25).toLong() shr 26
        h7 += carry6
        h6 -= carry6 shl 26
        carry8 = h8 + (1 shl 25).toLong() shr 26
        h9 += carry8
        h8 -= carry8 shl 26

        val h = IntArray(10)
        h[0] = h0.toInt()
        h[1] = h1.toInt()
        h[2] = h2.toInt()
        h[3] = h3.toInt()
        h[4] = h4.toInt()
        h[5] = h5.toInt()
        h[6] = h6.toInt()
        h[7] = h7.toInt()
        h[8] = h8.toInt()
        h[9] = h9.toInt()
        return Ed25519FieldElement(f!!, h)
    }

    /**
     * Is the FieldElement negative in this encoding?
     *
     *
     * Return true if $x$ is in $\{1,3,5,\dots,q-2\}$<br></br>
     * Return false if $x$ is in $\{0,2,4,\dots,q-1\}$
     *
     *
     * Preconditions:
     *
     *  * $|x|$ bounded by $1.1*2^{26},1.1*2^{25},1.1*2^{26},1.1*2^{25}$, etc.
     *
     *
     * @return true if $x$ is in $\{1,3,5,\dots,q-2\}$, false otherwise.
     */
    override fun isNegative(x: FieldElement): Boolean {
        val s = encode(x)
        return s[0] and 1.toByte() != 0.toByte()
    }

    fun signum(a: Long): Long {
        return (a shr 63) - (-a shr 63)
    }

    fun sc_check(s: ByteArray): Boolean {
        val s0 = load_4(s, 0)
        val s1 = load_4(s, 4)
        val s2 = load_4(s, 8)
        val s3 = load_4(s, 12)
        val s4 = load_4(s, 16)
        val s5 = load_4(s, 20)
        val s6 = load_4(s, 24)
        val s7 = load_4(s, 28)
        return ((signum(1559614444 - s0)
                + (signum(1477600026 - s1) shl 1)
                + (signum(2734136534 - s2) shl 2)
                + (signum(350157278 - s3) shl 3)
                + (signum(-s4) shl 4)
                + (signum(-s5) shl 5)
                + (signum(-s6) shl 6)
                + (signum(268435456 - s7) shl 7))
                shr 8) != 0L
    }


    companion object {

        internal fun load_3(`in`: ByteArray, offset: Int): Int {
            var offset1 = offset
            var result = `in`[offset1++].toInt() and 0xff
            result = result or (`in`[offset1++].toInt() and 0xff shl 8)
            result = result or (`in`[offset1].toInt() and 0xff shl 16)
            return result
        }

        internal fun load_4(`in`: ByteArray, offset: Int): Long {
            var offset1 = offset
            var result = `in`[offset1++].toInt() and 0xff
            result = result or (`in`[offset1++].toInt() and 0xff shl 8)
            result = result or (`in`[offset1++].toInt() and 0xff shl 16)
            result = result or (`in`[offset1].toInt() shl 24)
            return result.toLong() and 0xffffffffL
        }
    }

}
