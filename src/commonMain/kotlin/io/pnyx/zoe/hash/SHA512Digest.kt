package io.pnyx.zoe.hash

import io.pnyx.zoe.bytes.bigEndianToLong
import io.pnyx.zoe.bytes.longToBigEndian


class SHA512Digest {
    private val xBuf = ByteArray(8)
    private var xBufOff: Int = 0

    private var byteCount1: Long = 0
    private var byteCount2: Long = 0

    private var H1: Long = 0
    private var H2:Long = 0
    private var H3:Long = 0
    private var H4:Long = 0
    private var H5:Long = 0
    private var H6:Long = 0
    private var H7:Long = 0
    private var H8:Long = 0

    private val W = LongArray(80)
    private var wOff: Int = 0

    init {
        xBufOff = 0
        reset()
    }

    fun reset() {
        byteCount1 = 0
        byteCount2 = 0

        xBufOff = 0
        for (i in xBuf.indices) {
            xBuf[i] = 0
        }

        wOff = 0
        for (i in W.indices) {
            W[i] = 0
        }
        /* SHA-512 initial hash value
         * The first 64 bits of the fractional parts of the square roots
         * of the first eight prime numbers
         */
        H1 = 0x6a09e667f3bcc908L
        H2 = -0x4498517a7b3558c5L
        H3 = 0x3c6ef372fe94f82bL
        H4 = -0x5ab00ac5a0e2c90fL
        H5 = 0x510e527fade682d1L
        H6 = -0x64fa9773d4c193e1L
        H7 = 0x1f83d9abfb41bd6bL
        H8 = 0x5be0cd19137e2179L

    }

    fun update(
        input: Byte
    ) {
        xBuf[xBufOff++] = input

        if (xBufOff == xBuf.size) {
            processWord(xBuf, 0)
            xBufOff = 0
        }

        byteCount1++
    }

    fun update(
        input: ByteArray,
        inOff: Int,
        len: Int
    ) {
        var _inOff = inOff
        var _len = len
        //
        // fill the current word
        //
        while (xBufOff != 0 && _len > 0) {
            update(input[_inOff])

            _inOff++
            _len--
        }

        //
        // process whole words.
        //
        while (_len > xBuf.size) {
            processWord(input, _inOff)

            _inOff += xBuf.size
            _len -= xBuf.size
            byteCount1 += xBuf.size.toLong()
        }

        //
        // load in the remainder.
        //
        while (_len > 0) {
            update(input[_inOff])

            _inOff++
            _len--
        }
    }

    fun doFinal(out: ByteArray, outOff: Int): Int {
        finish()

        longToBigEndian(H1, out, outOff);
        longToBigEndian(H2, out, outOff + 8)
        longToBigEndian(H3, out, outOff + 16)
        longToBigEndian(H4, out, outOff + 24)
        longToBigEndian(H5, out, outOff + 32)
        longToBigEndian(H6, out, outOff + 40)
        longToBigEndian(H7, out, outOff + 48)
        longToBigEndian(H8, out, outOff + 56)

        reset()

        return 64
    }

    fun finish() {
        adjustByteCounts()

        val lowBitLength = byteCount1 shl 3
        val hiBitLength = byteCount2

        //
        // add the pad bytes.
        //
        update(128.toByte())

        while (xBufOff != 0) {
            update(0.toByte())
        }

        processLength(lowBitLength, hiBitLength)

        processBlock()
    }

//////////////////////////////////////////////////////////////
    /**
     * adjust the byte counts so that byteCount2 represents the
     * upper long (less 3 bits) word of the byte count.
     */
    private fun adjustByteCounts() {
        if (byteCount1 > 0x1fffffffffffffffL) {
            byteCount2 += byteCount1.ushr(61)
            byteCount1 = byteCount1 and 0x1fffffffffffffffL
        }
    }
    private fun processLength(
        lowW: Long,
        hiW: Long
    ) {
        if (wOff > 14) {
            processBlock()
        }

        W[14] = hiW
        W[15] = lowW
    }

    private fun processWord(
        input: ByteArray,
        inOff: Int
    ) {
        W[wOff] = bigEndianToLong(input, inOff)

        if (++wOff == 16) {
            processBlock()
        }
    }

    private fun processBlock() {
        adjustByteCounts()

        //
        // expand 16 word block into 80 word blocks.
        //
        for (t in 16..79) {
            W[t] = Sigma1(W[t - 2]) + W[t - 7] + Sigma0(W[t - 15]) + W[t - 16]
        }

        //
        // set up working variables.
        //
        var a = H1
        var b = H2
        var c = H3
        var d = H4
        var e = H5
        var f = H6
        var g = H7
        var h = H8

        var t = 0
        for (i in 0..9) {
            // t = 8 * i
            h += Sum1(e) + Ch(e, f, g) + K[t] + W[t++]
            d += h
            h += Sum0(a) + Maj(a, b, c)

            // t = 8 * i + 1
            g += Sum1(d) + Ch(d, e, f) + K[t] + W[t++]
            c += g
            g += Sum0(h) + Maj(h, a, b)

            // t = 8 * i + 2
            f += Sum1(c) + Ch(c, d, e) + K[t] + W[t++]
            b += f
            f += Sum0(g) + Maj(g, h, a)

            // t = 8 * i + 3
            e += Sum1(b) + Ch(b, c, d) + K[t] + W[t++]
            a += e
            e += Sum0(f) + Maj(f, g, h)

            // t = 8 * i + 4
            d += Sum1(a) + Ch(a, b, c) + K[t] + W[t++]
            h += d
            d += Sum0(e) + Maj(e, f, g)

            // t = 8 * i + 5
            c += Sum1(h) + Ch(h, a, b) + K[t] + W[t++]
            g += c
            c += Sum0(d) + Maj(d, e, f)

            // t = 8 * i + 6
            b += Sum1(g) + Ch(g, h, a) + K[t] + W[t++]
            f += b
            b += Sum0(c) + Maj(c, d, e)

            // t = 8 * i + 7
            a += Sum1(f) + Ch(f, g, h) + K[t] + W[t++]
            e += a
            a += Sum0(b) + Maj(b, c, d)
        }

        H1 += a
        H2 += b
        H3 += c
        H4 += d
        H5 += e
        H6 += f
        H7 += g
        H8 += h

        //
        // reset the offset and clean out the word buffer.
        //
        wOff = 0
        for (i in 0..15) {
            W[i] = 0
        }
    }

    /* SHA-384 and SHA-512 functions (as for SHA-256 but for longs) */
    private fun Ch(
        x: Long,
        y: Long,
        z: Long
    ): Long {
        return x and y xor (x.inv() and z)
    }

    private fun Maj(
        x: Long,
        y: Long,
        z: Long
    ): Long {
        return x and y xor (x and z) xor (y and z)
    }

    private fun Sum0(
        x: Long
    ): Long {
        return x shl 36 or x.ushr(28) xor (x shl 30 or x.ushr(34)) xor (x shl 25 or x.ushr(39))
    }

    private fun Sum1(
        x: Long
    ): Long {
        return x shl 50 or x.ushr(14) xor (x shl 46 or x.ushr(18)) xor (x shl 23 or x.ushr(41))
    }

    private fun Sigma0(
        x: Long
    ): Long {
        return x shl 63 or x.ushr(1) xor (x shl 56 or x.ushr(8)) xor x.ushr(7)
    }

    private fun Sigma1(
        x: Long
    ): Long {
        return x shl 45 or x.ushr(19) xor (x shl 3 or x.ushr(61)) xor x.ushr(6)
    }

    companion object {
        internal val K = longArrayOf(
            0x428a2f98d728ae22L,
            0x7137449123ef65cdL,
            -0x4a3f043013b2c4d1L,
            -0x164a245a7e762444L,
            0x3956c25bf348b538L,
            0x59f111f1b605d019L,
            -0x6dc07d5b50e6b065L,
            -0x54e3a12a25927ee8L,
            -0x27f855675cfcfdbeL,
            0x12835b0145706fbeL,
            0x243185be4ee4b28cL,
            0x550c7dc3d5ffb4e2L,
            0x72be5d74f27b896fL,
            -0x7f214e01c4e9694fL,
            -0x6423f958da38edcbL,
            -0x3e640e8b3096d96cL,
            -0x1b64963e610eb52eL,
            -0x1041b879c7b0da1dL,
            0x0fc19dc68b8cd5b5L,
            0x240ca1cc77ac9c65L,
            0x2de92c6f592b0275L,
            0x4a7484aa6ea6e483L,
            0x5cb0a9dcbd41fbd4L,
            0x76f988da831153b5L,
            -0x67c1aead11992055L,
            -0x57ce3992d24bcdf0L,
            -0x4ffcd8376704dec1L,
            -0x40a680384110f11cL,
            -0x391ff40cc257703eL,
            -0x2a586eb86cf558dbL,
            0x06ca6351e003826fL,
            0x142929670a0e6e70L,
            0x27b70a8546d22ffcL,
            0x2e1b21385c26c926L,
            0x4d2c6dfc5ac42aedL,
            0x53380d139d95b3dfL,
            0x650a73548baf63deL,
            0x766a0abb3c77b2a8L,
            -0x7e3d36d1b812511aL,
            -0x6d8dd37aeb7dcac5L,
            -0x5d40175eb30efc9cL,
            -0x57e599b443bdcfffL,
            -0x3db4748f2f07686fL,
            -0x3893ae5cf9ab41d0L,
            -0x2e6d17e62910ade8L,
            -0x2966f9dbaa9a56f0L,
            -0xbf1ca7aa88edfd6L,
            0x106aa07032bbd1b8L,
            0x19a4c116b8d2d0c8L,
            0x1e376c085141ab53L,
            0x2748774cdf8eeb99L,
            0x34b0bcb5e19b48a8L,
            0x391c0cb3c5c95a63L,
            0x4ed8aa4ae3418acbL,
            0x5b9cca4f7763e373L,
            0x682e6ff3d6b2b8a3L,
            0x748f82ee5defb2fcL,
            0x78a5636f43172f60L,
            -0x7b3787eb5e0f548eL,
            -0x7338fdf7e59bc614L,
            -0x6f410005dc9ce1d8L,
            -0x5baf9314217d4217L,
            -0x41065c084d3986ebL,
            -0x398e870d1c8dacd5L,
            -0x35d8c13115d99e64L,
            -0x2e794738de3f3df9L,
            -0x15258229321f14e2L,
            -0xa82b08011912e88L,
            0x06f067aa72176fbaL,
            0x0a637dc5a2c898a6L,
            0x113f9804bef90daeL,
            0x1b710b35131c471bL,
            0x28db77f523047d84L,
            0x32caab7b40c72493L,
            0x3c9ebe0a15c9bebcL,
            0x431d67c49c100d4cL,
            0x4cc5d4becb3e42b6L,
            0x597f299cfc657e2aL,
            0x5fcb6fab3ad6faecL,
            0x6c44198c4a475817L
        )
    }

}