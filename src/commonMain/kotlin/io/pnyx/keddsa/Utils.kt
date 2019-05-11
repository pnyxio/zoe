package io.pnyx.keddsa

import kotlin.experimental.xor

object Utils {

    /**
     * Constant-time byte comparison.
     * @param b a byte
     * @param c a byte
     * @return 1 if b and c are equal, 0 otherwise.
     */
    fun equal(b: Int, c: Int): Int {
        var result = 0
        val xor = b xor c
        for (i in 0..7) {
            result = result or (xor shr i)
        }
        return result xor 0x01 and 0x01
    }

    /**
     * Constant-time byte[] comparison.
     * @param b a byte[]
     * @param c a byte[]
     * @return 1 if b and c are equal, 0 otherwise.
     */
    fun equal(b: ByteArray, c: ByteArray): Int {
        var result = 0
        for (i in 0..31) {
            result = result or ((b[i] xor c[i]).toInt())
        }

        return equal(result, 0)
    }

    /**
     * Constant-time determine if byte is negative.
     * @param b the byte to check.
     * @return 1 if the byte is negative, 0 otherwise.
     */
    fun negative(b: Int): Int {
        return b shr 8 and 1
    }

    /**
     * Get the i'th bit of a byte array.
     * @param h the byte array.
     * @param i the bit index.
     * @return 0 or 1, the value of the i'th bit in h
     */
    fun bit(h: ByteArray, i: Int): Int {
        return h[i shr/*miki*/ 3].toInt() shr (i and 7).toInt() and 1
    }

    /**
     * Converts a hex string to bytes.
     * @param s the hex string to be converted.
     * @return the byte[]
     */
    fun hexToBytes(s: String): ByteArray {
        val result = ByteArray(s.length / 2)

        for (i in 0 until s.length step 2) {
            val firstIndex = hexArray.indexOf(s[i].toLowerCase());
            val secondIndex = hexArray.indexOf(s[i + 1].toLowerCase());

            val octet = firstIndex.shl(4).or(secondIndex)
            result.set(i.shr(1), octet.toByte())
        }

        return result
    }

    /**
     * Converts bytes to a hex string.
     * @param raw the byte[] to be converted.
     * @return the hex representation as a string.
     */
    private val hexArray = "0123456789abcdef".toList()
    fun bytesToHex(raw: ByteArray?): String? {
        if (raw == null) {
            return null
        }
        val chars = CharArray(raw.size * 2)
        for (j in raw.indices) {
            val x = raw[j].toInt() and 0xFF
            chars[j * 2] = hexArray[x ushr 4]
            chars[j * 2 + 1] = hexArray[x and 0x0F]
        }
        return String(chars)
    }

    fun ByteArray.contentHashCode(): Int {
            var result = 1
            for (element in this)
                result = 31 * result + element
            return result

    }
}
