package io.pnyx.zoe.bytes

/**
 * A variable-length encoded unsigned integer using Satoshi's encoding (a.k.a. "CompactSize").
 */
class BtcVarInt {
    val value: Long
    /**
     * Returns the original number of bytes used to encode the value if it was
     * deserialized from a byte array, or the minimum encoded size if it was not.
     */
    val originalSizeInBytes: Int

    /**
     * Returns the minimum encoded size of the value.
     */
    val sizeInBytes: Int
        get() = sizeOf(value)

    /**
     * Constructs a new BtcVarInt with the given unsigned long value.
     *
     * @param value the unsigned long value (beware widening conversion of negatives!)
     */
    constructor(value: Long) {
        this.value = value
        originalSizeInBytes = sizeInBytes
    }

    /**
     * Constructs a new BtcVarInt with the value parsed from the specified offset of the given buffer.
     *
     * @param buf the buffer containing the value
     * @param offset the offset of the value
     */
    constructor(buf: ByteArray, offset: Int) {
        val first = 0xFF and buf[offset].toInt()
        if (first < 253) {
            value = first.toLong()
            originalSizeInBytes = 1 // 1 data byte (8 bits)
        } else if (first == 253) {
            value = (0xFF.toInt() and buf[offset + 1].toInt() or (0xFF.toInt() and buf[offset + 2].toInt() shl 8)).toLong()
            originalSizeInBytes = 3 // 1 marker + 2 data bytes (16 bits)
        } else if (first == 254) {
            value = readUint32(buf, offset + 1)
            originalSizeInBytes = 5 // 1 marker + 4 data bytes (32 bits)
        } else {
            value = readInt64(buf, offset + 1)
            originalSizeInBytes = 9 // 1 marker + 8 data bytes (64 bits)
        }
    }

    /**
     * Encodes the value into its minimal representation.
     *
     * @return the minimal encoded bytes of the value
     */
    fun encode(): ByteArray {
        val bytes: ByteArray
        when (sizeOf(value)) {
            1 -> return byteArrayOf(value.toByte())
            3 -> return byteArrayOf(253.toByte(), value.toByte(), (value shr 8).toByte())
            5 -> {
                bytes = ByteArray(5)
                bytes[0] = 254.toByte()
                uint32ToByteArrayLE(value, bytes, 1)
                return bytes
            }
            else -> {
                bytes = ByteArray(9)
                bytes[0] = 255.toByte()
                uint64ToByteArrayLE(value, bytes, 1)
                return bytes
            }
        }
    }

    companion object {

        /**
         * Returns the minimum encoded size of the given unsigned long value.
         *
         * @param value the unsigned long value (beware widening conversion of negatives!)
         */
        fun sizeOf(value: Long): Int {
            // if negative, it's actually a very large unsigned long value
            if (value < 0) return 9 // 1 marker + 8 data bytes
            if (value < 253) return 1 // 1 data byte
            if (value <= 0xFFFFL) return 3 // 1 marker + 2 data bytes
            return if (value <= 0xFFFFFFFFL) 5 else 9 // 1 marker + 4 data bytes
// 1 marker + 8 data bytes
        }

        /** Parse 4 bytes from the byte array (starting at the offset) as unsigned 32-bit integer in little endian format.  */
        fun readUint32(bytes: ByteArray, offset: Int): Long {
            return bytes[offset].toLong() and 0xffL or
                    ((bytes[offset + 1].toLong() and 0xffL) shl 8) or
                    (bytes[offset + 2].toLong() and 0xffL shl 16) or
                    (bytes[offset + 3].toLong() and 0xffL shl 24)
        }

        /** Parse 8 bytes from the byte array (starting at the offset) as signed 64-bit integer in little endian format.  */
        fun readInt64(bytes: ByteArray, offset: Int): Long {
            return bytes[offset].toLong() and 0xffL or
                    (bytes[offset + 1].toLong() and 0xffL shl 8) or
                    (bytes[offset + 2].toLong() and 0xffL shl 16) or
                    (bytes[offset + 3].toLong() and 0xffL shl 24) or
                    (bytes[offset + 4].toLong() and 0xffL shl 32) or
                    (bytes[offset + 5].toLong() and 0xffL shl 40) or
                    (bytes[offset + 6].toLong() and 0xffL shl 48) or
                    (bytes[offset + 7].toLong() and 0xffL shl 56)
        }

        fun uint32ToByteArrayLE(v: Long, out: ByteArray, offset: Int) {
            out[offset] = (0xFF.toLong() and v).toByte()
            out[offset + 1] = (0xFF.toLong() and (v shr 8)).toByte()
            out[offset + 2] = (0xFF.toLong() and (v shr 16)).toByte()
            out[offset + 3] = (0xFF.toLong() and (v shr 24)).toByte()
        }

        fun uint64ToByteArrayLE(v: Long, out: ByteArray, offset: Int) {
            out[offset] = (0xFF.toLong() and v).toByte()
            out[offset + 1] = (0xFF.toLong() and (v shr 8)).toByte()
            out[offset + 2] = (0xFF.toLong() and (v shr 16)).toByte()
            out[offset + 3] = (0xFF.toLong() and (v shr 24)).toByte()
            out[offset + 4] = (0xFF.toLong() and (v shr 32)).toByte()
            out[offset + 5] = (0xFF.toLong() and (v shr 40)).toByte()
            out[offset + 6] = (0xFF.toLong() and (v shr 48)).toByte()
            out[offset + 7] = (0xFF.toLong() and (v shr 56)).toByte()
        }

    }

}
