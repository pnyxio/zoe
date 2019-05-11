package io.pnyx.zoe.bytes

import io.pnyx.zoe.hash.HashingAlgo


object Base58 {
    private val ALPHABET = charArrayOf('1','2','3','4','5','6','7','8','9','A','B','C','D','E','F','G','H','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
    private val ENCODED_ZERO = ALPHABET[0]
    private val INDEXES = IntArray(128) {-1}

    init {
        for (i in ALPHABET.indices) {
            INDEXES[ALPHABET[i].toInt()] = i
        }
    }

    /**
     * Encodes the given bytes as a base58 string (no checksum is appended).
     *
     * @param input the bytes to encode
     * @return the base58-encoded string
     */
    fun encode(input: ByteArray): String {
        var barr = input
        if (barr.size == 0) {
            return ""
        }
        // Count leading zeros.
        var zeros = 0
        while (zeros < barr.size && barr[zeros].toInt() == 0) {
            ++zeros
        }
        // Convert base-256 digits to base-58 digits (plus conversion to ASCII characters)
        barr = barr.copyOf(barr.size) // since we modify it in-place
        val encoded = CharArray(barr.size * 2) // upper bound
        var outputStart = encoded.size
        var inputStart = zeros
        while (inputStart < barr.size) {
            encoded[--outputStart] = ALPHABET[divmod(
                barr,
                inputStart,
                256,
                58
            ).toInt()]
            if (barr[inputStart].toInt() == 0) {
                ++inputStart // optimization - skip leading zeros
            }
        }
        // Preserve exactly as many leading encoded zeros in output as there were leading zeros in input.
        while (outputStart < encoded.size && encoded[outputStart] == ENCODED_ZERO) {
            ++outputStart
        }
        while (--zeros >= 0) {
            encoded[--outputStart] = ENCODED_ZERO
        }
        // Return encoded string (including encoded leading zeros).
        return String(encoded, outputStart, encoded.size - outputStart)
    }

    /**
     * Encodes the given version and bytes as a base58 string. A checksum is appended.
     *
     * @param version the version to encode
     * @param payload the bytes to encode, e.g. pubkey hash
     * @return the base58-encoded string
     */
    fun encodeChecked(version: Int, payload: ByteArray): String {
        if (version < 0 || version > 255)
            throw IllegalArgumentException("Version not in range.")

        // A stringified buffer is:
        // 1 byte version + data bytes + 4 bytes check code (a truncated hash)
        val addressBytes = ByteArray(1 + payload.size + 4)
        addressBytes[0] = version.toByte()
        payload.copyInto(addressBytes, destinationOffset = 1)
        val checksum = sha256HashHashTwice(addressBytes, 0, payload.size + 1)
        checksum.copyInto(addressBytes, destinationOffset = payload.size + 1, endIndex = 4)
        return encode(addressBytes)
    }

    /**
     * Decodes the given base58 string into the original data bytes.
     *
     * @param input the base58-encoded string to decode
     * @return the decoded data bytes
     * @throws AddressFormatException if the given string is not a valid base58 string
     */
    fun decode(input: String): ByteArray {
        if (input.length == 0) {
            return ByteArray(0)
        }
        // Convert the base58-encoded ASCII chars to a base58 byte sequence (base58 digits).
        val input58 = ByteArray(input.length)
        for (i in 0 until input.length) {
            val c = input[i]
            val digit = if (c.toInt() < 128) INDEXES[c.toInt()] else -1
            if (digit < 0) {
                throw IllegalArgumentException("AddressFormatException.InvalidCharacter($c, $i)")
            }
            input58[i] = digit.toByte()
        }
        // Count leading zeros.
        var zeros = 0
        while (zeros < input58.size && input58[zeros].toInt() == 0) {
            ++zeros
        }
        // Convert base-58 digits to base-256 digits.
        val decoded = ByteArray(input.length)
        var outputStart = decoded.size
        var inputStart = zeros
        while (inputStart < input58.size) {
            decoded[--outputStart] = divmod(input58, inputStart, 58, 256)
            if (input58[inputStart].toInt() == 0) {
                ++inputStart // optimization - skip leading zeros
            }
        }
        // Ignore extra leading zeroes that were added during the calculation.
        while (outputStart < decoded.size && decoded[outputStart].toInt() == 0) {
            ++outputStart
        }
        // Return decoded data (including original number of leading zeros).
        return decoded.copyOfRange(outputStart - zeros, decoded.size)
    }

    /**
     * Decodes the given base58 string into the original data bytes, using the checksum in the
     * last 4 bytes of the decoded data to verify that the rest are correct. The checksum is
     * removed from the returned data.
     *
     * @param input the base58-encoded string to decode (which should include the checksum)
     * @throws AddressFormatException if the input is not base 58 or the checksum does not validate.
     */
    fun decodeChecked(input: String): ByteArray {
        val decoded = decode(input)
        if (decoded.size < 4)
            throw IllegalArgumentException("AddressFormatException InvalidDataLength Input too short: " + decoded.size)
        val data = decoded.copyOfRange(0, decoded.size - 4)
        val checksum = decoded.copyOfRange(decoded.size - 4, decoded.size)
        val actualChecksum = sha256HashHashTwice(data).copyOfRange(0, 4)
        if (!byteArrayEquals(checksum, actualChecksum))
            throw IllegalArgumentException("AddressFormatException.InvalidChecksum")
        return data
    }

    private val sha256 get() = HashingAlgo.SHA_256.factory.getInstance()
    private fun sha256HashHashTwice(data: ByteArray) =
        sha256(sha256(data))


    private fun sha256HashHashTwice(data: ByteArray, start: Int, size: Int) =
        sha256(sha256(data.copyOfRange(start, start + size)))

    /**
     * Divides a number, represented as an array of bytes each containing a single digit
     * in the specified base, by the given divisor. The given number is modified in-place
     * to contain the quotient, and the return value is the remainder.
     *
     * @param number the number to divide
     * @param firstDigit the index within the array of the first non-zero digit
     * (this is used for optimization by skipping the leading zeros)
     * @param base the base in which the number's digits are represented (up to 256)
     * @param divisor the number to divide by (up to 256)
     * @return the remainder of the division operation
     */
    private fun divmod(number: ByteArray, firstDigit: Int, base: Int, divisor: Int): Byte {
        // this is just long division which accounts for the base of the input digits
        var remainder = 0
        for (i in firstDigit until number.size) {
            val digit = number[i].toInt() and 0xFF
            val temp = remainder * base + digit
            number[i] = (temp / divisor).toByte()
            remainder = temp % divisor
        }
        return remainder.toByte()
    }
}
