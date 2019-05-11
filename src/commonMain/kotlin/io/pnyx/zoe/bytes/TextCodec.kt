package io.pnyx.zoe.bytes

interface TextCodec {
    fun encode(bytes: ByteArray): String

    fun decode(encoded: String): ByteArray
}

fun ByteArray.hexEnc() : String = Hex.encode(this)

fun String.hexDec() : ByteArray = Hex.decode(this)

expect object Hex: TextCodec {
    override fun encode(bytes: ByteArray): String

    override fun decode(encoded: String): ByteArray
}

private val HEX_CHARS = arrayOf('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f')


object HexImpl: TextCodec {
    override fun encode(bytes: ByteArray): String {
        val result = StringBuilder()

        bytes.forEach {
            val octet = it.toInt()
            val firstIndex = (octet and 0xF0).ushr(4)
            val secondIndex = octet and 0x0F
            result.append(HEX_CHARS[firstIndex])
            result.append(HEX_CHARS[secondIndex])
        }

        return result.toString()
    }

    override fun decode(encoded: String): ByteArray {
        require(encoded.length %2 == 0)
        val result = ByteArray(encoded.length / 2)
        for (i in 0 until encoded.length step 2) {
            val firstIndex = HEX_CHARS.indexOf(encoded[i]);
            val secondIndex = HEX_CHARS.indexOf(encoded[i + 1]);
            require(firstIndex >= 0 && secondIndex >= 0)
            val octet = firstIndex.shl(4).or(secondIndex)
            result.set(i.shr(1), octet.toByte())
        }

        return result
    }

}

fun ByteArray.asciiEnc() : String = AsciiCodec.encode(this)

fun String.asciiDec() : ByteArray = AsciiCodec.decode(this)

object AsciiCodec: TextCodec {
    override fun encode(bytes: ByteArray) = CharArray(bytes.size) {
        val b = bytes[it]
        if(b > 126
            || (b < 32
                && b != '\n'.toByte()
                && b != '\r'.toByte()
                && b != '\t'.toByte()
               )
        ) {
            throw IllegalArgumentException("character ${b.toChar()} as pos $it not an ASCII printable")
        }
        b.toChar()
    }.joinToString(separator = "")

    override fun decode(encoded: String): ByteArray {
        val result = ByteArray(encoded.length)
        for (i in 0 until encoded.length) {
            val b = encoded[i].toInt()
            if(b > 126
                || (b < 32
                    && b != '\n'.toInt()
                    && b != '\r'.toInt()
                    && b != '\t'.toInt()
                    )
            ) {
                throw IllegalArgumentException("character ${encoded[i]} as pos $i not an ASCII printable")
            }
            result[i] = b.toByte()
        }
        return result
    }
}
