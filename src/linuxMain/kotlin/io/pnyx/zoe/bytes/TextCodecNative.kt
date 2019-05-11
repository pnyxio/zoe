package io.pnyx.zoe.bytes

actual object Hex : TextCodec {
    actual override fun encode(bytes: ByteArray): String = HexImpl.encode(bytes)

    actual override fun decode(encoded: String): ByteArray = HexImpl.decode(encoded)

}