package io.pnyx.zoe.bytes


actual object Hex : TextCodec {
    actual override fun encode(bytes: ByteArray) = HexImpl.encode(bytes)

    actual override fun decode(encoded: String) = HexImpl.decode(encoded)
}
