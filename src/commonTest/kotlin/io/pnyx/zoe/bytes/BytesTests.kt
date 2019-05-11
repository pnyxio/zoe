package io.pnyx.zoe.bytes

import kotlin.test.Test
import kotlin.test.assertEquals

class BytesTests {

    @Test
    fun inlineUbytes() {
        val w = Wrapz(ByteArray(1) { -1 })
        val b: UByteArray = w.ubytes
        assertEquals(255, b[0].toInt())
        val iw = InlWrapz(ByteArray(1) { -1 })
        assertEquals(255, iw.ubytes[0].toInt())

    }
}

class Wrapz(bytes: ByteArray): BytesWrap(bytes)
inline class InlWrapz(override val bytes: ByteArray): Bytes

