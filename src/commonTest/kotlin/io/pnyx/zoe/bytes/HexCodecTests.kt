package io.pnyx.zoe.bytes


import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

class HexCodecTests {

    @Test
    fun hexByteArrayConversion() {
        val barr = byteArrayOf(0x0F, 0xAA.toByte())
        assertEquals("0faa", barr.hexEnc())
        assertTrue {
            barr contentEquals "0faa".hexDec()
            ubyteArrayOf(0x0F.toUByte()) contentEquals "0f".hexDec().asUByteArray()
        }
    }

    @Test
    fun illFormedHexStrings() {
        try {
            "0x".hexDec()
            fail()
        } catch (e: IllegalArgumentException) {}
        try {
            "zz".hexDec()
            fail()
        } catch (e: IllegalArgumentException) {}
        try {
            "9".hexDec()
            fail()
        } catch (e: IllegalArgumentException) {}
    }

}