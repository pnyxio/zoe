package io.pnyx.zoe.bytes


import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

class AsciiCodecTests {

    @Test
    fun asciiByteArrayConversion() {
        assertEquals(" @~", byteArrayOf(32, 64, 126).asciiEnc())
        assertTrue {
            byteArrayOf(32, 64, 126) contentEquals " @~".asciiDec()
        }
    }

    @Test
    fun illFormedStrings() {
        try {
            "è".asciiDec()
            fail()
        } catch (e: IllegalArgumentException) {}
        try {
            byteArrayOf(1).asciiEnc()
            fail()
        } catch (e: IllegalArgumentException) {}
    }

}