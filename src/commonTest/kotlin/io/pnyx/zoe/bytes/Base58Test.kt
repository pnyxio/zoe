package io.pnyx.zoe.bytes

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail


class Base58Test {

    @Test
    fun testEncode() {
        val t = 's'
        t.toInt()
        val testbytes = "Hello World".asciiDec()
        assertEquals("JxF12TrwUP45BMd", Base58.encode(testbytes))

        val zeroBytes1 = ByteArray(1)
        assertEquals("1", Base58.encode(zeroBytes1))

        val zeroBytes7 = ByteArray(7)
        assertEquals("1111111", Base58.encode(zeroBytes7))

        // test empty encode
        assertEquals("", Base58.encode(ByteArray(0)))
    }

    @Test
    fun testEncodeChecked_address() {
        val encoded = Base58.encodeChecked(111, ByteArray(20))
        assertEquals("mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8", encoded)
    }

    @Test
    fun testEncodeChecked_privateKey() {
        val encoded = Base58.encodeChecked(128, ByteArray(32))
        assertEquals("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAbuatmU", encoded)
    }

    @Test
    fun testDecode() {
        val testbytes = "Hello World".asciiDec()
        val actualbytes = Base58.decode("JxF12TrwUP45BMd")
        assertTrue { byteArrayEquals(testbytes, actualbytes) }

        assertTrue { byteArrayEquals(Base58.decode("1"), ByteArray(1)) }
        assertTrue {
            byteArrayEquals(Base58.decode("1111"), ByteArray(4))
        }


        // Test decode of empty String.
        assertEquals(0, Base58.decode("").size)
    }

    fun testDecode_invalidBase58() {
        try {
            Base58.decode("This isn't valid base58")
            fail()
        } catch(e: IllegalArgumentException){}
    }

    @Test
    fun testDecodeChecked() {
        Base58.decodeChecked("4stwEBjT6FYyVV")

        // Now check we can correctly decode the case where the high bit of the first byte is not zero, so BigInteger
        // sign extends. Fix for a bug that stopped us parsing keys exported using sipas patch.
        Base58.decodeChecked("93VYUMzRG9DdbRP72uQXjaWibbQwygnvaCu9DumcqDjGybD864T")
    }

    fun decode_invalidCharacter_notInAlphabet() {
        try {
            Base58.decodeChecked("J0F12TrwUP45BMd")
            fail()
        } catch(e: IllegalArgumentException){}
    }

    fun testDecodeChecked_invalidChecksum() {
        try {
            Base58.decodeChecked("4stwEBjT6FYyVW")
            fail()
        } catch(e: IllegalArgumentException){}
    }

    fun testDecodeChecked_shortInput() {
        try {
            Base58.decodeChecked("4s")
            fail()
        } catch(e: IllegalArgumentException){}
    }

}