package io.pnyx.zoe.hash

import io.pnyx.zoe.bytes.hexDec
import io.pnyx.zoe.bytes.hexEnc
import kotlin.test.Test
import kotlin.test.assertEquals

class Sha256Test {
    @Test
    fun digestEmptyString2() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            HashingAlgo.SHA_256.factory.getInstance()(ByteArray(0)).hexEnc())
    }

    @Test
    fun digestAsciiAbc2() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            HashingAlgo.SHA_256.factory.getInstance()("616263".hexDec()).hexEnc())
    }

}