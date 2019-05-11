package io.pnyx.zoe.hash

import io.pnyx.zoe.bytes.hexDec
import io.pnyx.zoe.bytes.hexEnc
import kotlin.test.Test
import kotlin.test.assertEquals

class Sha256DigestTest {

    @Test
    fun digestEmptyString() {
        val d = SHA256Digest()
        d.update(ByteArray(0), 0, 0)
        val res = ByteArray(32)
        d.doFinal(res, 0)
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", res.hexEnc())
    }

    @Test
    fun digestAsciiAbc() {
        val d = SHA256Digest()
        d.update("616263".hexDec(), 0, 3)
        val res = ByteArray(32)
        d.doFinal(res, 0)
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", res.hexEnc())
    }

}