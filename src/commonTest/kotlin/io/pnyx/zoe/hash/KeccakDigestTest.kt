package io.pnyx.zoe.hash

import io.pnyx.zoe.bytes.hexDec
import io.pnyx.zoe.bytes.hexEnc
import kotlin.test.Test
import kotlin.test.assertEquals

class KeccakDigestTest {

    @Test
    fun digestEmptyString() {
        val d = KeccakDigest(256)
        d.update(ByteArray(0), 0, 0)
        val res = ByteArray(32)
        d.doFinal(res, 0)
        assertEquals("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", res.hexEnc())
    }

    @Test
    fun digestAsciiAbc() {
        val d = KeccakDigest(256)
        d.update("616263".hexDec(), 0, 3)
        val res = ByteArray(32)
        d.doFinal(res, 0)
        assertEquals("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", res.hexEnc())
    }

}