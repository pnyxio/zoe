package io.pnyx.zoe.hash

import io.pnyx.zoe.bytes.hexDec
import io.pnyx.zoe.bytes.hexEnc
import kotlin.test.Test
import kotlin.test.assertEquals

class Sha512DigestTest {

    @Test
    fun digestEmptyString() {
        val d = SHA512Digest()
        d.update(ByteArray(0), 0, 0)
        val res = ByteArray(64)
        d.doFinal(res, 0)
        assertEquals("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", res.hexEnc())
    }

    @Test
    fun digestAsciiAbc() {
        val d = SHA512Digest()
        d.update("616263".hexDec(), 0, 3)
        val res = ByteArray(64)
        d.doFinal(res, 0)
        assertEquals("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", res.hexEnc())
    }

}