package io.pnyx.keddsa.spec


import org.hamcrest.CoreMatchers.*
import org.junit.Assert.*

import io.pnyx.keddsa.Utils

import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException

class EdDSAPrivateKeySpecTest {

    @get:Rule
    var exception = ExpectedException.none()

    @Test
    fun testEdDSAPrivateKeySpecFromSeed() {
        val key = EdDSAPrivateKeySpec(ZERO_SEED, ed25519!!)
        assertThat(key.seed, `is`(equalTo(ZERO_SEED)))
        assertThat(key.h, `is`(equalTo(ZERO_H)))
        assertThat(key.getA().toByteArray(), `is`(equalTo(ZERO_PK)))
    }

    @Test
    fun incorrectSeedLengthThrows() {
        exception.expect(IllegalArgumentException::class.java)
        exception.expectMessage("seed length is wrong")
        EdDSAPrivateKeySpec(ByteArray(2), ed25519!!)
    }

    @Test
    fun testEdDSAPrivateKeySpecFromH() {
        val key = EdDSAPrivateKeySpec(ed25519!!, ZERO_H)
        assertThat(key.seed, `is`(nullValue()))
        assertThat(key.h, `is`(equalTo(ZERO_H)))
        assertThat(key.getA().toByteArray(), `is`(equalTo(ZERO_PK)))
    }

    @Test
    fun incorrectHashLengthThrows() {
        exception.expect(IllegalArgumentException::class.java)
        exception.expectMessage("hash length is wrong")
        EdDSAPrivateKeySpec(ed25519!!, ByteArray(2))
    }

    companion object {
        internal val ZERO_SEED =
            Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
        internal val ZERO_H =
            Utils.hexToBytes("5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f1960a6a85eaa642dac835424b5d7c8d637c00408c7a73da672b7f498521420b6dd3")
        internal val ZERO_PK =
            Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")

        internal val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
    }
}
