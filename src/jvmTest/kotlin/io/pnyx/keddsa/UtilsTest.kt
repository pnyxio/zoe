package io.pnyx.keddsa

import io.pnyx.keddsa.Utils
import org.hamcrest.core.IsEqual
import org.junit.*

import java.security.SecureRandom

import org.hamcrest.CoreMatchers.`is`
import org.junit.Assert.assertThat
import kotlin.experimental.xor

class UtilsTest {

    /**
     */
    @Test
    fun testIntEqual() {
        assertThat(Utils.equal(0, 0), `is`(1))
        assertThat(Utils.equal(1, 1), `is`(1))
        assertThat(Utils.equal(1, 0), `is`(0))
        assertThat(Utils.equal(1, 127), `is`(0))
        assertThat(Utils.equal(-127, 127), `is`(0))
        assertThat(Utils.equal(-42, -42), `is`(1))
        assertThat(Utils.equal(255, 255), `is`(1))
        assertThat(Utils.equal(-255, -256), `is`(0))
    }

    @Test
    fun equalsReturnsOneForEqualByteArrays() {
        val random = SecureRandom()
        val bytes1 = ByteArray(32)
        val bytes2 = ByteArray(32)
        for (i in 0..99) {
            random.nextBytes(bytes1)
            System.arraycopy(bytes1, 0, bytes2, 0, 32)
            Assert.assertThat(Utils.equal(bytes1, bytes2), IsEqual.equalTo(1))
        }
    }

    @Test
    fun equalsReturnsZeroForUnequalByteArrays() {
        val random = SecureRandom()
        val bytes1 = ByteArray(32)
        val bytes2 = ByteArray(32)
        random.nextBytes(bytes1)
        for (i in 0..31) {
            System.arraycopy(bytes1, 0, bytes2, 0, 32)
            bytes2[i] = (bytes2[i] xor 0xff.toByte()).toByte()//TODO miki (byte)(bytes2[i] ^ 0xff);
            Assert.assertThat(Utils.equal(bytes1, bytes2), IsEqual.equalTo(0))
        }
    }

    /**
     */
    @Test
    fun testByteArrayEqual() {
        val zero = ByteArray(32)
        val one = ByteArray(32)
        one[0] = 1

        assertThat(Utils.equal(zero, zero), `is`(1))
        assertThat(Utils.equal(one, one), `is`(1))
        assertThat(Utils.equal(one, zero), `is`(0))
        assertThat(Utils.equal(zero, one), `is`(0))
    }

    /**
     */
    @Test
    fun testNegative() {
        assertThat(Utils.negative(0), `is`(0))
        assertThat(Utils.negative(1), `is`(0))
        assertThat(Utils.negative(-1), `is`(1))
        assertThat(Utils.negative(32), `is`(0))
        assertThat(Utils.negative(-100), `is`(1))
        assertThat(Utils.negative(127), `is`(0))
        assertThat(Utils.negative(-255), `is`(1))
    }

    /**
     */
    @Test
    fun testBit() {
        assertThat(Utils.bit(byteArrayOf(0), 0), `is`(0))
        assertThat(Utils.bit(byteArrayOf(8), 3), `is`(1))
        assertThat(Utils.bit(byteArrayOf(1, 2, 3), 9), `is`(1))
        assertThat(Utils.bit(byteArrayOf(1, 2, 3), 15), `is`(0))
        assertThat(Utils.bit(byteArrayOf(1, 2, 3), 16), `is`(1))
    }

    @Test
    fun hexToBytesReturnsCorrectByteArray() {
        Assert.assertThat(Utils.hexToBytes(hex1), IsEqual.equalTo(bytes1))
        Assert.assertThat(Utils.hexToBytes(hex2), IsEqual.equalTo(bytes2))
        Assert.assertThat(Utils.hexToBytes(hex3), IsEqual.equalTo(bytes3))
    }

    @Test
    fun bytesToHexReturnsCorrectHexString() {
        Assert.assertThat(Utils.bytesToHex(bytes1), IsEqual.equalTo(hex1))
        Assert.assertThat(Utils.bytesToHex(bytes2), IsEqual.equalTo(hex2))
        Assert.assertThat(Utils.bytesToHex(bytes3), IsEqual.equalTo(hex3))
    }

    companion object {
        private val hex1 = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        private val hex2 = "47a3f5b71494bcd961f3a4e859a238d6eaf8e648746d2f56a89b5e236f98d45f"
        private val hex3 = "5fd396e4a2b5dc9078f57e3ab5a87c28fd128e5f78cc4a97f4122dc45f6e4bb9"
        private val bytes1 = byteArrayOf(
            59,
            106,
            39,
            -68,
            -50,
            -74,
            -92,
            45,
            98,
            -93,
            -88,
            -48,
            42,
            111,
            13,
            115,
            101,
            50,
            21,
            119,
            29,
            -30,
            67,
            -90,
            58,
            -64,
            72,
            -95,
            -117,
            89,
            -38,
            41
        )
        private val bytes2 = byteArrayOf(
            71,
            -93,
            -11,
            -73,
            20,
            -108,
            -68,
            -39,
            97,
            -13,
            -92,
            -24,
            89,
            -94,
            56,
            -42,
            -22,
            -8,
            -26,
            72,
            116,
            109,
            47,
            86,
            -88,
            -101,
            94,
            35,
            111,
            -104,
            -44,
            95
        )
        private val bytes3 = byteArrayOf(
            95,
            -45,
            -106,
            -28,
            -94,
            -75,
            -36,
            -112,
            120,
            -11,
            126,
            58,
            -75,
            -88,
            124,
            40,
            -3,
            18,
            -114,
            95,
            120,
            -52,
            74,
            -105,
            -12,
            18,
            45,
            -60,
            95,
            110,
            75,
            -71
        )
    }
}
