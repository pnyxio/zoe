package io.pnyx.keddsa.math.ed25519


import io.pnyx.keddsa.math.*
import io.pnyx.keddsa.math.ed22519.Ed25519FieldElement
import org.hamcrest.core.IsEqual
import org.junit.*

import java.math.BigInteger
import java.security.SecureRandom
import kotlin.experimental.and


class Ed25519LittleEndianEncodingTest {

    @Test
    fun encodeReturnsCorrectByteArrayForSimpleFieldElements() {
        // Arrange:
        val t1 = IntArray(10)
        val t2 = IntArray(10)
        t2[0] = 1
        val fieldElement1 = Ed25519FieldElement(MathUtils.field, t1)
        val fieldElement2 = Ed25519FieldElement(MathUtils.field, t2)

        // Act:
        val bytes1 = MathUtils.field.getEncoding().encode(fieldElement1)
        val bytes2 = MathUtils.field.getEncoding().encode(fieldElement2)

        // Assert:
        Assert.assertThat(bytes1, IsEqual.equalTo(MathUtils.toByteArray(BigInteger.ZERO)))
        Assert.assertThat(bytes2, IsEqual.equalTo(MathUtils.toByteArray(BigInteger.ONE)))
    }

    @Test
    fun encodeReturnsCorrectByteArray() {
        for (i in 0..9999) {
            // Arrange:
            val t = IntArray(10)
            for (j in 0..9) {
                t[j] = random.nextInt(1 shl 28) - (1 shl 27)
            }
            val fieldElement1 = Ed25519FieldElement(MathUtils.field, t)
            val b = MathUtils.toBigInteger(t)

            // Act:
            val bytes = MathUtils.field.getEncoding().encode(fieldElement1)

            // Assert:
            Assert.assertThat(bytes, IsEqual.equalTo(MathUtils.toByteArray(b.mod(MathUtils.q))))
        }
    }

    @Test
    fun decodeReturnsCorrectFieldElementForSimpleByteArrays() {
        // Arrange:
        val bytes1 = ByteArray(32)
        val bytes2 = ByteArray(32)
        bytes2[0] = 1

        // Act:
        val f1 = MathUtils.field.getEncoding().decode(bytes1) as Ed25519FieldElement
        val f2 = MathUtils.field.getEncoding().decode(bytes2) as Ed25519FieldElement
        val b1 = MathUtils.toBigInteger(f1.t)
        val b2 = MathUtils.toBigInteger(f2.t)

        // Assert:
        Assert.assertThat(b1, IsEqual.equalTo(BigInteger.ZERO))
        Assert.assertThat(b2, IsEqual.equalTo(BigInteger.ONE))
    }

    @Test
    fun decodeReturnsCorrectFieldElement() {
        for (i in 0..9999) {
            // Arrange:
            val bytes = ByteArray(32)
            random.nextBytes(bytes)
            bytes[31] = (bytes[31].toUByte() and 0x7f.toUByte()).toByte()
            val b1 = MathUtils.toBigInteger(bytes)

            // Act:
            val f = MathUtils.field.getEncoding().decode(bytes) as Ed25519FieldElement
            val b2 = MathUtils.toBigInteger(f.t).mod(MathUtils.q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1))
        }
    }

    @Test
    fun isNegativeReturnsCorrectResult() {
        for (i in 0..9999) {
            // Arrange:
            val t = IntArray(10)
            for (j in 0..9) {
                t[j] = random.nextInt(1 shl 28) - (1 shl 27)
            }
            val isNegative = MathUtils.toBigInteger(t).mod(MathUtils.q).mod(BigInteger("2")).equals(BigInteger.ONE)
            val f = Ed25519FieldElement(MathUtils.field, t)

            // Assert:
            Assert.assertThat(MathUtils.field.getEncoding().isNegative(f), IsEqual.equalTo(isNegative))
        }
    }

    companion object {

        private val random = SecureRandom()
    }
}
