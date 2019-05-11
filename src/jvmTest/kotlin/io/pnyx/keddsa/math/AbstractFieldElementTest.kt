package io.pnyx.keddsa.math


import org.hamcrest.core.*
import org.junit.*

import java.math.BigInteger


abstract class AbstractFieldElementTest {

    protected abstract val randomFieldElement: FieldElement
    protected abstract val q: BigInteger
    protected abstract val field: Field

    // region isNonZero

    protected abstract val zeroFieldElement: FieldElement
    protected abstract val nonZeroFieldElement: FieldElement
    protected abstract fun toBigInteger(f: FieldElement): BigInteger

    @Test
    fun isNonZeroReturnsFalseIfFieldElementIsZero() {
        // Act:
        val f = zeroFieldElement

        // Assert:
        Assert.assertThat(f.isNonZero, IsEqual.equalTo(false))
    }

    @Test
    fun isNonZeroReturnsTrueIfFieldElementIsNonZero() {
        // Act:
        val f = nonZeroFieldElement

        // Assert:
        Assert.assertThat(f.isNonZero, IsEqual.equalTo(true))
    }

    // endregion

    // region mod q arithmetic

    @Test
    fun addReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val f2 = randomFieldElement
            val b1 = toBigInteger(f1)
            val b2 = toBigInteger(f2)

            // Act:
            val f3 = f1.add(f2)
            val b3 = toBigInteger(f3).mod(q)

            // Assert:
            Assert.assertThat(b3, IsEqual.equalTo(b1.add(b2).mod(q)))
        }
    }

    @Test
    fun subtractReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val f2 = randomFieldElement
            val b1 = toBigInteger(f1)
            val b2 = toBigInteger(f2)

            // Act:
            val f3 = f1.subtract(f2)
            val b3 = toBigInteger(f3).mod(q)

            // Assert:
            Assert.assertThat(b3, IsEqual.equalTo(b1.subtract(b2).mod(q)))
        }
    }

    @Test
    fun negateReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val b1 = toBigInteger(f1)

            // Act:
            val f2 = f1.negate()
            val b2 = toBigInteger(f2).mod(q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.negate().mod(q)))
        }
    }

    @Test
    fun multiplyReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val f2 = randomFieldElement
            val b1 = toBigInteger(f1)
            val b2 = toBigInteger(f2)

            // Act:
            val f3 = f1.multiply(f2)
            val b3 = toBigInteger(f3).mod(q)

            // Assert:
            Assert.assertThat(b3, IsEqual.equalTo(b1.multiply(b2).mod(q)))
        }
    }

    @Test
    fun squareReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val b1 = toBigInteger(f1)

            // Act:
            val f2 = f1.square()
            val b2 = toBigInteger(f2).mod(q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.multiply(b1).mod(q)))
        }
    }

    @Test
    fun squareAndDoubleReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val b1 = toBigInteger(f1)

            // Act:
            val f2 = f1.squareAndDouble()
            val b2 = toBigInteger(f2).mod(q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.multiply(b1).multiply(BigInteger("2")).mod(q)))
        }
    }

    @Test
    fun invertReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val b1 = toBigInteger(f1)

            // Act:
            val f2 = f1.invert()
            val b2 = toBigInteger(f2).mod(q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.modInverse(q)))
        }
    }

    @Test
    fun pow22523ReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val b1 = toBigInteger(f1)

            // Act:
            val f2 = f1.pow22523()
            val b2 = toBigInteger(f2).mod(q)

            // Assert:
            Assert.assertThat(
                b2,
                IsEqual.equalTo(b1.modPow(BigInteger.ONE.shiftLeft(252).subtract(BigInteger("3")), q))
            )
        }
    }

    // endregion

    // region cmov

    @Test
    fun cmovReturnsCorrectResult() {
        val zero = zeroFieldElement
        val nz = nonZeroFieldElement
        val f = randomFieldElement

        Assert.assertThat(zero.cmov(nz, 0), IsEqual.equalTo<Any>(zero))
        Assert.assertThat(zero.cmov(nz, 1), IsEqual.equalTo<Any>(nz))

        Assert.assertThat(f.cmov(nz, 0), IsEqual.equalTo<Any>(f))
        Assert.assertThat(f.cmov(nz, 1), IsEqual.equalTo<Any>(nz))
    }

    // endregion

    // region hashCode / equals

    @Test
    fun equalsOnlyReturnsTrueForEquivalentObjects() {
        // Arrange:
        val f1 = randomFieldElement
        val f2 = field.getEncoding().decode(f1.toByteArray())
        val f3 = randomFieldElement
        val f4 = randomFieldElement

        // Assert:
        Assert.assertThat<Any>(f1, IsEqual.equalTo(f2))
        Assert.assertThat<Any>(f1, IsNot.not(IsEqual.equalTo<Any>(f3)))
        Assert.assertThat<Any>(f1, IsNot.not(IsEqual.equalTo<Any>(f4)))
        Assert.assertThat<Any>(f3, IsNot.not(IsEqual.equalTo<Any>(f4)))
    }

    @Test
    fun hashCodesAreEqualForEquivalentObjects() {
        // Arrange:
        val f1 = randomFieldElement
        val f2 = field.getEncoding().decode(f1.toByteArray())
        val f3 = randomFieldElement
        val f4 = randomFieldElement

        // Assert:
        Assert.assertThat(f1.hashCode(), IsEqual.equalTo(f2.hashCode()))
        Assert.assertThat(f1.hashCode(), IsNot.not(IsEqual.equalTo(f3.hashCode())))
        Assert.assertThat(f1.hashCode(), IsNot.not(IsEqual.equalTo(f4.hashCode())))
        Assert.assertThat(f3.hashCode(), IsNot.not(IsEqual.equalTo(f4.hashCode())))
    }

    // endregion
}
