package io.pnyx.keddsa.math.bigint

import org.hamcrest.CoreMatchers.*
import org.junit.Assert.*

import java.math.BigInteger
import java.util.Random

import io.pnyx.keddsa.Utils
import io.pnyx.keddsa.math.*
import org.junit.Test

class BigIntegerFieldElementTest : AbstractFieldElementTest() {

    override protected val randomFieldElement: FieldElement
        get() {
            var r: BigInteger
            val rnd = Random()
            do {
                r = BigInteger(255, rnd)
            } while (r.compareTo(q) >= 0)
            return BigIntegerFieldElement(ed25519Field, r)
        }

    override protected val q: BigInteger
        get() = MathUtils.q

    override protected val field: Field
        get() = ed25519Field

    // region isNonZero

    override protected val zeroFieldElement: FieldElement
        get() = ZERO

    override protected val nonZeroFieldElement: FieldElement
        get() = TWO

    override protected fun toBigInteger(f: FieldElement): BigInteger {
        return (f as BigIntegerFieldElement).bi
    }

    /**
     * Test method for [BigIntegerFieldElement.BigIntegerFieldElement].
     */
    @Test
    fun testFieldElementBigInteger() {
        assertThat(BigIntegerFieldElement(ed25519Field, BigInteger.ZERO).bi, `is`(BigInteger.ZERO))
        assertThat(BigIntegerFieldElement(ed25519Field, BigInteger.ONE).bi, `is`(BigInteger.ONE))
        assertThat(BigIntegerFieldElement(ed25519Field, BigInteger.valueOf(2)).bi, `is`(BigInteger.valueOf(2)))
    }

    /**
     * Test method for [FieldElement.toByteArray].
     */
    @Test
    fun testToByteArray() {
        val zero = ZERO.toByteArray()
        assertThat(zero.size, `is`(equalTo(BYTES_ZERO.size)))
        assertThat(zero, `is`(equalTo(BYTES_ZERO)))

        val one = ONE.toByteArray()
        assertThat(one.size, `is`(equalTo(BYTES_ONE.size)))
        assertThat(one, `is`(equalTo(BYTES_ONE)))

        val ten = BigIntegerFieldElement(ed25519Field, BigInteger.TEN).toByteArray()
        assertThat(ten.size, `is`(equalTo(BYTES_TEN.size)))
        assertThat(ten, `is`(equalTo(BYTES_TEN)))
    }

    // endregion

    /**
     * Test method for [FieldElement.equals].
     */
    @Test
    fun testEqualsObject() {
        assertThat(BigIntegerFieldElement(ed25519Field, BigInteger.ZERO), `is`(equalTo(ZERO)))
        assertThat(
            BigIntegerFieldElement(ed25519Field, BigInteger.valueOf(1000)),
            `is`(equalTo(BigIntegerFieldElement(ed25519Field, BigInteger.valueOf(1000))))
        )
        assertThat(ONE, `is`(not(equalTo(TWO))))
    }

    companion object {
        internal val BYTES_ZERO =
            Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
        internal val BYTES_ONE =
            Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000")
        internal val BYTES_TEN =
            Utils.hexToBytes("0a00000000000000000000000000000000000000000000000000000000000000")

        internal val ed25519Field = Field(
            256, // b
            Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
            BigIntegerLittleEndianEncoding()
        )

        internal val ZERO: FieldElement = BigIntegerFieldElement(ed25519Field, BigInteger.ZERO)
        internal val ONE: FieldElement = BigIntegerFieldElement(ed25519Field, BigInteger.ONE)
        internal val TWO: FieldElement = BigIntegerFieldElement(ed25519Field, BigInteger.valueOf(2))
    }

}

