package io.pnyx.keddsa.math.ed25519


import io.pnyx.keddsa.math.*
import io.pnyx.keddsa.math.ed22519.Ed25519FieldElement
import org.hamcrest.core.*
import org.junit.*

import java.math.BigInteger


/**
 * Tests rely on the BigInteger class.
 */
class Ed25519FieldElementTest : AbstractFieldElementTest() {

    override val randomFieldElement: FieldElement
        get() = MathUtils.randomFieldElement()

    override val q: BigInteger
        get() = MathUtils.q

    override val field: Field
        get() = MathUtils.field

    // endregion

    // region isNonZero

    override val zeroFieldElement: FieldElement
        get() = Ed25519FieldElement(MathUtils.field, IntArray(10))

    override val nonZeroFieldElement: FieldElement
        get() {
            val t = IntArray(10)
            t[0] = 5
            return Ed25519FieldElement(MathUtils.field, t)
        }

    override fun toBigInteger(f: FieldElement): BigInteger {
        return MathUtils.toBigInteger(f)
    }

    // region constructor

    @Test
    fun canConstructFieldElementFromArrayWithCorrectLength() {
        // Assert:
        Ed25519FieldElement(MathUtils.field, IntArray(10))
    }

    @Test(expected = IllegalArgumentException::class)
    fun cannotConstructFieldElementFromArrayWithIncorrectLength() {
        // Assert:
        Ed25519FieldElement(MathUtils.field, IntArray(9))
    }

//    @Test(expected = IllegalArgumentException::class)
//    fun cannotConstructFieldElementWithoutField() {
//        // Assert:
//        Ed25519FieldElement(null, IntArray(9))
//    }

    // endregion

    // region toString

    @Test
    fun toStringReturnsCorrectRepresentation() {
        // Arrange:
        val bytes = ByteArray(32)
        for (i in 0..31) {
            bytes[i] = (i + 1).toByte()
        }
        val f = MathUtils.field.getEncoding().decode(bytes)

        // Act:
        val fAsString = f.toString()
        val builder = StringBuilder()
        builder.append("[Ed25519FieldElement val=")
        for (b in bytes) {
            builder.append(String.format("%02x", b))
        }
        builder.append("]")

        // Assert:
        Assert.assertThat(fAsString, IsEqual.equalTo(builder.toString()))
    }

    // endregion
}
