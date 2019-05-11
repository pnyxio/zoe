package io.pnyx.keddsa.math.bigint

import io.pnyx.keddsa.math.Field
import io.pnyx.keddsa.math.FieldElement
import java.math.BigInteger

/**
 * A particular element of the field \Z/(2^255-19).
 * @author str4d
 */
class BigIntegerFieldElement(f: Field,
                             /**
                              * Variable is package private for encoding.
                              */
                             //internal
                             val bi: BigInteger) : FieldElement(f) {

    override val isNonZero: Boolean
        get() = bi != BigInteger.ZERO

    override fun add(`val`: FieldElement): FieldElement {
        return BigIntegerFieldElement(f, bi.add((`val` as BigIntegerFieldElement).bi)).rem(f.getQ())
    }

    override fun addOne(): FieldElement {
        return BigIntegerFieldElement(f, bi.add(BigInteger.ONE)).rem(f.getQ())
    }

    override fun subtract(`val`: FieldElement): FieldElement {
        return BigIntegerFieldElement(f, bi.subtract((`val` as BigIntegerFieldElement).bi)).rem(f.getQ())
    }

    override fun subtractOne(): FieldElement {
        return BigIntegerFieldElement(f, bi.subtract(BigInteger.ONE)).rem(f.getQ())
    }

    override fun negate(): FieldElement {
        return f.getQ().subtract(this)
    }

    override fun divide(`val`: FieldElement): FieldElement {
        return divide((`val` as BigIntegerFieldElement).bi)
    }

    fun divide(`val`: BigInteger): FieldElement {
        return BigIntegerFieldElement(f, bi.divide(`val`)).rem(f.getQ())
    }

    override fun multiply(`val`: FieldElement): FieldElement {
        return BigIntegerFieldElement(f, bi.multiply((`val` as BigIntegerFieldElement).bi)).rem(f.getQ())
    }

    override fun square(): FieldElement {
        return multiply(this)
    }

    override fun squareAndDouble(): FieldElement {
        val sq = square()
        return sq.add(sq)
    }

    override fun invert(): FieldElement {
        // Euler's theorem
        //return modPow(f.getQm2(), f.getQ());
        return BigIntegerFieldElement(f, bi.modInverse((f.getQ() as BigIntegerFieldElement).bi))
    }

    operator fun rem(m: FieldElement): FieldElement {
        return BigIntegerFieldElement(f, bi.mod((m as BigIntegerFieldElement).bi))
    }

    fun modPow(e: FieldElement, m: FieldElement): FieldElement {
        return BigIntegerFieldElement(f, bi.modPow((e as BigIntegerFieldElement).bi, (m as BigIntegerFieldElement).bi))
    }

    fun pow(e: FieldElement): FieldElement {
        return modPow(e, f.getQ())
    }

    override fun pow22523(): FieldElement {
        return pow(f.getQm5d8())
    }

    override fun cmov(`val`: FieldElement, b: Int): FieldElement {
        // Not constant-time, but it doesn't really matter because none of the underlying BigInteger operations
        // are either, so there's not much point in trying hard here ...
        return if (b == 0) this else `val`
    }

    override fun hashCode(): Int {
        return bi.hashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (other !is BigIntegerFieldElement)
            return false
        val fe = other as BigIntegerFieldElement?
        return bi == fe!!.bi
    }

    override fun toString(): String {
        return "[BigIntegerFieldElement val=$bi]"
    }

}
