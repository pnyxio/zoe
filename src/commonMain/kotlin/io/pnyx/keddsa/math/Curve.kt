package io.pnyx.keddsa.math


/**
 * A twisted Edwards curve.
 * Points on the curve satisfy $-x^2 + y^2 = 1 + d x^2y^2$
 * @author str4d
 */
class Curve(val field: Field, d: ByteArray, val i: FieldElement) {
    val d: FieldElement
    val _2D: FieldElement

    private val zeroP2: GroupElement
    private val zeroP3: GroupElement
    private val zeroP3PrecomputedDouble: GroupElement
    private val zeroPrecomp: GroupElement

    init {
        this.d = field.fromByteArray(d)
        this._2D = this.d.add(this.d)

        val zero = field.ZERO
        val one = field.ONE
        zeroP2 = GroupElement.p2(this, zero, one, one)
        zeroP3 = GroupElement.p3(this, zero, one, one, zero, false)
        zeroP3PrecomputedDouble = GroupElement.p3(this, zero, one, one, zero, true)
        zeroPrecomp = GroupElement.precomp(this, one, one, zero)
    }

    fun getZero(repr: GroupElement.Representation): GroupElement {
        when (repr) {
            GroupElement.Representation.P2 -> return zeroP2
            GroupElement.Representation.P3 -> return zeroP3
            GroupElement.Representation.P3PrecomputedDouble -> return zeroP3PrecomputedDouble
            GroupElement.Representation.PRECOMP -> return zeroPrecomp
            else -> throw IllegalStateException()
        }
    }

    fun createPoint(P: ByteArray, precompute: Boolean): GroupElement {
        return GroupElement(this, P, precompute)
    }

    override fun hashCode(): Int {
        return field.hashCode() xor
                d.hashCode() xor
                i.hashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (other === this)
            return true
        if (other !is Curve)
            return false
        val c = other as Curve?
        return field == c!!.field &&
                d == c.d &&
                i == c.i
    }

}
