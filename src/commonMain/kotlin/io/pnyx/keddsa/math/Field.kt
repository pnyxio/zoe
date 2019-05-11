package io.pnyx.keddsa.math

import io.pnyx.keddsa.math.Constants

class Field(private val b: Int, q: ByteArray, private val enc: Encoding) {
    val ZERO: FieldElement
    val ONE: FieldElement
    val TWO: FieldElement
    val FOUR: FieldElement
    val FIVE: FieldElement
    val EIGHT: FieldElement

    private val q: FieldElement
    /**
     * q-2
     */
    private val qm2: FieldElement
    /**
     * (q-5) / 8
     */
    private val qm5d8: FieldElement
    init {
        this.enc.setField(this)

        this.q = fromByteArray(q)

        // Set up constants
        ZERO = fromByteArray(Constants.ZERO)
        ONE = fromByteArray(Constants.ONE)
        TWO = fromByteArray(Constants.TWO)
        FOUR = fromByteArray(Constants.FOUR)
        FIVE = fromByteArray(Constants.FIVE)
        EIGHT = fromByteArray(Constants.EIGHT)

        // Precompute values
        qm2 = this.q.subtract(TWO)
        qm5d8 = this.q.subtract(FIVE).divide(EIGHT)
    }



    fun fromByteArray(x: ByteArray): FieldElement {
        return enc.decode(x)
    }

    fun getb(): Int {
        return b
    }

    fun getQ(): FieldElement {
        return q
    }

    fun getQm2(): FieldElement {
        return qm2
    }

    fun getQm5d8(): FieldElement {
        return qm5d8
    }

    fun getEncoding(): Encoding {
        return enc
    }

    override fun hashCode(): Int {
        return q.hashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (other !is Field)
            return false
        val f = other as Field?
        return b == f!!.b && q == f.q
    }
}