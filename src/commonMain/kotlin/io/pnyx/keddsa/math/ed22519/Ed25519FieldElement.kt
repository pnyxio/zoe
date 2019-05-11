package io.pnyx.keddsa.math.ed22519

import io.pnyx.keddsa.Utils
import io.pnyx.keddsa.math.Field
import io.pnyx.keddsa.math.FieldElement


/**
 * Class to represent a field element of the finite field $p = 2^{255} - 19$ l.
 *
 *
 * An element $t$, entries $t[0] \dots t[9]$, represents the integer
 * $t[0]+2^{26} t[1]+2^{51} t[2]+2^{77} t[3]+2^{102} t[4]+\dots+2^{230} t[9]$.
 * Bounds on each $t[i]$ vary depending on context.
 *
 *
 * Reviewed/commented by Bloody Rookie (nemproject@gmx.de)
 */
class Ed25519FieldElement
/**
 * Creates a field element.
 *
 * @param f The underlying field, must be the finite field with $p = 2^{255} - 19$ l
 * @param t The $2^{25.5}$ bit representation of the field element.
 */
(f: Field,
 /**
  * Variable is package private for encoding.
  */
 //internal
 val t: IntArray) : FieldElement(f) {

    /**
     * Gets a value indicating whether or not the field element is non-zero.
     *
     * @return 1 if it is non-zero, 0 otherwise.
     */
    override val isNonZero: Boolean
        get() {
            val s = toByteArray()
            return Utils.equal(s, ZERO) == 0
        }

    init {
        if (t.size != 10)
            throw IllegalArgumentException("Invalid radix-2^51 representation")
    }

    /**
     * $h = f + g$
     *
     *
     * TODO-CR BR: $h$ is allocated via new, probably not a good idea. Do we need the copying into temp variables if we do that?
     *
     *
     * Preconditions:
     *
     *  * $|f|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     *  * $|g|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     *
     *
     * Postconditions:
     *
     *  * $|h|$ bounded by $1.1*2^{26},1.1*2^{25},1.1*2^{26},1.1*2^{25},$ etc.
     *
     *
     * @param val The field element to add.
     * @return The field element this + val.
     */
    override fun add(`val`: FieldElement): FieldElement {
        val g = (`val` as Ed25519FieldElement).t
        val h = IntArray(10)
        for (i in 0..9) {
            h[i] = t[i] + g[i]
        }
        return Ed25519FieldElement(f, h)
    }

    /**
     * $h = f - g$
     *
     *
     * Can overlap $h$ with $f$ or $g$.
     *
     *
     * TODO-CR BR: See above.
     *
     *
     * Preconditions:
     *
     *  * $|f|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     *  * $|g|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     *
     *
     * Postconditions:
     *
     *  * $|h|$ bounded by $1.1*2^{26},1.1*2^{25},1.1*2^{26},1.1*2^{25},$ etc.
     *
     *
     * @param val The field element to subtract.
     * @return The field element this - val.
     */
    override fun subtract(`val`: FieldElement): FieldElement {
        val g = (`val` as Ed25519FieldElement).t
        val h = IntArray(10)
        for (i in 0..9) {
            h[i] = t[i] - g[i]
        }
        return Ed25519FieldElement(f, h)
    }

    /**
     * $h = -f$
     *
     *
     * TODO-CR BR: see above.
     *
     *
     * Preconditions:
     *
     *  * $|f|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     *
     *
     * Postconditions:
     *
     *  * $|h|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     *
     *
     * @return The field element (-1) * this.
     */
    override fun negate(): FieldElement {
        val h = IntArray(10)
        for (i in 0..9) {
            h[i] = -t[i]
        }
        return Ed25519FieldElement(f, h)
    }

    /**
     * $h = f * g$
     *
     *
     * Can overlap $h$ with $f$ or $g$.
     *
     *
     * Preconditions:
     *
     *  * $|f|$ bounded by
     * $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     *  * $|g|$ bounded by
     * $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     *
     *
     * Postconditions:
     *
     *  * $|h|$ bounded by
     * $1.01*2^{25},1.01*2^{24},1.01*2^{25},1.01*2^{24},$ etc.
     *
     *
     * Notes on implementation strategy:
     *
     *
     * Using schoolbook multiplication. Karatsuba would save a little in some
     * cost models.
     *
     *
     * Most multiplications by 2 and 19 are 32-bit precomputations; cheaper than
     * 64-bit postcomputations.
     *
     *
     * There is one remaining multiplication by 19 in the carry chain; one *19
     * precomputation can be merged into this, but the resulting data flow is
     * considerably less clean.
     *
     *
     * There are 12 carries below. 10 of them are 2-way parallelizable and
     * vectorizable. Can get away with 11 carries, but then data flow is much
     * deeper.
     *
     *
     * With tighter constraints on inputs can squeeze carries into int32.
     *
     * @param val The field element to multiply.
     * @return The (reasonably reduced) field element this * val.
     */
    override fun multiply(`val`: FieldElement): FieldElement {
        val g = (`val` as Ed25519FieldElement).t
        val g1_19 = 19 * g[1] /* 1.959375*2^29 */
        val g2_19 = 19 * g[2] /* 1.959375*2^30; still ok */
        val g3_19 = 19 * g[3]
        val g4_19 = 19 * g[4]
        val g5_19 = 19 * g[5]
        val g6_19 = 19 * g[6]
        val g7_19 = 19 * g[7]
        val g8_19 = 19 * g[8]
        val g9_19 = 19 * g[9]
        val f1_2 = 2 * t[1]
        val f3_2 = 2 * t[3]
        val f5_2 = 2 * t[5]
        val f7_2 = 2 * t[7]
        val f9_2 = 2 * t[9]
        val f0g0 = t[0] * g[0].toLong()
        val f0g1 = t[0] * g[1].toLong()
        val f0g2 = t[0] * g[2].toLong()
        val f0g3 = t[0] * g[3].toLong()
        val f0g4 = t[0] * g[4].toLong()
        val f0g5 = t[0] * g[5].toLong()
        val f0g6 = t[0] * g[6].toLong()
        val f0g7 = t[0] * g[7].toLong()
        val f0g8 = t[0] * g[8].toLong()
        val f0g9 = t[0] * g[9].toLong()
        val f1g0 = t[1] * g[0].toLong()
        val f1g1_2 = f1_2 * g[1].toLong()
        val f1g2 = t[1] * g[2].toLong()
        val f1g3_2 = f1_2 * g[3].toLong()
        val f1g4 = t[1] * g[4].toLong()
        val f1g5_2 = f1_2 * g[5].toLong()
        val f1g6 = t[1] * g[6].toLong()
        val f1g7_2 = f1_2 * g[7].toLong()
        val f1g8 = t[1] * g[8].toLong()
        val f1g9_38 = f1_2 * g9_19.toLong()
        val f2g0 = t[2] * g[0].toLong()
        val f2g1 = t[2] * g[1].toLong()
        val f2g2 = t[2] * g[2].toLong()
        val f2g3 = t[2] * g[3].toLong()
        val f2g4 = t[2] * g[4].toLong()
        val f2g5 = t[2] * g[5].toLong()
        val f2g6 = t[2] * g[6].toLong()
        val f2g7 = t[2] * g[7].toLong()
        val f2g8_19 = t[2] * g8_19.toLong()
        val f2g9_19 = t[2] * g9_19.toLong()
        val f3g0 = t[3] * g[0].toLong()
        val f3g1_2 = f3_2 * g[1].toLong()
        val f3g2 = t[3] * g[2].toLong()
        val f3g3_2 = f3_2 * g[3].toLong()
        val f3g4 = t[3] * g[4].toLong()
        val f3g5_2 = f3_2 * g[5].toLong()
        val f3g6 = t[3] * g[6].toLong()
        val f3g7_38 = f3_2 * g7_19.toLong()
        val f3g8_19 = t[3] * g8_19.toLong()
        val f3g9_38 = f3_2 * g9_19.toLong()
        val f4g0 = t[4] * g[0].toLong()
        val f4g1 = t[4] * g[1].toLong()
        val f4g2 = t[4] * g[2].toLong()
        val f4g3 = t[4] * g[3].toLong()
        val f4g4 = t[4] * g[4].toLong()
        val f4g5 = t[4] * g[5].toLong()
        val f4g6_19 = t[4] * g6_19.toLong()
        val f4g7_19 = t[4] * g7_19.toLong()
        val f4g8_19 = t[4] * g8_19.toLong()
        val f4g9_19 = t[4] * g9_19.toLong()
        val f5g0 = t[5] * g[0].toLong()
        val f5g1_2 = f5_2 * g[1].toLong()
        val f5g2 = t[5] * g[2].toLong()
        val f5g3_2 = f5_2 * g[3].toLong()
        val f5g4 = t[5] * g[4].toLong()
        val f5g5_38 = f5_2 * g5_19.toLong()
        val f5g6_19 = t[5] * g6_19.toLong()
        val f5g7_38 = f5_2 * g7_19.toLong()
        val f5g8_19 = t[5] * g8_19.toLong()
        val f5g9_38 = f5_2 * g9_19.toLong()
        val f6g0 = t[6] * g[0].toLong()
        val f6g1 = t[6] * g[1].toLong()
        val f6g2 = t[6] * g[2].toLong()
        val f6g3 = t[6] * g[3].toLong()
        val f6g4_19 = t[6] * g4_19.toLong()
        val f6g5_19 = t[6] * g5_19.toLong()
        val f6g6_19 = t[6] * g6_19.toLong()
        val f6g7_19 = t[6] * g7_19.toLong()
        val f6g8_19 = t[6] * g8_19.toLong()
        val f6g9_19 = t[6] * g9_19.toLong()
        val f7g0 = t[7] * g[0].toLong()
        val f7g1_2 = f7_2 * g[1].toLong()
        val f7g2 = t[7] * g[2].toLong()
        val f7g3_38 = f7_2 * g3_19.toLong()
        val f7g4_19 = t[7] * g4_19.toLong()
        val f7g5_38 = f7_2 * g5_19.toLong()
        val f7g6_19 = t[7] * g6_19.toLong()
        val f7g7_38 = f7_2 * g7_19.toLong()
        val f7g8_19 = t[7] * g8_19.toLong()
        val f7g9_38 = f7_2 * g9_19.toLong()
        val f8g0 = t[8] * g[0].toLong()
        val f8g1 = t[8] * g[1].toLong()
        val f8g2_19 = t[8] * g2_19.toLong()
        val f8g3_19 = t[8] * g3_19.toLong()
        val f8g4_19 = t[8] * g4_19.toLong()
        val f8g5_19 = t[8] * g5_19.toLong()
        val f8g6_19 = t[8] * g6_19.toLong()
        val f8g7_19 = t[8] * g7_19.toLong()
        val f8g8_19 = t[8] * g8_19.toLong()
        val f8g9_19 = t[8] * g9_19.toLong()
        val f9g0 = t[9] * g[0].toLong()
        val f9g1_38 = f9_2 * g1_19.toLong()
        val f9g2_19 = t[9] * g2_19.toLong()
        val f9g3_38 = f9_2 * g3_19.toLong()
        val f9g4_19 = t[9] * g4_19.toLong()
        val f9g5_38 = f9_2 * g5_19.toLong()
        val f9g6_19 = t[9] * g6_19.toLong()
        val f9g7_38 = f9_2 * g7_19.toLong()
        val f9g8_19 = t[9] * g8_19.toLong()
        val f9g9_38 = f9_2 * g9_19.toLong()

        /**
         * Remember: 2^255 congruent 19 modulo p.
         * h = h0 * 2^0 + h1 * 2^26 + h2 * 2^(26+25) + h3 * 2^(26+25+26) + ... + h9 * 2^(5*26+5*25).
         * So to get the real number we would have to multiply the coefficients with the corresponding powers of 2.
         * To get an idea what is going on below, look at the calculation of h0:
         * h0 is the coefficient to the power 2^0 so it collects (sums) all products that have the power 2^0.
         * f0 * g0 really is f0 * 2^0 * g0 * 2^0 = (f0 * g0) * 2^0.
         * f1 * g9 really is f1 * 2^26 * g9 * 2^230 = f1 * g9 * 2^256 = 2 * f1 * g9 * 2^255 congruent 2 * 19 * f1 * g9 * 2^0 modulo p.
         * f2 * g8 really is f2 * 2^51 * g8 * 2^204 = f2 * g8 * 2^255 congruent 19 * f2 * g8 * 2^0 modulo p.
         * and so on...
         */
        var h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38
        var h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19
        var h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38
        var h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19
        var h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38
        var h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19
        var h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38
        var h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19
        var h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38
        var h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0
        var carry0: Long
        val carry1: Long
        val carry2: Long
        val carry3: Long
        var carry4: Long
        val carry5: Long
        val carry6: Long
        val carry7: Long
        val carry8: Long
        val carry9: Long

        /*
        |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
          i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
        |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
          i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9
        */

        carry0 = h0 + (1 shl 25).toLong() shr 26
        h1 += carry0
        h0 -= carry0 shl 26
        carry4 = h4 + (1 shl 25).toLong() shr 26
        h5 += carry4
        h4 -= carry4 shl 26
        /* |h0| <= 2^25 */
        /* |h4| <= 2^25 */
        /* |h1| <= 1.71*2^59 */
        /* |h5| <= 1.71*2^59 */

        carry1 = h1 + (1 shl 24).toLong() shr 25
        h2 += carry1
        h1 -= carry1 shl 25
        carry5 = h5 + (1 shl 24).toLong() shr 25
        h6 += carry5
        h5 -= carry5 shl 25
        /* |h1| <= 2^24; from now on fits into int32 */
        /* |h5| <= 2^24; from now on fits into int32 */
        /* |h2| <= 1.41*2^60 */
        /* |h6| <= 1.41*2^60 */

        carry2 = h2 + (1 shl 25).toLong() shr 26
        h3 += carry2
        h2 -= carry2 shl 26
        carry6 = h6 + (1 shl 25).toLong() shr 26
        h7 += carry6
        h6 -= carry6 shl 26
        /* |h2| <= 2^25; from now on fits into int32 unchanged */
        /* |h6| <= 2^25; from now on fits into int32 unchanged */
        /* |h3| <= 1.71*2^59 */
        /* |h7| <= 1.71*2^59 */

        carry3 = h3 + (1 shl 24).toLong() shr 25
        h4 += carry3
        h3 -= carry3 shl 25
        carry7 = h7 + (1 shl 24).toLong() shr 25
        h8 += carry7
        h7 -= carry7 shl 25
        /* |h3| <= 2^24; from now on fits into int32 unchanged */
        /* |h7| <= 2^24; from now on fits into int32 unchanged */
        /* |h4| <= 1.72*2^34 */
        /* |h8| <= 1.41*2^60 */

        carry4 = h4 + (1 shl 25).toLong() shr 26
        h5 += carry4
        h4 -= carry4 shl 26
        carry8 = h8 + (1 shl 25).toLong() shr 26
        h9 += carry8
        h8 -= carry8 shl 26
        /* |h4| <= 2^25; from now on fits into int32 unchanged */
        /* |h8| <= 2^25; from now on fits into int32 unchanged */
        /* |h5| <= 1.01*2^24 */
        /* |h9| <= 1.71*2^59 */

        carry9 = h9 + (1 shl 24).toLong() shr 25
        h0 += carry9 * 19
        h9 -= carry9 shl 25
        /* |h9| <= 2^24; from now on fits into int32 unchanged */
        /* |h0| <= 1.1*2^39 */

        carry0 = h0 + (1 shl 25).toLong() shr 26
        h1 += carry0
        h0 -= carry0 shl 26
        /* |h0| <= 2^25; from now on fits into int32 unchanged */
        /* |h1| <= 1.01*2^24 */

        val h = IntArray(10)
        h[0] = h0.toInt()
        h[1] = h1.toInt()
        h[2] = h2.toInt()
        h[3] = h3.toInt()
        h[4] = h4.toInt()
        h[5] = h5.toInt()
        h[6] = h6.toInt()
        h[7] = h7.toInt()
        h[8] = h8.toInt()
        h[9] = h9.toInt()
        return Ed25519FieldElement(f, h)
    }

    /**
     * $h = f * f$
     *
     *
     * Can overlap $h$ with $f$.
     *
     *
     * Preconditions:
     *
     *  * $|f|$ bounded by $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     *
     *
     * Postconditions:
     *
     *  * $|h|$ bounded by $1.01*2^{25},1.01*2^{24},1.01*2^{25},1.01*2^{24},$ etc.
     *
     *
     * See [.multiply] for discussion
     * of implementation strategy.
     *
     * @return The (reasonably reduced) square of this field element.
     */
    override fun square(): FieldElement {
        val f0 = t[0]
        val f1 = t[1]
        val f2 = t[2]
        val f3 = t[3]
        val f4 = t[4]
        val f5 = t[5]
        val f6 = t[6]
        val f7 = t[7]
        val f8 = t[8]
        val f9 = t[9]
        val f0_2 = 2 * f0
        val f1_2 = 2 * f1
        val f2_2 = 2 * f2
        val f3_2 = 2 * f3
        val f4_2 = 2 * f4
        val f5_2 = 2 * f5
        val f6_2 = 2 * f6
        val f7_2 = 2 * f7
        val f5_38 = 38 * f5 /* 1.959375*2^30 */
        val f6_19 = 19 * f6 /* 1.959375*2^30 */
        val f7_38 = 38 * f7 /* 1.959375*2^30 */
        val f8_19 = 19 * f8 /* 1.959375*2^30 */
        val f9_38 = 38 * f9 /* 1.959375*2^30 */
        val f0f0 = f0 * f0.toLong()
        val f0f1_2 = f0_2 * f1.toLong()
        val f0f2_2 = f0_2 * f2.toLong()
        val f0f3_2 = f0_2 * f3.toLong()
        val f0f4_2 = f0_2 * f4.toLong()
        val f0f5_2 = f0_2 * f5.toLong()
        val f0f6_2 = f0_2 * f6.toLong()
        val f0f7_2 = f0_2 * f7.toLong()
        val f0f8_2 = f0_2 * f8.toLong()
        val f0f9_2 = f0_2 * f9.toLong()
        val f1f1_2 = f1_2 * f1.toLong()
        val f1f2_2 = f1_2 * f2.toLong()
        val f1f3_4 = f1_2 * f3_2.toLong()
        val f1f4_2 = f1_2 * f4.toLong()
        val f1f5_4 = f1_2 * f5_2.toLong()
        val f1f6_2 = f1_2 * f6.toLong()
        val f1f7_4 = f1_2 * f7_2.toLong()
        val f1f8_2 = f1_2 * f8.toLong()
        val f1f9_76 = f1_2 * f9_38.toLong()
        val f2f2 = f2 * f2.toLong()
        val f2f3_2 = f2_2 * f3.toLong()
        val f2f4_2 = f2_2 * f4.toLong()
        val f2f5_2 = f2_2 * f5.toLong()
        val f2f6_2 = f2_2 * f6.toLong()
        val f2f7_2 = f2_2 * f7.toLong()
        val f2f8_38 = f2_2 * f8_19.toLong()
        val f2f9_38 = f2 * f9_38.toLong()
        val f3f3_2 = f3_2 * f3.toLong()
        val f3f4_2 = f3_2 * f4.toLong()
        val f3f5_4 = f3_2 * f5_2.toLong()
        val f3f6_2 = f3_2 * f6.toLong()
        val f3f7_76 = f3_2 * f7_38.toLong()
        val f3f8_38 = f3_2 * f8_19.toLong()
        val f3f9_76 = f3_2 * f9_38.toLong()
        val f4f4 = f4 * f4.toLong()
        val f4f5_2 = f4_2 * f5.toLong()
        val f4f6_38 = f4_2 * f6_19.toLong()
        val f4f7_38 = f4 * f7_38.toLong()
        val f4f8_38 = f4_2 * f8_19.toLong()
        val f4f9_38 = f4 * f9_38.toLong()
        val f5f5_38 = f5 * f5_38.toLong()
        val f5f6_38 = f5_2 * f6_19.toLong()
        val f5f7_76 = f5_2 * f7_38.toLong()
        val f5f8_38 = f5_2 * f8_19.toLong()
        val f5f9_76 = f5_2 * f9_38.toLong()
        val f6f6_19 = f6 * f6_19.toLong()
        val f6f7_38 = f6 * f7_38.toLong()
        val f6f8_38 = f6_2 * f8_19.toLong()
        val f6f9_38 = f6 * f9_38.toLong()
        val f7f7_38 = f7 * f7_38.toLong()
        val f7f8_38 = f7_2 * f8_19.toLong()
        val f7f9_76 = f7_2 * f9_38.toLong()
        val f8f8_19 = f8 * f8_19.toLong()
        val f8f9_38 = f8 * f9_38.toLong()
        val f9f9_38 = f9 * f9_38.toLong()

        /**
         * Same procedure as in multiply, but this time we have a higher symmetry leading to less summands.
         * e.g. f1f9_76 really stands for f1 * 2^26 * f9 * 2^230 + f9 * 2^230 + f1 * 2^26 congruent 2 * 2 * 19 * f1 * f9  2^0 modulo p.
         */
        var h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38
        var h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38
        var h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19
        var h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38
        var h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38
        var h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38
        var h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19
        var h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38
        var h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38
        var h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2
        var carry0: Long
        val carry1: Long
        val carry2: Long
        val carry3: Long
        var carry4: Long
        val carry5: Long
        val carry6: Long
        val carry7: Long
        val carry8: Long
        val carry9: Long

        carry0 = h0 + (1 shl 25).toLong() shr 26
        h1 += carry0
        h0 -= carry0 shl 26
        carry4 = h4 + (1 shl 25).toLong() shr 26
        h5 += carry4
        h4 -= carry4 shl 26

        carry1 = h1 + (1 shl 24).toLong() shr 25
        h2 += carry1
        h1 -= carry1 shl 25
        carry5 = h5 + (1 shl 24).toLong() shr 25
        h6 += carry5
        h5 -= carry5 shl 25

        carry2 = h2 + (1 shl 25).toLong() shr 26
        h3 += carry2
        h2 -= carry2 shl 26
        carry6 = h6 + (1 shl 25).toLong() shr 26
        h7 += carry6
        h6 -= carry6 shl 26

        carry3 = h3 + (1 shl 24).toLong() shr 25
        h4 += carry3
        h3 -= carry3 shl 25
        carry7 = h7 + (1 shl 24).toLong() shr 25
        h8 += carry7
        h7 -= carry7 shl 25

        carry4 = h4 + (1 shl 25).toLong() shr 26
        h5 += carry4
        h4 -= carry4 shl 26
        carry8 = h8 + (1 shl 25).toLong() shr 26
        h9 += carry8
        h8 -= carry8 shl 26

        carry9 = h9 + (1 shl 24).toLong() shr 25
        h0 += carry9 * 19
        h9 -= carry9 shl 25

        carry0 = h0 + (1 shl 25).toLong() shr 26
        h1 += carry0
        h0 -= carry0 shl 26

        val h = IntArray(10)
        h[0] = h0.toInt()
        h[1] = h1.toInt()
        h[2] = h2.toInt()
        h[3] = h3.toInt()
        h[4] = h4.toInt()
        h[5] = h5.toInt()
        h[6] = h6.toInt()
        h[7] = h7.toInt()
        h[8] = h8.toInt()
        h[9] = h9.toInt()
        return Ed25519FieldElement(f, h)
    }

    /**
     * $h = 2 * f * f$
     *
     *
     * Can overlap $h$ with $f$.
     *
     *
     * Preconditions:
     *
     *  * $|f|$ bounded by $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     *
     *
     * Postconditions:
     *
     *  * $|h|$ bounded by $1.01*2^{25},1.01*2^{24},1.01*2^{25},1.01*2^{24},$ etc.
     *
     *
     * See [.multiply] for discussion
     * of implementation strategy.
     *
     * @return The (reasonably reduced) square of this field element times 2.
     */
    override fun squareAndDouble(): FieldElement {
        val f0 = t[0]
        val f1 = t[1]
        val f2 = t[2]
        val f3 = t[3]
        val f4 = t[4]
        val f5 = t[5]
        val f6 = t[6]
        val f7 = t[7]
        val f8 = t[8]
        val f9 = t[9]
        val f0_2 = 2 * f0
        val f1_2 = 2 * f1
        val f2_2 = 2 * f2
        val f3_2 = 2 * f3
        val f4_2 = 2 * f4
        val f5_2 = 2 * f5
        val f6_2 = 2 * f6
        val f7_2 = 2 * f7
        val f5_38 = 38 * f5 /* 1.959375*2^30 */
        val f6_19 = 19 * f6 /* 1.959375*2^30 */
        val f7_38 = 38 * f7 /* 1.959375*2^30 */
        val f8_19 = 19 * f8 /* 1.959375*2^30 */
        val f9_38 = 38 * f9 /* 1.959375*2^30 */
        val f0f0 = f0 * f0.toLong()
        val f0f1_2 = f0_2 * f1.toLong()
        val f0f2_2 = f0_2 * f2.toLong()
        val f0f3_2 = f0_2 * f3.toLong()
        val f0f4_2 = f0_2 * f4.toLong()
        val f0f5_2 = f0_2 * f5.toLong()
        val f0f6_2 = f0_2 * f6.toLong()
        val f0f7_2 = f0_2 * f7.toLong()
        val f0f8_2 = f0_2 * f8.toLong()
        val f0f9_2 = f0_2 * f9.toLong()
        val f1f1_2 = f1_2 * f1.toLong()
        val f1f2_2 = f1_2 * f2.toLong()
        val f1f3_4 = f1_2 * f3_2.toLong()
        val f1f4_2 = f1_2 * f4.toLong()
        val f1f5_4 = f1_2 * f5_2.toLong()
        val f1f6_2 = f1_2 * f6.toLong()
        val f1f7_4 = f1_2 * f7_2.toLong()
        val f1f8_2 = f1_2 * f8.toLong()
        val f1f9_76 = f1_2 * f9_38.toLong()
        val f2f2 = f2 * f2.toLong()
        val f2f3_2 = f2_2 * f3.toLong()
        val f2f4_2 = f2_2 * f4.toLong()
        val f2f5_2 = f2_2 * f5.toLong()
        val f2f6_2 = f2_2 * f6.toLong()
        val f2f7_2 = f2_2 * f7.toLong()
        val f2f8_38 = f2_2 * f8_19.toLong()
        val f2f9_38 = f2 * f9_38.toLong()
        val f3f3_2 = f3_2 * f3.toLong()
        val f3f4_2 = f3_2 * f4.toLong()
        val f3f5_4 = f3_2 * f5_2.toLong()
        val f3f6_2 = f3_2 * f6.toLong()
        val f3f7_76 = f3_2 * f7_38.toLong()
        val f3f8_38 = f3_2 * f8_19.toLong()
        val f3f9_76 = f3_2 * f9_38.toLong()
        val f4f4 = f4 * f4.toLong()
        val f4f5_2 = f4_2 * f5.toLong()
        val f4f6_38 = f4_2 * f6_19.toLong()
        val f4f7_38 = f4 * f7_38.toLong()
        val f4f8_38 = f4_2 * f8_19.toLong()
        val f4f9_38 = f4 * f9_38.toLong()
        val f5f5_38 = f5 * f5_38.toLong()
        val f5f6_38 = f5_2 * f6_19.toLong()
        val f5f7_76 = f5_2 * f7_38.toLong()
        val f5f8_38 = f5_2 * f8_19.toLong()
        val f5f9_76 = f5_2 * f9_38.toLong()
        val f6f6_19 = f6 * f6_19.toLong()
        val f6f7_38 = f6 * f7_38.toLong()
        val f6f8_38 = f6_2 * f8_19.toLong()
        val f6f9_38 = f6 * f9_38.toLong()
        val f7f7_38 = f7 * f7_38.toLong()
        val f7f8_38 = f7_2 * f8_19.toLong()
        val f7f9_76 = f7_2 * f9_38.toLong()
        val f8f8_19 = f8 * f8_19.toLong()
        val f8f9_38 = f8 * f9_38.toLong()
        val f9f9_38 = f9 * f9_38.toLong()
        var h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38
        var h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38
        var h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19
        var h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38
        var h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38
        var h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38
        var h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19
        var h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38
        var h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38
        var h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2
        var carry0: Long
        val carry1: Long
        val carry2: Long
        val carry3: Long
        var carry4: Long
        val carry5: Long
        val carry6: Long
        val carry7: Long
        val carry8: Long
        val carry9: Long

        h0 += h0
        h1 += h1
        h2 += h2
        h3 += h3
        h4 += h4
        h5 += h5
        h6 += h6
        h7 += h7
        h8 += h8
        h9 += h9

        carry0 = h0 + (1 shl 25).toLong() shr 26
        h1 += carry0
        h0 -= carry0 shl 26
        carry4 = h4 + (1 shl 25).toLong() shr 26
        h5 += carry4
        h4 -= carry4 shl 26

        carry1 = h1 + (1 shl 24).toLong() shr 25
        h2 += carry1
        h1 -= carry1 shl 25
        carry5 = h5 + (1 shl 24).toLong() shr 25
        h6 += carry5
        h5 -= carry5 shl 25

        carry2 = h2 + (1 shl 25).toLong() shr 26
        h3 += carry2
        h2 -= carry2 shl 26
        carry6 = h6 + (1 shl 25).toLong() shr 26
        h7 += carry6
        h6 -= carry6 shl 26

        carry3 = h3 + (1 shl 24).toLong() shr 25
        h4 += carry3
        h3 -= carry3 shl 25
        carry7 = h7 + (1 shl 24).toLong() shr 25
        h8 += carry7
        h7 -= carry7 shl 25

        carry4 = h4 + (1 shl 25).toLong() shr 26
        h5 += carry4
        h4 -= carry4 shl 26
        carry8 = h8 + (1 shl 25).toLong() shr 26
        h9 += carry8
        h8 -= carry8 shl 26

        carry9 = h9 + (1 shl 24).toLong() shr 25
        h0 += carry9 * 19
        h9 -= carry9 shl 25

        carry0 = h0 + (1 shl 25).toLong() shr 26
        h1 += carry0
        h0 -= carry0 shl 26

        val h = IntArray(10)
        h[0] = h0.toInt()
        h[1] = h1.toInt()
        h[2] = h2.toInt()
        h[3] = h3.toInt()
        h[4] = h4.toInt()
        h[5] = h5.toInt()
        h[6] = h6.toInt()
        h[7] = h7.toInt()
        h[8] = h8.toInt()
        h[9] = h9.toInt()
        return Ed25519FieldElement(f, h)
    }

    /**
     * Invert this field element.
     *
     *
     * The inverse is found via Fermat's little theorem:<br></br>
     * $a^p \cong a \mod p$ and therefore $a^{(p-2)} \cong a^{-1} \mod p$
     *
     * @return The inverse of this field element.
     */
    override fun invert(): FieldElement {
        var t0: FieldElement
        var t1: FieldElement
        var t2: FieldElement
        var t3: FieldElement

        // 2 == 2 * 1
        t0 = square()

        // 4 == 2 * 2
        t1 = t0.square()

        // 8 == 2 * 4
        t1 = t1.square()

        // 9 == 8 + 1
        t1 = multiply(t1)

        // 11 == 9 + 2
        t0 = t0.multiply(t1)

        // 22 == 2 * 11
        t2 = t0.square()

        // 31 == 22 + 9
        t1 = t1.multiply(t2)

        // 2^6 - 2^1
        t2 = t1.square()

        // 2^10 - 2^5
        for (i in 1..4) {
            t2 = t2.square()
        }

        // 2^10 - 2^0
        t1 = t2.multiply(t1)

        // 2^11 - 2^1
        t2 = t1.square()

        // 2^20 - 2^10
        for (i in 1..9) {
            t2 = t2.square()
        }

        // 2^20 - 2^0
        t2 = t2.multiply(t1)

        // 2^21 - 2^1
        t3 = t2.square()

        // 2^40 - 2^20
        for (i in 1..19) {
            t3 = t3.square()
        }

        // 2^40 - 2^0
        t2 = t3.multiply(t2)

        // 2^41 - 2^1
        t2 = t2.square()

        // 2^50 - 2^10
        for (i in 1..9) {
            t2 = t2.square()
        }

        // 2^50 - 2^0
        t1 = t2.multiply(t1)

        // 2^51 - 2^1
        t2 = t1.square()

        // 2^100 - 2^50
        for (i in 1..49) {
            t2 = t2.square()
        }

        // 2^100 - 2^0
        t2 = t2.multiply(t1)

        // 2^101 - 2^1
        t3 = t2.square()

        // 2^200 - 2^100
        for (i in 1..99) {
            t3 = t3.square()
        }

        // 2^200 - 2^0
        t2 = t3.multiply(t2)

        // 2^201 - 2^1
        t2 = t2.square()

        // 2^250 - 2^50
        for (i in 1..49) {
            t2 = t2.square()
        }

        // 2^250 - 2^0
        t1 = t2.multiply(t1)

        // 2^251 - 2^1
        t1 = t1.square()

        // 2^255 - 2^5
        for (i in 1..4) {
            t1 = t1.square()
        }

        // 2^255 - 21
        return t1.multiply(t0)
    }

    /**
     * Gets this field element to the power of $(2^{252} - 3)$.
     * This is a helper function for calculating the square root.
     *
     *
     * TODO-CR BR: I think it makes sense to have a sqrt function.
     *
     * @return This field element to the power of $(2^{252} - 3)$.
     */
    override fun pow22523(): FieldElement {
        var t0: FieldElement
        var t1: FieldElement
        var t2: FieldElement

        // 2 == 2 * 1
        t0 = square()

        // 4 == 2 * 2
        t1 = t0.square()

        // 8 == 2 * 4
        t1 = t1.square()

        // z9 = z1*z8
        t1 = multiply(t1)

        // 11 == 9 + 2
        t0 = t0.multiply(t1)

        // 22 == 2 * 11
        t0 = t0.square()

        // 31 == 22 + 9
        t0 = t1.multiply(t0)

        // 2^6 - 2^1
        t1 = t0.square()

        // 2^10 - 2^5
        for (i in 1..4) {
            t1 = t1.square()
        }

        // 2^10 - 2^0
        t0 = t1.multiply(t0)

        // 2^11 - 2^1
        t1 = t0.square()

        // 2^20 - 2^10
        for (i in 1..9) {
            t1 = t1.square()
        }

        // 2^20 - 2^0
        t1 = t1.multiply(t0)

        // 2^21 - 2^1
        t2 = t1.square()

        // 2^40 - 2^20
        for (i in 1..19) {
            t2 = t2.square()
        }

        // 2^40 - 2^0
        t1 = t2.multiply(t1)

        // 2^41 - 2^1
        t1 = t1.square()

        // 2^50 - 2^10
        for (i in 1..9) {
            t1 = t1.square()
        }

        // 2^50 - 2^0
        t0 = t1.multiply(t0)

        // 2^51 - 2^1
        t1 = t0.square()

        // 2^100 - 2^50
        for (i in 1..49) {
            t1 = t1.square()
        }

        // 2^100 - 2^0
        t1 = t1.multiply(t0)

        // 2^101 - 2^1
        t2 = t1.square()

        // 2^200 - 2^100
        for (i in 1..99) {
            t2 = t2.square()
        }

        // 2^200 - 2^0
        t1 = t2.multiply(t1)

        // 2^201 - 2^1
        t1 = t1.square()

        // 2^250 - 2^50
        for (i in 1..49) {
            t1 = t1.square()
        }

        // 2^250 - 2^0
        t0 = t1.multiply(t0)

        // 2^251 - 2^1
        t0 = t0.square()

        // 2^252 - 2^2
        t0 = t0.square()

        // 2^252 - 3
        return multiply(t0)
    }

    /**
     * Constant-time conditional move. Well, actually it is a conditional copy.
     * Logic is inspired by the SUPERCOP implementation at:
     * https://github.com/floodyberry/supercop/blob/master/crypto_sign/ed25519/ref10/fe_cmov.c
     *
     * @param val the other field element.
     * @param b must be 0 or 1, otherwise results are undefined.
     * @return a copy of this if $b == 0$, or a copy of val if $b == 1$.
     */
    override fun cmov(`val`: FieldElement, b: Int): FieldElement {
        val b1 = -b
        val that = `val` as Ed25519FieldElement
        val result = IntArray(10)
        for (i in 0..9) {
            result[i] = this.t[i]
            var x = this.t[i] xor that.t[i]
            x = x and b1
            result[i] = result[i] xor x
        }
        return Ed25519FieldElement(this.f, result)
    }

    override fun hashCode(): Int {
        return t.contentHashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (other !is Ed25519FieldElement)
            return false
        val fe = other as Ed25519FieldElement?
        return 1 == Utils.equal(toByteArray(), fe!!.toByteArray())
    }

    override fun toString(): String {
        return "[Ed25519FieldElement val=" + Utils.bytesToHex(toByteArray()) + "]"
    }

    companion object {

        private val ZERO = ByteArray(32)
    }
}
