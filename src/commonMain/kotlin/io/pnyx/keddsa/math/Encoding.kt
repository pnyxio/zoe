package io.pnyx.keddsa.math

/**
 * Common interface for all $(b-1)$-bit encodings of l
 * of EdDSA finite fields.
 * @author str4d
 */
abstract class Encoding {
    protected var f: Field? = null

    //TODO @Synchronized
    open fun setField(f: Field) {
        if (this.f != null)
            throw IllegalStateException("already set")
        this.f = f
    }

    /**
     * Encode a FieldElement in its $(b-1)$-bit encoding.
     * @param x the FieldElement to encode
     * @return the $(b-1)$-bit encoding of this FieldElement.
     */
    abstract fun encode(x: FieldElement): ByteArray

    /**
     * Decode a FieldElement from its $(b-1)$-bit encoding.
     * The highest bit is masked out.
     * @param in the $(b-1)$-bit encoding of a FieldElement.
     * @return the FieldElement represented by 'val'.
     */
    abstract fun decode(`in`: ByteArray): FieldElement

    /**
     * From the Ed25519 paper:<br></br>
     * $x$ is negative if the $(b-1)$-bit encoding of $x$ is lexicographically larger
     * than the $(b-1)$-bit encoding of -x. If $q$ is an odd prime and the encoding
     * is the little-endian representation of $\{0, 1,\dots, q-1\}$ then the negative
     * elements of $F_q$ are $\{1, 3, 5,\dots, q-2\}$.
     * @param x the FieldElement to check
     * @return true if negative
     */
    abstract fun isNegative(x: FieldElement): Boolean
}
