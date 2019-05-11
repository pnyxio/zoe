package io.pnyx.keddsa.spec

import java.io.Serializable
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.spec.AlgorithmParameterSpec

import io.pnyx.keddsa.math.Curve
import io.pnyx.keddsa.math.GroupElement
import io.pnyx.keddsa.math.ScalarOps


open class EdDSAParameterSpec
/**
 * @param curve the curve
 * @param hashAlgo the JCA string for the hash algorithm
 * @param sc the parameter L represented as ScalarOps
 * @param B the parameter B
 * @throws IllegalArgumentException if hash algorithm is unsupported or length is wrong
 */
    (
    val curve: Curve, val hashAlgorithm: String,
    val scalarOps: ScalarOps,
    /**
     * @return the base (generator)
     */
    val b: GroupElement
) : AlgorithmParameterSpec, Serializable {

    init {
        try {
            val hash = MessageDigest.getInstance(hashAlgorithm)
            // EdDSA hash function must produce 2b-bit output
            if (curve.field.getb() / 4 != hash.digestLength)
                throw IllegalArgumentException("Hash output is not 2b-bit")
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalArgumentException("Unsupported hash algorithm")
        }

    }

    override fun hashCode(): Int {
        return hashAlgorithm.hashCode() xor
                curve.hashCode() xor
                b.hashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (other === this)
            return true
        if (other !is EdDSAParameterSpec)
            return false
        val s = other as EdDSAParameterSpec?
        return hashAlgorithm == s!!.hashAlgorithm &&
                curve.equals(s.curve) &&
                b.equals(s.b)
    }

    companion object {
        private const val serialVersionUID = 8274987108472012L
    }
}
