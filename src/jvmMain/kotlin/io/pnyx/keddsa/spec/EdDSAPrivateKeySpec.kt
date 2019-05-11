package io.pnyx.keddsa.spec

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import io.pnyx.keddsa.math.GroupElement;
import kotlin.experimental.and
import kotlin.experimental.or

class EdDSAPrivateKeySpec : KeySpec {
    /**
     * @return will be null if constructed directly from the private key
     */
    val seed: ByteArray?
    /**
     * @return the hash
     */
    val h: ByteArray
    private val a: ByteArray
    private val A: GroupElement
    val params: EdDSAParameterSpec

    /**
     * @param seed the private key
     * @param spec the parameter specification for this key
     * @throws IllegalArgumentException if seed length is wrong or hash algorithm is unsupported
     */
    constructor(seed: ByteArray, spec: EdDSAParameterSpec) {
        if (seed.size != spec.curve.field.getb() / 8)
            throw IllegalArgumentException("seed length is wrong")

        this.params = spec
        this.seed = seed

        try {
            val hash = MessageDigest.getInstance(spec.hashAlgorithm)
            val b = spec.curve.field.getb()

            // H(k)
            h = hash.digest(seed)

            /*a = BigInteger.valueOf(2).pow(b-2);
            for (int i=3;i<(b-2);i++) {
                a = a.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(Utils.bit(h,i))));
            }*/
            // Saves ~0.4ms per key when running signing tests.
            // TODO: are these bitflips the same for any hash function?
            h[0] = (h[0].toUByte() and 248.toUByte()).toByte()//TODO miki ???????????????
            h[b / 8 - 1] = h[b / 8 - 1] and 63
            h[b / 8 - 1] = h[b / 8 - 1] or 64
            a = Arrays.copyOfRange(h, 0, b / 8)

            A = spec.b.scalarMultiply(a)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalArgumentException("Unsupported hash algorithm")
        }

    }

    /**
     * Initialize directly from the hash.
     * getSeed() will return null if this constructor is used.
     *
     * @param spec the parameter specification for this key
     * @param h the private key
     * @throws IllegalArgumentException if hash length is wrong
     * @since 0.1.1
     */
    constructor(spec: EdDSAParameterSpec, h: ByteArray) {
        if (h.size != spec.curve.field.getb() / 4)
            throw IllegalArgumentException("hash length is wrong")

        this.seed = null
        this.h = h
        this.params = spec
        val b = spec.curve.field.getb()

        h[0] = (h[0].toUByte() and 248.toUByte()).toByte()//TODO miki ???????????????
        h[b / 8 - 1] = h[b / 8 - 1] and 63
        h[b / 8 - 1] = h[b / 8 - 1] or 64
        a = Arrays.copyOfRange(h, 0, b / 8)

        A = spec.b.scalarMultiply(a)
    }

    constructor(seed: ByteArray, h: ByteArray, a: ByteArray, A: GroupElement, spec: EdDSAParameterSpec) {
        this.seed = seed
        this.h = h
        this.a = a
        this.A = A
        this.params = spec
    }

    /**
     * @return the private key
     */
    fun geta(): ByteArray {
        return a
    }

    /**
     * @return the public key
     */
    fun getA(): GroupElement {
        return A
    }
}
