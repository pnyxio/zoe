package io.pnyx.keddsa

import java.security.InvalidAlgorithmParameterException
import java.security.InvalidParameterException
import java.security.KeyPair
import java.security.KeyPairGeneratorSpi
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import java.util.Hashtable

import io.pnyx.keddsa.spec.*


class KeyPairGenerator : KeyPairGeneratorSpi() {
    private var edParams: EdDSAParameterSpec? = null
    private var random: SecureRandom? = null
    private var initialized: Boolean = false

    override fun initialize(keysize: Int, random: SecureRandom) {
        val edParams = edParameters[Integer.valueOf(keysize)!!] ?: throw InvalidParameterException("unknown key type.")
        try {
            initialize(edParams, random)
        } catch (e: InvalidAlgorithmParameterException) {
            throw InvalidParameterException("key type not configurable.")
        }

    }

    @Throws(InvalidAlgorithmParameterException::class)
    override fun initialize(params: AlgorithmParameterSpec?, random: SecureRandom?) {
        if (params is EdDSAParameterSpec) {
            edParams = params
        } else if (params is EdDSAGenParameterSpec) {
            edParams = createNamedCurveSpec((params).name)
        } else
            throw InvalidAlgorithmParameterException("parameter object not a EdDSAParameterSpec")

        this.random = random
        initialized = true
    }

    override fun generateKeyPair(): KeyPair {
        if (!initialized)
            initialize(DEFAULT_KEYSIZE, SecureRandom())

        val seed = ByteArray(edParams!!.curve.field.getb() / 8)
        random!!.nextBytes(seed)

        val privKey = EdDSAPrivateKeySpec(seed, edParams!!)
        val pubKey = EdDSAPublicKeySpec(privKey.getA(), edParams!!)

        return KeyPair(EdDSAPublicKey(pubKey), EdDSAPrivateKey(privKey))
    }

    /**
     * Create an EdDSANamedCurveSpec from the provided curve name. The current
     * implementation fetches the pre-created curve spec from a table.
     * @param curveName the EdDSA named curve.
     * @return the specification for the named curve.
     * @throws InvalidAlgorithmParameterException if the named curve is unknown.
     */
    @Throws(InvalidAlgorithmParameterException::class)
    protected fun createNamedCurveSpec(curveName: String): EdDSANamedCurveSpec {
        return EdDSANamedCurveTable.getByName(curveName)
            ?: throw InvalidAlgorithmParameterException("unknown curve name: $curveName")
    }

    companion object {
        private val DEFAULT_KEYSIZE = 256

        private val edParameters: Hashtable<Int, AlgorithmParameterSpec>

        init {
            edParameters = Hashtable()

            edParameters[Integer.valueOf(256)!!] = EdDSAGenParameterSpec(EdDSANamedCurveTable.ED_25519)
        }
    }
}
