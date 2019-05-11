package io.pnyx.keddsa

import io.pnyx.keddsa.EdDSAKey.Companion.KEY_ALGORITHM
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import java.util.Arrays

import io.pnyx.keddsa.math.GroupElement
import io.pnyx.keddsa.spec.EdDSANamedCurveTable
import io.pnyx.keddsa.spec.EdDSAParameterSpec
import io.pnyx.keddsa.spec.EdDSAPublicKeySpec


/**
 * An EdDSA public key.
 *
 *
 * Warning: Public key encoding is is based on the current curdle WG draft,
 * and is subject to change. See getEncoded().
 *
 *
 * For compatibility with older releases, decoding supports both the old and new
 * draft specifications. See decode().
 *
 *
 * Ref: https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
 *
 *
 * Old Ref: https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-04
 *
 * @author str4d
 */
class EdDSAPublicKey(spec: EdDSAPublicKeySpec) : EdDSAKey, PublicKey {
    val a: GroupElement
    private var Aneg: GroupElement? = null
    val abyte: ByteArray
    override val params: EdDSAParameterSpec

    // Only read Aneg once, otherwise read re-ordering might occur between here and return. Requires all GroupElement's fields to be final.
    val negativeA: GroupElement?
        get() {
            var ourAneg = Aneg
            if (ourAneg == null) {
                ourAneg = a.negate()
                Aneg = ourAneg
            }
            return ourAneg
        }

    init {
        this.a = spec.a
        this.abyte = this.a.toByteArray()
        this.params = spec.params
    }

    @Throws(InvalidKeySpecException::class)
    constructor(spec: X509EncodedKeySpec) : this(
        EdDSAPublicKeySpec(
            decode(spec.encoded),
            EdDSANamedCurveTable.ED_25519_CURVE_SPEC
        )
    )

    override fun getAlgorithm(): String {
        return KEY_ALGORITHM
    }

    override fun getFormat(): String {
        return "X.509"
    }

    /**
     * Returns the public key in its canonical encoding.
     *
     *
     * This implements the following specs:
     *  *
     * General encoding: https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
     *  *
     * Key encoding: https://tools.ietf.org/html/rfc8032
     *
     *
     *
     * For keys in older formats, decoding and then re-encoding is sufficient to
     * migrate them to the canonical encoding.
     *
     * Relevant spec quotes:
     * <pre>
     * In the X.509 certificate, the subjectPublicKeyInfo field has the
     * SubjectPublicKeyInfo type, which has the following ASN.1 syntax:
     *
     * SubjectPublicKeyInfo  ::=  SEQUENCE  {
     * algorithm         AlgorithmIdentifier,
     * subjectPublicKey  BIT STRING
     * }
    </pre> *
     *
     * <pre>
     * AlgorithmIdentifier  ::=  SEQUENCE  {
     * algorithm   OBJECT IDENTIFIER,
     * parameters  ANY DEFINED BY algorithm OPTIONAL
     * }
     *
     * For all of the OIDs, the parameters MUST be absent.
    </pre> *
     *
     * <pre>
     * id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
    </pre> *
     *
     * @return 44 bytes for Ed25519, null for other curves
     */
    override fun getEncoded(): ByteArray? {
        if (!params.equals(EdDSANamedCurveTable.ED_25519_CURVE_SPEC))
            return null
        val totlen = 12 + abyte.size
        val rv = ByteArray(totlen)
        var idx = 0
        // sequence
        rv[idx++] = 0x30
        rv[idx++] = (totlen - 2).toByte()
        // Algorithm Identifier
        // sequence
        rv[idx++] = 0x30
        rv[idx++] = 5
        // OID
        // https://msdn.microsoft.com/en-us/library/windows/desktop/bb540809%28v=vs.85%29.aspx
        rv[idx++] = 0x06
        rv[idx++] = 3
        rv[idx++] = (1 * 40 + 3).toByte()
        rv[idx++] = 101
        rv[idx++] = OID_ED25519.toByte()
        // params - absent
        // the key
        rv[idx++] = 0x03 // bit string
        rv[idx++] = (1 + abyte.size).toByte()
        rv[idx++] = 0 // number of trailing unused bits
        System.arraycopy(abyte, 0, rv, idx, abyte.size)
        return rv
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(abyte)
    }

    override fun equals(other: Any?): Boolean {
        if (other === this)
            return true
        if (other !is EdDSAPublicKey)
            return false
        val pk = other as EdDSAPublicKey?
        return Arrays.equals(abyte, pk!!.abyte) && params.equals(pk.params)
    }

    companion object {
        private val serialVersionUID = 9837459837498475L

        // OID 1.3.101.xxx
        private val OID_OLD = 100
        private val OID_ED25519 = 112
        private val OID_BYTE = 8
        private val IDLEN_BYTE = 3

        /**
         * Extracts the public key bytes from the provided encoding.
         *
         *
         * This will decode data conforming to the current spec at
         * https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
         * or the old spec at
         * https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-04.
         *
         *
         * Contrary to draft-ietf-curdle-pkix-04, it WILL accept a parameter value
         * of NULL, as it is required for interoperability with the default Java
         * keystore. Other implementations MUST NOT copy this behaviour from here
         * unless they also need to read keys from the default Java keystore.
         *
         *
         * This is really dumb for now. It does not use a general-purpose ASN.1 decoder.
         * See also getEncoded().
         *
         *
         * @return 32 bytes for Ed25519, throws for other curves
         */
        @Throws(InvalidKeySpecException::class)
        private fun decode(d: ByteArray): ByteArray {
            try {
                //
                // Setup and OID check
                //
                var totlen = 44
                var idlen = 5
                val doid = d[OID_BYTE].toInt()
                if (doid == OID_OLD) {
                    totlen = 47
                    idlen = 8
                } else if (doid == OID_ED25519) {
                    // Detect parameter value of NULL
                    if (d[IDLEN_BYTE].toInt() == 7) {
                        totlen = 46
                        idlen = 7
                    }
                } else {
                    throw InvalidKeySpecException("unsupported key spec")
                }

                //
                // Pre-decoding check
                //
                if (d.size != totlen) {
                    throw InvalidKeySpecException("invalid key spec length")
                }

                //
                // Decoding
                //
                var idx = 0
                if (d[idx++].toInt() != 0x30 ||
                    d[idx++].toInt() != totlen - 2 ||
                    d[idx++].toInt() != 0x30 ||
                    d[idx++].toInt() != idlen ||
                    d[idx++].toInt() != 0x06 ||
                    d[idx++].toInt() != 3 ||
                    d[idx++].toInt() != 1 * 40 + 3 ||
                    d[idx++].toInt() != 101
                ) {
                    throw InvalidKeySpecException("unsupported key spec")
                }
                idx++ // OID, checked above
                // parameters only with old OID
                if (doid == OID_OLD) {
                    if (d[idx++].toInt() != 0x0a ||
                        d[idx++].toInt() != 1 ||
                        d[idx++].toInt() != 1
                    ) {
                        throw InvalidKeySpecException("unsupported key spec")
                    }
                } else {
                    // Handle parameter value of NULL
                    //
                    // Quote https://tools.ietf.org/html/draft-ietf-curdle-pkix-04 :
                    //   For all of the OIDs, the parameters MUST be absent.
                    //   Regardless of the defect in the original 1997 syntax,
                    //   implementations MUST NOT accept a parameters value of NULL.
                    //
                    // But Java's default keystore puts it in (when decoding as
                    // PKCS8 and then re-encoding to pass on), so we must accept it.
                    if (idlen == 7) {
                        if (d[idx++].toInt() != 0x05 || d[idx++].toInt() != 0) {
                            throw InvalidKeySpecException("unsupported key spec")
                        }
                    }
                }
                if (d[idx++].toInt() != 0x03 ||
                    d[idx++].toInt() != 33 ||
                    d[idx++].toInt() != 0
                ) {
                    throw InvalidKeySpecException("unsupported key spec")
                }
                val rv = ByteArray(32)
                System.arraycopy(d, idx, rv, 0, 32)
                return rv
            } catch (ioobe: IndexOutOfBoundsException) {
                throw InvalidKeySpecException(ioobe)
            }

        }
    }
}
