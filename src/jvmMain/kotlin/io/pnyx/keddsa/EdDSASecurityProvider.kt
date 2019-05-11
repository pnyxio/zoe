package io.pnyx.keddsa

import java.security.AccessController
import java.security.PrivilegedAction
import java.security.Provider
import java.security.Security

/**
 * A security [Provider] that can be registered via [Security.addProvider]
 *
 * @author str4d
 */
class EdDSASecurityProvider : Provider(PROVIDER_NAME, 0.3, "str4d $PROVIDER_NAME security provider wrapper") {
    init {

        AccessController.doPrivileged(PrivilegedAction<Any> {
            setup()
            null
        })
    }/* should match POM major.minor version */

    protected fun setup() {
        // See https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/HowToImplAProvider.html
        put("KeyFactory." + EdDSAKey.KEY_ALGORITHM, "net.i2p.crypto.eddsa.KeyFactory")
        put("KeyPairGenerator." + EdDSAKey.KEY_ALGORITHM, "net.i2p.crypto.eddsa.KeyPairGenerator")
        put("Signature." + EdDSAEngine.SIGNATURE_ALGORITHM, "net.i2p.crypto.eddsa.EdDSAEngine")

        // OID Mappings
        // See section "Mapping from OID to name".
        // The Key* -> OID mappings correspond to the default algorithm in KeyPairGenerator.
        //
        // From draft-ieft-curdle-pkix-04:
        //   id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
        put("Alg.Alias.KeyFactory.1.3.101.112", EdDSAKey.KEY_ALGORITHM)
        put("Alg.Alias.KeyFactory.OID.1.3.101.112", EdDSAKey.KEY_ALGORITHM)
        put("Alg.Alias.KeyPairGenerator.1.3.101.112", EdDSAKey.KEY_ALGORITHM)
        put("Alg.Alias.KeyPairGenerator.OID.1.3.101.112", EdDSAKey.KEY_ALGORITHM)
        put("Alg.Alias.Signature.1.3.101.112", EdDSAEngine.SIGNATURE_ALGORITHM)
        put("Alg.Alias.Signature.OID.1.3.101.112", EdDSAEngine.SIGNATURE_ALGORITHM)
    }

    companion object {
        private val serialVersionUID = 1210027906682292307L
        val PROVIDER_NAME = "EdDSA"
    }
}
