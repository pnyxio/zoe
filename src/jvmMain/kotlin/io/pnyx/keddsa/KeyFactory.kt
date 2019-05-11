package io.pnyx.keddsa

import java.security.InvalidKeyException
import java.security.Key
import java.security.KeyFactorySpi
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

import io.pnyx.keddsa.spec.EdDSAPrivateKeySpec
import io.pnyx.keddsa.spec.EdDSAPublicKeySpec

@Suppress("UNUSED")
class KeyFactory : KeyFactorySpi() {

    @Throws(InvalidKeySpecException::class)
    override fun engineGeneratePrivate(keySpec: KeySpec): PrivateKey {
        if (keySpec is EdDSAPrivateKeySpec) {
            return EdDSAPrivateKey(keySpec)
        }
        if (keySpec is PKCS8EncodedKeySpec) {
            return EdDSAPrivateKey(keySpec)
        }
        throw InvalidKeySpecException("key spec not recognised: " + keySpec.javaClass)
    }

    @Throws(InvalidKeySpecException::class)
    override fun engineGeneratePublic(keySpec: KeySpec): PublicKey {
        if (keySpec is EdDSAPublicKeySpec) {
            return EdDSAPublicKey(keySpec)
        }
        if (keySpec is X509EncodedKeySpec) {
            return EdDSAPublicKey(keySpec)
        }
        throw InvalidKeySpecException("key spec not recognised: " + keySpec.javaClass)
    }

    @Throws(InvalidKeySpecException::class)
    override fun <T : KeySpec> engineGetKeySpec(key: Key, keySpec: Class<T>): T {
        if (keySpec.isAssignableFrom(EdDSAPublicKeySpec::class.java) && key is EdDSAPublicKey) {
//            if (key.params != null) {
                @Suppress("UNCHECKED_CAST")
                return EdDSAPublicKeySpec(key.a, key.params) as T
//            }
        } else if (keySpec.isAssignableFrom(EdDSAPrivateKeySpec::class.java) && key is EdDSAPrivateKey) {
//            if (key.params != null) {
                @Suppress("UNCHECKED_CAST")
                return EdDSAPrivateKeySpec(key.seed!!, key.h, key.geta(), key.getA(), key.params) as T
//            }
        }
        throw InvalidKeySpecException("not implemented yet $key $keySpec")
    }

    @Throws(InvalidKeyException::class)
    override fun engineTranslateKey(key: Key): Key {
        throw InvalidKeyException("No other EdDSA key providers known")
    }
}
