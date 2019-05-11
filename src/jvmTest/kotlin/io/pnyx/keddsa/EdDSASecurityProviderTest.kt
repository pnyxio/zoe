package io.pnyx.keddsa


import org.junit.Test
import java.security.*
import java.security.KeyFactory
import java.security.KeyPairGenerator

class EdDSASecurityProviderTest {



    @Suppress("UNUSED_VARIABLE")
    @Test
    fun canGetInstancesWhenProviderIsPresent() {
        Security.addProvider(EdDSASecurityProvider())


        val keyGen = KeyPairGenerator.getInstance("EdDSA", "EdDSA")
        val keyFac = KeyFactory.getInstance("EdDSA", "EdDSA")
        val sgr = Signature.getInstance("NONEwithEdDSA", "EdDSA")

        Security.removeProvider("EdDSA")
    }

    @Suppress("UNUSED_VARIABLE")
    @Test
    fun cannotGetInstancesWhenProviderIsNotPresent() {
        try {
            val keyGen = KeyPairGenerator.getInstance("EdDSA", "EdDSA")
        } catch(e: NoSuchProviderException) {}
        catch (e1: NoSuchAlgorithmException) {}
    }
}
