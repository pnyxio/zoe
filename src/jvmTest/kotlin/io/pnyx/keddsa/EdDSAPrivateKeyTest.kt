package io.pnyx.keddsa


import io.pnyx.keddsa.Utils

import org.hamcrest.CoreMatchers.*
import org.junit.Assert.*

import java.security.spec.PKCS8EncodedKeySpec

import io.pnyx.keddsa.spec.EdDSAPrivateKeySpec

import org.junit.Test

class EdDSAPrivateKeyTest {

    @Test
    fun testDecodeAndEncode() {
        // Decode
        val encoded = PKCS8EncodedKeySpec(TEST_PRIVKEY)
        val keyIn = EdDSAPrivateKey(encoded)

        // Encode
        val decoded = EdDSAPrivateKeySpec(
            keyIn.seed!!,
            keyIn.h,
            keyIn.geta(),
            keyIn.getA(),
            keyIn.params
        )
        val keyOut = EdDSAPrivateKey(decoded)

        // Check
        assertThat(keyOut.encoded, `is`(equalTo(TEST_PRIVKEY)))
    }

    @Test
    fun testDecodeWithNullAndEncode() {
        // Decode
        val encoded = PKCS8EncodedKeySpec(TEST_PRIVKEY_NULL_PARAMS)
        val keyIn = EdDSAPrivateKey(encoded)

        // Encode
        val decoded = EdDSAPrivateKeySpec(
            keyIn.seed!!,
            keyIn.h,
            keyIn.geta(),
            keyIn.getA(),
            keyIn.params
        )
        val keyOut = EdDSAPrivateKey(decoded)

        // Check
        assertThat(keyOut.encoded, `is`(equalTo(TEST_PRIVKEY)))
    }

    @Test
    fun testReEncodeOldEncoding() {
        // Decode
        val encoded = PKCS8EncodedKeySpec(TEST_PRIVKEY_OLD)
        val keyIn = EdDSAPrivateKey(encoded)

        // Encode
        val decoded = EdDSAPrivateKeySpec(
            keyIn.seed!!,
            keyIn.h,
            keyIn.geta(),
            keyIn.getA(),
            keyIn.params
        )
        val keyOut = EdDSAPrivateKey(decoded)

        // Check
        assertThat(keyOut.encoded, `is`(equalTo(TEST_PRIVKEY)))
    }

    companion object {
        /**
         * The example private key MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
         * from https://tools.ietf.org/html/draft-ietf-curdle-pkix-04#section-10.3
         */
        internal val TEST_PRIVKEY =
            Utils.hexToBytes("302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842")

        internal val TEST_PRIVKEY_NULL_PARAMS =
            Utils.hexToBytes("3030020100300706032b6570050004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842")
        internal val TEST_PRIVKEY_OLD =
            Utils.hexToBytes("302f020100300806032b65640a01010420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842")
    }
}
