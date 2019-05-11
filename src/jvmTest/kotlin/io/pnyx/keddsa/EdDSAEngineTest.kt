package io.pnyx.keddsa


import org.hamcrest.CoreMatchers.equalTo
import org.hamcrest.CoreMatchers.`is`
import org.junit.Assert.assertThat

import java.nio.charset.Charset
import java.security.MessageDigest
import java.security.SignatureException

import io.pnyx.keddsa.spec.*

import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import sun.security.util.DerValue
import sun.security.x509.X509Key


class EdDSAEngineTest {

    @get:Rule
    public var exception = ExpectedException.none()

    @Test
    @Throws(Exception::class)
    fun testSign() {
        val spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!
        //Signature sgr = Signature.getInstance("EdDSA", "I2P");
        val sgr = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm))

        for (testCase in Ed25519TestVectors.testCases) {
            val privKey = EdDSAPrivateKeySpec(testCase.seed, spec)
            val sKey = EdDSAPrivateKey(privKey)
            sgr.initSign(sKey)

            sgr.update(testCase.message)

            assertThat(
                "Test case " + testCase.caseNum + " failed",
                sgr.sign(), `is`(equalTo(testCase.sig))
            )
        }
    }

    @Test
    @Throws(Exception::class)
    fun testVerify() {
        val spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!
        //Signature sgr = Signature.getInstance("EdDSA", "I2P");
        val sgr = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm))
        for (testCase in Ed25519TestVectors.testCases) {
            val pubKey = EdDSAPublicKeySpec(testCase.pk, spec)
            val vKey = EdDSAPublicKey(pubKey)
            sgr.initVerify(vKey)

            sgr.update(testCase.message)

            assertThat(
                "Test case " + testCase.caseNum + " failed",
                sgr.verify(testCase.sig), `is`(true)
            )
        }
    }

    /**
     * Checks that a wrong-length signature throws an IAE.
     */
    @Test
    @Throws(Exception::class)
    fun testVerifyWrongSigLength() {
        val spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!
        //Signature sgr = Signature.getInstance("EdDSA", "I2P");
        val sgr = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm))
        val pubKey = EdDSAPublicKeySpec(TEST_PK, spec)
        val vKey = EdDSAPublicKey(pubKey)
        sgr.initVerify(vKey)

        sgr.update(TEST_MSG)

        exception.expect(SignatureException::class.java)
        exception.expectMessage("signature length is wrong")
        sgr.verify(byteArrayOf(0))
    }

    @Test
    @Throws(Exception::class)
    fun testSignResetsForReuse() {
        val spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!
        val sgr = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm))
        val privKey = EdDSAPrivateKeySpec(TEST_SEED, spec)
        val sKey = EdDSAPrivateKey(privKey)
        sgr.initSign(sKey)

        // First usage
        sgr.update(byteArrayOf(0))
        sgr.sign()

        // Second usage
        sgr.update(TEST_MSG)
        assertThat("Second sign failed", sgr.sign(), `is`(equalTo(TEST_MSG_SIG)))
    }

    @Test
    @Throws(Exception::class)
    fun testVerifyResetsForReuse() {
        val spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!
        val sgr = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm))
        val pubKey = EdDSAPublicKeySpec(TEST_PK, spec)
        val vKey = EdDSAPublicKey(pubKey)
        sgr.initVerify(vKey)

        // First usage
        sgr.update(byteArrayOf(0))
        sgr.verify(TEST_MSG_SIG)

        // Second usage
        sgr.update(TEST_MSG)
        assertThat("Second verify failed", sgr.verify(TEST_MSG_SIG), `is`(true))
    }

    @Test
    @Throws(Exception::class)
    fun testSignOneShotMode() {
        val spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!
        val sgr = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm))
        val privKey = EdDSAPrivateKeySpec(TEST_SEED, spec)
        val sKey = EdDSAPrivateKey(privKey)
        sgr.initSign(sKey)
        sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE)

        sgr.update(TEST_MSG)

        assertThat("One-shot mode sign failed", sgr.sign(), `is`(equalTo(TEST_MSG_SIG)))
    }

    @Test
    @Throws(Exception::class)
    fun testVerifyOneShotMode() {
        val spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!
        val sgr = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm))
        val pubKey = EdDSAPublicKeySpec(TEST_PK, spec)
        val vKey = EdDSAPublicKey(pubKey)
        sgr.initVerify(vKey)
        sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE)

        sgr.update(TEST_MSG)

        assertThat("One-shot mode verify failed", sgr.verify(TEST_MSG_SIG), `is`(true))
    }

    @Test
    @Throws(Exception::class)
    fun testSignOneShotModeMultipleUpdates() {
        val spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!
        val sgr = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm))
        val privKey = EdDSAPrivateKeySpec(TEST_SEED, spec)
        val sKey = EdDSAPrivateKey(privKey)
        sgr.initSign(sKey)
        sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE)

        sgr.update(TEST_MSG)

        exception.expect(SignatureException::class.java)
        exception.expectMessage("update() already called")
        sgr.update(TEST_MSG)
    }

    @Test
    @Throws(Exception::class)
    fun testVerifyOneShotModeMultipleUpdates() {
        val spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!
        val pubKey = EdDSAPublicKeySpec(TEST_PK, spec)
        val sgr = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm))
        val vKey = EdDSAPublicKey(pubKey)
        sgr.initVerify(vKey)
        sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE)

        sgr.update(TEST_MSG)

        exception.expect(SignatureException::class.java)
        exception.expectMessage("update() already called")
        sgr.update(TEST_MSG)
    }

    @Test
    @Throws(Exception::class)
    fun testSignOneShot() {
        val spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!
        val privKey = EdDSAPrivateKeySpec(TEST_SEED, spec)
        val sgr = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm))
        val sKey = EdDSAPrivateKey(privKey)
        sgr.initSign(sKey)

        assertThat("signOneShot() failed", sgr.signOneShot(TEST_MSG), `is`(equalTo(TEST_MSG_SIG)))
    }

    @Test
    @Throws(Exception::class)
    fun testVerifyOneShot() {
        val spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!
        val pubKey = EdDSAPublicKeySpec(TEST_PK, spec)
        val sgr = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm))
        val vKey = EdDSAPublicKey(pubKey)
        sgr.initVerify(vKey)

        assertThat("verifyOneShot() failed", sgr.verifyOneShot(TEST_MSG, TEST_MSG_SIG), `is`(true))
    }

    @Test
    @Throws(Exception::class)
    fun testVerifyX509PublicKeyInfo() {
        val spec = EdDSANamedCurveTable.getByName("Ed25519")!!
        val sgr = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm))
        for (testCase in Ed25519TestVectors.testCases) {
            val pubKey = EdDSAPublicKeySpec(testCase.pk, spec)
            val vKey = EdDSAPublicKey(pubKey)
            val x509Key = X509Key.parse(DerValue(vKey.getEncoded()))
            sgr.initVerify(x509Key)

            sgr.update(testCase.message)

            assertThat(
                "Test case " + testCase.caseNum + " failed",
                sgr.verify(testCase.sig), `is`(true)
            )
        }
    }

    companion object {
        internal val TEST_SEED =
            Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
        internal val TEST_PK =
            Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")
        internal val TEST_MSG = "This is a secret message".toByteArray(Charset.forName("UTF-8"))
        internal val TEST_MSG_SIG =
            Utils.hexToBytes("94825896c7075c31bcb81f06dba2bdcd9dcf16e79288d4b9f87c248215c8468d475f429f3de3b4a2cf67fe17077ae19686020364d6d4fa7a0174bab4a123ba0f")
    }
}
