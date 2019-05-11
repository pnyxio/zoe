package io.pnyx.keddsa.math

import org.hamcrest.CoreMatchers.*


import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

import io.pnyx.keddsa.spec.*
import org.junit.Assert.*

import org.junit.Test

class ConstantsTest {

    @Test
    fun testb() {
        val b = curve.field.getb()
        assertTrue(b >= 10)
        try {
            val h = MessageDigest.getInstance(ed25519.hashAlgorithm)
            assertThat(8 * h.digestLength, `is`(equalTo(2 * b)))
        } catch (e: NoSuchAlgorithmException) {
            fail(e.message)
        }

    }

    /*@Test
    public void testq() {
        FieldElement q = curve.field.getQ();
        assertThat(TWO.modPow(q.subtractOne(), q), is(equalTo(ONE)));
        assertThat(q.mod(curve.field.FOUR), is(equalTo(ONE)));
    }

    @Test
    public void testl() {
        int b = curve.field.getb();
        BigInteger l = ed25519.getL();
        assertThat(TWO.modPow(l.subtract(BigInteger.ONE), l), is(equalTo(ONE)));
        assertThat(l, is(greaterThanOrEqualTo(BigInteger.valueOf(2).pow(b-4))));
        assertThat(l, is(lessThanOrEqualTo(BigInteger.valueOf(2).pow(b-3))));
    }

    @Test
    public void testd() {
        FieldElement q = curve.field.getQ();
        FieldElement qm1 = q.subtractOne();
        assertThat(curve.getD().modPow(qm1.divide(curve.field.TWO), q), is(equalTo(qm1)));
    }

    @Test
    public void testI() {
        FieldElement q = curve.field.getQ();
        assertThat(curve.getI().modPow(curve.field.TWO, q), is(equalTo(q.subtractOne())));
    }*/

    @Test
    fun testB() {
        val B = ed25519.b
        assertThat(B.isOnCurve(curve), `is`(true))
        //assertThat(B.scalarMultiply(new BigIntegerLittleEndianEncoding().encode(ed25519.getL(), curve.field.getb()/8)), is(equalTo(P3_ZERO)));
    }

    companion object {
        internal val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!
        internal val curve = ed25519.curve

        internal val ZERO = curve.field.ZERO
        internal val ONE = curve.field.ONE
        internal val TWO = curve.field.TWO

        internal val P3_ZERO = GroupElement.p3(curve, ZERO, ONE, ONE, ZERO)
    }
}
