package io.pnyx.zoe.ed25519

import io.pnyx.zoe.bytes.hexDec
import io.pnyx.zoe.ed25519.EcScalar.Companion.SC_ONE
import io.pnyx.zoe.ed25519.EcScalar.Companion.SC_TWO
import io.pnyx.zoe.ed25519.EcScalar.Companion.SC_ZERO
import io.pnyx.zoe.util.autoMem
import kotlin.test.Test
import kotlin.test.assertEquals


class GroupElementMulTest {

    @Test
    fun testScalarMultiplyByteArray() {
        autoMem {
            // Little-endian
//            val zero = "0000000000000000000000000000000000000000000000000000000000000000".hexDec()
//            val one = "0100000000000000000000000000000000000000000000000000000000000000".hexDec()
//            val two = "0200000000000000000000000000000000000000000000000000000000000000".hexDec()
            val a = "d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c".hexDec()
            val A = p3("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66".hexDec().asCompressedPoint())

            assertEquals(ZERO_P3, SC_ZERO * BPt)
            assertEquals(BPt, SC_ONE * BPt)
            assertEquals((SC_TWO * BPt) as EcPoint, BPt.dbl() as EcPoint)
            assertEquals(A, BPt.scalarMultiply(EcScalar(a)))//TODO EcScalar(a) a is not Scalar but uint255
        }
    }

    @Test
    fun scalarMultiplyBasePointWithZeroReturnsNeutralElement() {
        autoMem {
            // Arrange:
            val basePoint = BPt
            val g = SC_ZERO * basePoint
            assertEquals(ZERO_P3, g)
        }
    }

    @Test
    fun scalarMultiplyBasePointWithOneReturnsBasePoint() {
        autoMem {
            // Arrange:
            val basePoint = BPt
            val g = SC_ONE * basePoint
            assertEquals(BPt, g)
        }
    }


    @Test
    fun testDoubleScalarMultiplyVariableTime() {
        autoMem {
            // Little-endian
            val zero = "0000000000000000000000000000000000000000000000000000000000000000".hexDec().asEcScalar()
            val one = "0100000000000000000000000000000000000000000000000000000000000000".hexDec().asEcScalar()
            val two = "0200000000000000000000000000000000000000000000000000000000000000".hexDec().asEcScalar()
            val a = EcScalar("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c".hexDec())
            val A = p3("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66".hexDec().asCompressedPoint())
            val B = BPt
            val geZero = ZERO_P3

            // 0 * GE(0) + 0 * GE(0) = GE(0)
            assertEquals<Any>(geZero.doubleScalarMultiplyVariableTime(geZero, zero, zero), geZero)
            assertEquals(geZero.doubleScalarMultiplyVariableTime(geZero, zero, zero), geZero.toP2())
//            println(geZero.compress().bytes.hexEnc())
//            println(geZero.toP2().compress().bytes.hexEnc())
//            println(geZero.doubleScalarMultiplyVariableTime(geZero, zero, zero).compress().bytes.hexEnc())
//            println(geZero.doubleScalarMultiplyVariableTimeP3(geZero, zero, zero).compress().bytes.hexEnc())
            assertEquals(geZero.doubleScalarMultiplyVariableTimeP3(geZero, zero, zero), geZero)

            // 0 * GE(0) + 0 * B = GE(0)
            assertEquals<Any>(B.doubleScalarMultiplyVariableTime(geZero, zero, zero), geZero)
            assertEquals(B.doubleScalarMultiplyVariableTimeP3(geZero, zero, zero), geZero)

            // 1 * GE(0) + 0 * B = GE(0)
            assertEquals<Any>(B.doubleScalarMultiplyVariableTime(geZero, one, zero), geZero)
            assertEquals(B.doubleScalarMultiplyVariableTimeP3(geZero, one, zero), geZero)

            // 1 * GE(0) + 1 * B = B
            assertEquals<Any>(BPt.doubleScalarMultiplyVariableTime(geZero, one, one), B)
            assertEquals(BPt.doubleScalarMultiplyVariableTimeP3(geZero, one, one), B)
            // 1 * B + 1 * B = 2 * B
            assertEquals<Any>(B.doubleScalarMultiplyVariableTime(B, one, one), B.dbl())
            assertEquals(B.doubleScalarMultiplyVariableTimeP3(B, one, one), B.dbl().toP3())

            // 1 * B + 2 * B = 3 * B
            assertEquals<Any>(B.doubleScalarMultiplyVariableTime(B, one, two), B.dbl().toP3().add(B.toCached()))
            assertEquals<Any>(B.doubleScalarMultiplyVariableTimeP3(B, one, two), B.dbl().toP3().add(B.toCached()))

            //1 * A + 2 * A = 3 * A
//TODO jvm            assertEquals<Any>(A.doubleScalarMultiplyVariableTime(A, one, two), A.dbl().toP3().add(A.toCached()))
//TODO jvm            assertEquals<Any>(A.doubleScalarMultiplyVariableTimeP3(A, one, two), A.dbl().toP3().add(A.toCached()))

            // 2 * B + 2 * B = 4 * B
            assertEquals<Any>(B.doubleScalarMultiplyVariableTime(B, two, two), B.dbl().toP3().dbl())
            assertEquals<Any>(B.doubleScalarMultiplyVariableTimeP3(B, two, two), B.dbl().toP3().dbl())

            // 0 * B + a * B = A
            assertEquals<Any>(B.doubleScalarMultiplyVariableTime(B, zero, a), A)
            assertEquals(B.doubleScalarMultiplyVariableTimeP3(B, zero, a), A)

            // a * B + 0 * B = A
            assertEquals<Any>(B.doubleScalarMultiplyVariableTime(B, a, zero), A)
            assertEquals(B.doubleScalarMultiplyVariableTimeP3(B, a, zero), A)

            // a * B + a * B = 2 * A
            assertEquals<Any>(B.doubleScalarMultiplyVariableTimeP3(B, a, a), A.dbl())
            assertEquals<Any>(B.doubleScalarMultiplyVariableTime(B, a, a), A.dbl())
        }
    }

    // This test is slow (~6s) due to math utils using an inferior algorithm to calculate the result.
//TODO jvm
//    @Test
//    fun doubleScalarMultiplyVariableTimeReturnsExpectedResult() {
//        autoMem {
//            for (i in 0..9) {
//                // Arrange:
//                val basePoint = BPt
//                val g = randEcScalar() * BPt //randomGroupElement
//                val f1 = randEcScalar()
//                val f2 = randEcScalar()
//
//                // Act: B * f1 + g * f2
//                val h1 = basePoint.doubleScalarMultiplyVariableTime(g, f2, f1)
//                val h2 = (f1 * basePoint) + (f2 * g)
//
//                // Assert:
//                assertEquals(h1, h2.toP2())
//            }
//        }
//    }

}
