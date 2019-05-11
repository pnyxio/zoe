package io.pnyx.zoe.ed25519

import io.pnyx.zoe.ed25519.EcScalar.Companion.SC_FOUR
import io.pnyx.zoe.ed25519.EcScalar.Companion.SC_ONE
import io.pnyx.zoe.ed25519.EcScalar.Companion.SC_TWO
import io.pnyx.zoe.util.autoMem
import kotlin.test.Test
import kotlin.test.assertTrue

class GroupElementTest {

    @Test
    fun testDbl() {
        autoMem {
            val B = BPt
            assertTrue {
                B.dbl() == B.add(B.toCached())
            }
            assertTrue {
                (B + B) == B.add(B.toCached())
            }
            assertTrue {
                B.dbl() == (B + B)
            }
            assertTrue {
                B.dbl() == SC_TWO * B
            }
        }
    }

    @Test
    fun testScalMul() {
        autoMem {
            val B = BPt
            val _16 = SC_FOUR * SC_FOUR
            val _17 = _16 + SC_ONE
            assertTrue {
                (_17 * B) == B + (_16 * B)
            }
            assertTrue {
                (SC_FOUR * B) == (B + B).toP3() + (B + B).toP3()
            }
        }
    }

    @Test
    fun testNegate() {
        autoMem {
            val A =
                ZERO_P3//TODO p3("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66".hexDec().asCompressedPoint())
            val B = BPt
            val AminusB = A - B
            val AminusB2 = A + B.negate().toP3()
            assertTrue {
                AminusB == AminusB2
            }
        }
    }

}
