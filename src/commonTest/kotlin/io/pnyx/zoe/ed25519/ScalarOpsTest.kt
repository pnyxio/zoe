package io.pnyx.zoe.ed25519

import io.pnyx.zoe.bytes.UInt256
import io.pnyx.zoe.bytes.UInt512
import io.pnyx.zoe.bytes.hexDec
import kotlin.test.Test
import kotlin.test.assertTrue


class ScalarOpsTest {

    @Test
    fun testReduce() {
        val r =
            "b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f4044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d".hexDec()
        assertTrue(
            EdGroup.reduce(UInt512 of r).bytes contentEquals
            "f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404".hexDec()

        )
    }

    //TODO !!!!!!!!!
//    @Test
//    fun testScalCheck() {
//        repeat(1000) {
//            assertTrue { sc_check(randEcScalar().bytes.asUByteArray()) }
//            assertTrue { sc_check(EdGroup.reduce(UInt512 of Rand.get().randomBytes(64)).bytes.asUByteArray()) }
//        }
//    }

    @Test
    fun testMultiplyAndAdd() {
        // Example from test case 1
        val h = EcScalar of "86eabc8e4c96193d290504e7c600df6cf8d8256131ec2c138a3e7e162e525404".hexDec()
        val a = UInt256 of "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f".hexDec()
        val r = EcScalar of "f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404".hexDec()
        val S = EcScalar of "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b".hexDec()
        assertTrue {
            EdGroup.multiplyAndAdd(h, a, r).bytes contentEquals S.bytes
        }
    }

    @Test
    fun testOfInt() {
        assertTrue { EcScalar.SC_TWO.bytes contentEquals EcScalar.ofUInt(2u).bytes }
    }
}
