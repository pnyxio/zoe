package io.pnyx.zoe.ed25519

import io.pnyx.zoe.bytes.UInt256
import io.pnyx.zoe.bytes.UInt512
import io.pnyx.zoe.bytes.asUInt256
import io.pnyx.zoe.bytes.hexDec
import kotlin.test.Test
import kotlin.test.assertTrue

class FeMathsTest {

    @Test
    fun illFormedHexStrings() {
        assertTrue {
            true//TODO
        }
    }

    //TODO !!!! @Test
    fun testReduceModGroupOrder() {
        val r = "b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f4044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d".hexDec()
        assertTrue {
            EdGroup.reduce(UInt512 of r).bytes contentEquals  "f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404".hexDec()
        }
    }

    //TODO !!!! @Test
    fun testMultiplyAndAdd() {
        val h = "86eabc8e4c96193d290504e7c600df6cf8d8256131ec2c138a3e7e162e525404".hexDec()
        val a = "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f".hexDec()
        val r = "f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404".hexDec()
        val S = "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b".hexDec()
        assertTrue {
            S contentEquals EdGroup.multiplyAndAdd(h.asUInt256(), UInt256 of a , UInt256 of r).bytes
        }
    }

//    @Test
//    fun testMultiplyAndAdd() {
//        val h = "86eabc8e4c96193d290504e7c600df6cf8d8256131ec2c138a3e7e162e525404".hexDecode().castToScalar()
//        val a = "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f".hexDecode().castToScalar()
//        val r = "f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404".hexDecode().castToScalar()
//        val S = "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b".hexDecode().castToScalar()
//        assertEquals(S, h * a + r)//assertArrayEquals(scalarOps.multiplyAndAdd(h, a, r), S)
//    }

}