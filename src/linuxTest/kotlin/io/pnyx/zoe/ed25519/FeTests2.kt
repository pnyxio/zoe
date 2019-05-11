package io.pnyx.zoe.ed25519

import io.pnyx.zoe.bytes.hexDec
import io.pnyx.zoe.bytes.hexEnc
import kotlin.test.assertTrue

class FeTests2 {
//    @Test
    fun testSquare() {
//        val ser = "83efb774657700e37291f4b8dd10c839d1c739fd135c07a2fd7382334dafdd6a".hexDec()
        val ser = "5c380f98794ab7a9be7c2d3259b92772125ce93527be6a76210631fdd8001498".hexDec()
//                            5c380f98794ab7a9be7c2d3259b92772125ce93527be6a76210631fdd8001418
        val fe = FeVal.parse(ser)
        println("====================================")
        println(fe.bytes.hexEnc())
        println("====================================")
        assertTrue { ser contentEquals  fe.bytes }
    }
}