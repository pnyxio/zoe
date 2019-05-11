package io.pnyx.zoe.ed25519

import io.pnyx.ed25519monero.ge_p3
import io.pnyx.ed25519monero.ge_scalarmult_base
import io.pnyx.zoe.bytes.ubytes
import io.pnyx.zoe.util.AutoMemory
import io.pnyx.zoe.util.autoMem
import kotlinx.cinterop.cValue
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.refTo
import kotlin.test.assertEquals

class MemoryTest2 {

    //@Test
    fun test1() {
        println("=========================== MEMORY")
        for (i in 0..1_000_000_000) {
            autoMem {
                perform()
                if(i % 100000 == 0) {
                        println(i)
                }
            }
        }
        println("==END MEMORY")

    }

    private fun AutoMemory?.perform() {
        val P: P3 = randEcScalar() * BPt
        val P2 = P + P
        val P3 = ((P + P).toP3() + P).toP3() - P
        assertEquals(P2, P3)
        //scalarMultiply(randEcScalar())
    }

    fun scalarMultiply(scal: EcScalar) {
        val res = cValue<ge_p3> {}
        memScoped {
            ge_scalarmult_base(res.ptr, scal.ubytes.refTo(0))
        }
    }

}