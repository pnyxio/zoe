package io.pnyx.zoe.ed25519

import io.pnyx.ed25519monero.ge_p3
import io.pnyx.ed25519monero.ge_scalarmult_base
import io.pnyx.ed25519monero.ge_scalarmult_p3
import io.pnyx.zoe.bytes.hexEnc
import io.pnyx.zoe.bytes.ubytes
import kotlinx.cinterop.*
import platform.posix.memcpy

class Xxx(val p: ge_p3) {
    override fun toString(): String {
        return "[${p.X[0]}:${p.X[1]}:${p.X.get(2)}:${p.X.get(3)}:${p.X.get(4)}:${p.X.get(5)}:${p.X.get(6)}]"
    }
}

class Yyy(val b: ByteArray) {
    override fun toString(): String {
        return b.hexEnc()
    }
}

class MemoryTest {


    //@Test
    fun test1() {
        println("//////////////////////////////////////")
        //val P: P3 = randEcScalar() * null.BPt
        val p = ll()

        println(p)
        println(withy(p))
        println("//////////////////////////////////////")
    }

    fun withy(y: Yyy): Yyy {
        val b = ByteArray(160)
        memScoped {
            val res = cValue<ge_p3> {}
            val _yy = cValue<ge_p3>()
            _yy.useContents {
                val _y = this
                memcpy(_y.ptr, b.refTo(0), 160)
                res.useContents {
                    //                ge_scalarmult_base(this.ptr, randEcScalar().ubytes.refTo(0))

                    ge_scalarmult_p3(this.ptr, randEcScalar().ubytes.refTo(0), _y.ptr)
                    memcpy(b.refTo(0), this.ptr, 160)
                }
            }
        }
//        }
        return Yyy(b)
    }

    fun ll(): Yyy {
        val b = ByteArray(160)
//        memcpy()
//        val kk = b.refTo(0)
//        val sr = StableRef.create(b)
//        val cp: CValuesRef<ge_p3> = sr.asCPointer().reinterpret()
//        ge_scalarmult_base(cp, randEcScalar().ubytes.refTo(0))
//        println(b.hexEnc())
//        val y = Yyy(b)
//        println(y)
//        return y
//        var k: ge_p3? = null
//        var xxx: Xxx
//        val stableRef = StableRef.create(res)
//        val voidPtr = stableRef.asCPointer()
//
            memScoped {
                val res = cValue<ge_p3> {}
                res.useContents {
                    ge_scalarmult_base(this.ptr, randEcScalar().ubytes.refTo(0))
                    memcpy(b.refTo(0), this.ptr, 160)
//                    println(p3.X[0])
//                    println(p3.X[1])
//                    println(p3.X.get(2))
//                    println(p3.X.get(3))
//                    println(p3.X.get(4))
//                    println(p3.X.get(5))
//                    println(p3.X.get(6))
//                    val xxx = Xxx(p3)
//                println(xxx)
//                    return xxx
                }
            }
//        }
        return Yyy(b)
    }
}

//    @Test
//    fun test1() {
//        println("//////////////////////////////////////")
//        //val P: P3 = randEcScalar() * null.BPt
//        val x = ll()
//        val h = x.useContents {
//            println(this.X.get(0))
//            println(this.X.get(1))
//            println(this.X.get(2))
//            println(this.X.get(3))
//            println(this.X.get(4))
//            println(this.X.get(5))
//            println(this.X.get(6))
//            this
//        }
//        println("//////////////////////////////////////")
//    }
//
//    fun ll(): CValue<ge_p3> {
//        val res = cValue<ge_p3> {}
//        res.useContents {
//            val p = this
//            ge_scalarmult_base(res, randEcScalar().ubytes.refTo(0))
//            println(this.X.get(0))
//            println(this.X.get(1))
//            println(this.X.get(2))
//            println(this.X.get(3))
//            println(this.X.get(4))
//            println(this.X.get(5))
//            println(this.X.get(6))
//        }
//        return res
//    }
//
//}
