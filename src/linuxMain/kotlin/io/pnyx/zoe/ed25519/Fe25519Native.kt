package io.pnyx.zoe.ed25519

import io.pnyx.ed25519monero.*
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.refTo

//import io.pnyx.keddsa.math.FieldElement
//import io.pnyx.keddsa.math.ed22519.Ed25519FieldElement
//import io.pnyx.keddsa.math.ed22519.Ed25519LittleEndianEncoding
//import io.pnyx.keddsa.math.ed22519.Ed25519ScalarOps
//import io.pnyx.keddsa.spec.EdDSACurveSpec.curve
//
//private val enc = Ed25519LittleEndianEncoding()
//private val ops = Ed25519ScalarOps()
//
//actual val fe_0: Fe = FeImpl(curve.field.ZERO)
//actual val fe_1: Fe = FeImpl(curve.field.ONE)
//actual val fe_2: Fe = FeImpl(curve.field.TWO)
actual object FeVal {
    actual val fe0: Fe get() {
        val res = new_fe()
        fe_0(res)
        return FeImpl(res)
    }
    actual val fe1: Fe get() {
        val res = new_fe()
        fe_1(res)
        return FeImpl(res)
    }
    actual val fe2: Fe get() = fe1 + fe1

    actual val fe_d get() = parse(intArrayOf(-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116))

    actual val fe_sqrtm1 get() = parse(intArrayOf(-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482)) /* sqrt(-1) */

    actual fun parse(bytes: ByteArray): Fe {
        memScoped {
            val res: fe = new_fe()//IntArray(10).refTo(0).getPointer(this)

            fe_frombytes(res, bytes.asUByteArray().refTo(0));
            return FeImpl(res)
        }
    }

    actual fun parse(ints: IntArray): Fe {
        return FeImpl(ints.refTo(0) as fe)
    }


}


//
//
//actual object FeParser {
//    actual fun parse(bytes: ByteArray): Fe = FeImpl(enc.decode(bytes))
//    actual fun parse(ints: IntArray): Fe = FeImpl(Ed25519FieldElement(curve.field, ints))
//}
//
//class FeImpl(val fe: FieldElement): Fe {
//    override val bytes: ByteArray get() = enc.encode(fe)
//
//    override val isNonZero: Boolean get() = fe.isNonZero
//
//    override val isNegative: Boolean get() = fe.isNegative
//
//    override fun invert() = FeImpl(fe.invert())
//
//    override fun add(value: Fe) = FeImpl(fe.add((value as FeImpl).fe))
//
//    override fun addOne() = FeImpl(fe.addOne())
//
//    override fun subtract(value: Fe) = FeImpl(fe.subtract((value as FeImpl).fe))
//
//    override fun subtractOne() = FeImpl(fe.subtractOne())
//
//    override fun negate() = FeImpl(fe.negate())
//
//    override fun divide(value: Fe) = FeImpl(fe.divide((value as FeImpl).fe))
//
//    override fun multiply(value: Fe) = FeImpl(fe.multiply((value as FeImpl).fe))
//
//    override fun square() = FeImpl(fe.square())
//
//    override fun squareAndDouble() = FeImpl(fe.squareAndDouble())
//
//    override fun pow22523() = FeImpl(fe.pow22523())
//}





private fun new_fe(): fe {
    memScoped {
        val res: fe = IntArray(10).refTo(0).getPointer(this)
        return res
    }

}

private fun unwrap(value: Fe) = (value as FeImpl).e

class FeImpl(val e: fe): Fe {

    override val bytes: ByteArray get() {
        val res = UByteArray(32)
        fe_tobytes(res.refTo(0), e)
        return res.asByteArray()
    }

    override val isNonZero: Boolean get() = fe_isnonzero(e) != 0


    override val isNegative: Boolean get() = fe_isnegative(e) != 0

    override fun invert(): Fe {
        val res = new_fe()
        fe_invert(res, e)
        return FeImpl(res)
    }

    override fun add(value: Fe): Fe {
        val res = new_fe()
        fe_add(res, e, unwrap(value))
        return FeImpl(res)
    }

//    override fun addOne(): Fe = this.add(fe_1)

    override fun subtract(value: Fe): Fe {
        val res = new_fe()
        fe_sub(res, e, unwrap(value))
        return FeImpl(res)
    }

//    override fun subtractOne(): Fe = this.subtract(fe_1)

    override fun negate(): Fe {
        val res = new_fe()
        fe_neg(res, e)
        return FeImpl(res)
    }

    override fun multiply(value: Fe): Fe {
        val res = new_fe()
        fe_mul(res, e, unwrap(value))
        return FeImpl(res)
    }

    override fun square(): Fe {
        val res = new_fe()
        fe_sq(res, e)
        return FeImpl(res)
    }

    override fun squareAndDouble(): Fe {
        val res = new_fe()
        fe_sq2(res, e)
        return FeImpl(res)
    }

    override fun pow22523(): Fe {
        val res = new_fe()
        fe_pow22523(res, e)
        return FeImpl(res)
    }

//    override fun divPowM1(u: Fe, v: Fe): Fe {
//        val res = new_fe()
//        fe_divpowm1(res, unwrap(u), unwrap(v))
//        return FeImpl(res)
//    }

}



