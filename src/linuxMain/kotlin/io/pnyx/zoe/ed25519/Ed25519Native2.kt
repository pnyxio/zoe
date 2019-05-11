package io.pnyx.zoe.ed25519

//import io.pnyx.ed25519monero.*
//import io.pnyx.zoe.bytes.*
//import io.pnyx.zoe.util.AutoMemory
//import kotlinx.cinterop.*
//
//private val __BASE__ = (PointParser.parse(CompressedPoint("5866666666666666666666666666666666666666666666666666666666666666".hexDec()), MemScope()) as P3Impl).p3
//
//
//actual fun zeroP3(memScope: AutoMemory?): P3 = P3Impl(ge_p3_identity.readValue())
//
//
//actual fun BasePoint(memScope: AutoMemory?): P3 = BasePointImpl()
//
//actual object PointParser {
//    actual fun parse(p: CompressedPoint, helper: AutoMemory?, precomp: Boolean/*TODO*/): P3 =
//        parseNative(p)
//    internal fun parseNative(p: CompressedPoint/*, boolean precomputeSingleAndDouble*/): P3 {
//        val p3 = cValue<ge_p3>()
//        memScoped {
//            require(ge_frombytes_vartime(p3.ptr, p.ubytes.refTo(0)) == 0) {
//                "ge_frombytes_vartime err: ${p.bytes.hexEnc()}"
//            }
//            return P3Impl(p3)
//        }
//    }
//}
//
//actual fun ge_fromfe_frombytes_vartime(s: FeLeUInt, memScope: AutoMemory?): P2 {
//    val p2 = cValue<ge_p2>()
//    memScoped {
//        io.pnyx.ed25519monero.ge_fromfe_frombytes_vartime(p2.ptr, s.ubytes.refTo(0))
//    }
//    return P2Impl(p2)
//}
//
//class BasePointImpl(): P3Impl(__BASE__) {
//    override fun scalarMultiply(scal: EcScalar): P3 {
//        val res = cValue<ge_p3>()
//        memScoped {
//            ge_scalarmult_base(res.ptr, scal.ubytes.refTo(0))
//        }
//        return P3Impl(res)
//    }
//    override fun doubleScalarMultiplyVariableTime(A: P3, a: LeUInt32, b: LeUInt32): P2 {
//        val res = cValue<ge_p2>()
//        memScoped {
//            ge_double_scalarmult_base_vartime(
//                res.ptr,
//                a.ubytes.refTo(0),
//                (A as P3Impl).p3.ptr,
//                b.ubytes.refTo(0))
//        }
//        return P2Impl(res)
//    }
//
//    override fun doubleScalarMultiplyVariableTimeP3(A: P3, a: LeUInt32, b: LeUInt32): P3 {
//        //TODO @see GroupElementMulTest.testDoubleScalarMultiplyVariableTime
//        return PointParser.parseNative(doubleScalarMultiplyVariableTime(A, a, b).compress())
////        val res: ge_p3 = P3Impl.allocStruct(autoMem)
////        ge_double_scalarmult_base_vartime_p3(
////            res.ptr,
////            a.ubytes.refTo(0),
////            (A as P3Impl).p3.ptr,
////            b.ubytes.refTo(0))
////        return P3Impl(res, autoMem)
//    }
//
//}
//
//
//actual object EdGroup: GroupOps {
//    override fun reduce(s: UInt512): EcScalar {
//        val ret = s.bytes.copyOf().asUByteArray()
//        sc_reduce(ret.refTo(0))
//        return EcScalar(ret.asByteArray().copyOfRange(0, 32))
//    }
//
//    override fun multiplyAndAdd(a: LeUInt32, b: LeUInt32, c: LeUInt32): EcScalar {
//        val ret = UByteArray(32)
//        sc_muladd(
//            ret.refTo(0),
//            a.ubytes.refTo(0),
//            b.ubytes.refTo(0),
//            c.ubytes.refTo(0))
//        return EcScalar(ret.asByteArray())
//    }
//
//}
//
//abstract class ComparableEcPointAutoMem(): Compressable {
//
//    override fun equals(other: Any?): Boolean {
//        val b = bytes
//        println("---------------------" +bytes.hexEnc())
//        println("=====================" +(other as Compressable).bytes.hexEnc())
//
//        return if(other is Compressable) bytes contentEquals other.bytes else false
//    }
//
//    override fun hashCode(): Int = bytes.contentHashCode()
//}
//
//internal class P2Impl(val p2: CValues<ge_p2>): P2, ComparableEcPointAutoMem() {
//    override fun toP2(): P2 = this
//
//    override fun compress(): CompressedPoint {
//        val u : UByteArray = UByteArray(32)
//        memScoped {
//            ge_tobytes(u.refTo(0), p2.ptr)
//        }
//        return u.toByteArray().asCompressedPoint()
//    }
//
//    override fun dbl(): P1P1 {
//        val p1p1 = cValue<ge_p1p1>()
//        memScoped {
//            ge_p2_dbl(p1p1.ptr,  p2.ptr)
//        }
//        return P1P1Impl(p1p1)
//    }
//
//    override fun mul8(): P1P1 {
//        val p1p1 = cValue<ge_p1p1>()
//        memScoped {
//            ge_mul8(p1p1.ptr, p2.ptr)
//        }
//        return P1P1Impl(p1p1)
//    }
//}
//
//internal class P1P1Impl(val p1p1: CValues<ge_p1p1>): P1P1, ComparableEcPointAutoMem() {
//    override fun toP2(): P2 {
//        val p2 = cValue<ge_p2>()
//        memScoped {
//            ge_p1p1_to_p2(p2.ptr, p1p1.ptr)
//        }
//        return P2Impl(p2)
//    }
//
//    override fun compress(): CompressedPoint = toP2().compress()
//
//    override fun toP3(precomp: Boolean): P3 {//TODO
//        val p3 = cValue<ge_p3>()
//        memScoped {
//            ge_p1p1_to_p3(p3.ptr, p1p1.ptr)
//        }
//        return P3Impl(p3)
//    }
//
//}
//
//open class P3Impl(val p3: CValues<ge_p3>): P3, ComparableEcPointAutoMem() {
//    init {
//        memScoped {
//            print(">>>>>> P3("+p3.ptr.pointed.X.get(0))
//        }
//    }
//    override fun negate(): P1P1  = zeroP3(null/*TODO remove*/).sub(toCached())
//
//
//    override fun doubleScalarMultiplyVariableTimeP3(A: P3, a: LeUInt32, b: LeUInt32): P3 {
//        //TODO @see GroupElementMulTest.testDoubleScalarMultiplyVariableTime
//         return PointParser.parseNative(doubleScalarMultiplyVariableTime(A, a, b).compress())
////        val res: ge_p3 = P3Impl.allocStruct(autoMem)
////        val ths_dsmp = autoMem.allocArray<ge_cached>(8)
////        ge_dsm_precomp(ths_dsmp , p3.ptr)
////        val A_dsmp = autoMem.allocArray<ge_cached>(8)
////        ge_dsm_precomp(A_dsmp , (A as P3Impl).p3.ptr)
////        ge_double_scalarmult_precomp_vartime2_p3(
////            res.ptr,
////            a.ubytes.refTo(0),
////            A_dsmp,
////            b.ubytes.refTo(0),
////            ths_dsmp
////        )
////        return P3Impl(res, autoMem)
//    }
//
//    override fun doubleScalarMultiplyVariableTime(A: P3, a: LeUInt32, b: LeUInt32): P2 {
//        val p2 = cValue<ge_p2>()
//        memScoped {
//            val ths_dsmp = allocArray<ge_cached>(8)//.reinterpret<ge_cached>()
//            ge_dsm_precomp(ths_dsmp , p3.ptr)
//            val A_dsmp = allocArray<ge_cached>(8)//.reinterpret<ge_cached>()
//            ge_dsm_precomp(A_dsmp , (A as P3Impl).p3.ptr)
//            ge_double_scalarmult_precomp_vartime2(
//                p2.ptr,
//                a.ubytes.refTo(0),
//                A_dsmp,//.ptr,
//                b.ubytes.refTo(0),
//                ths_dsmp//.ptr
//            )
//        }
//        return P2Impl(p2)
//    }
//
//    override fun scalarMultiply(scal: EcScalar): P3 {
//        val res = cValue<ge_p3>()
//        memScoped {
//            ge_scalarmult_p3(res.ptr, scal.ubytes.refTo(0), p3.ptr)
//        }
//        return P3Impl(res)
//    }
//
//    override fun toP2(): P2 {
//        val p2 = cValue<ge_p2>()
//        memScoped {
//            ge_p3_to_p2(p2.ptr, p3.ptr)
//        }
//        return P2Impl(p2)
//    }
//
//    override fun compress(): CompressedPoint {
//        val u = UByteArray(32)
//        memScoped {
//            ge_p3_tobytes(u.refTo(0), p3.ptr)
//        }
//        return u.toByteArray().asCompressedPoint()
//    }
//
//    override fun dbl(): P1P1 = toP2().dbl()
//
//    override fun mul8(): P1P1 = toP2().mul8()
//
//    override fun toCached(): Cached {
//        val cached = cValue<ge_cached>()
//        memScoped {
//            ge_p3_to_cached(cached.ptr,  p3.ptr)
//        }
//        return CachedImpl(cached)
//    }
//
////    override fun madd(other: Precomp): P1P1 {
////        val p1p1: ge_p1p1 = P1P1Impl.allocStruct(autoMem)
////        ge_madd(p1p1.ptr, p3.ptr, (other as PrecompImpl).precomp.ptr)
////        return P1P1Impl(p1p1, autoMem)
////    }
////
////    override fun msub(other: Precomp): P1P1 {
////        val p1p1: ge_p1p1 = P1P1Impl.allocStruct(autoMem)
////        ge_msub(p1p1.ptr, p3.ptr, (other as PrecompImpl).precomp.ptr)
////        return P1P1Impl(p1p1, autoMem)
////    }
//
//    override fun add(other: Cached): P1P1 {
//        val p1p1 = cValue<ge_p1p1>()
//        memScoped {
//            ge_add(p1p1.ptr, p3.ptr, (other as CachedImpl).cached.ptr)
//        }
//        return P1P1Impl(p1p1)
//    }
//
//    override fun sub(other: Cached): P1P1 {
//        val p1p1 = cValue<ge_p1p1>()
//        memScoped {
//            ge_sub(p1p1.ptr, p3.ptr, (other as CachedImpl).cached.ptr)
//        }
//        return P1P1Impl(p1p1)
//    }
//}
//
//internal class CachedImpl(val cached: CValues<ge_cached>): Cached {
//}
//
//internal class PrecompImpl(val precomp: ge_precomp): Precomp {
//}
//
//
//actual fun AutoMemory?.p3(X: Fe, Y: Fe, Z: Fe, T: Fe): P3 {
//    val p3 = cValue<ge_p3>()
//    memScoped {
//        new_ge_p3(p3.ptr, (X as FeImpl).e, (Y as FeImpl).e, (Z as FeImpl).e, (T as FeImpl).e)
//    }
//    return P3Impl(p3)
//}