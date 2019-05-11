package io.pnyx.zoe.ed25519

//private val __BASE__ = (PointParser.parse(CompressedPoint("5866666666666666666666666666666666666666666666666666666666666666".hexDec()), MemScope()) as P3Impl).p3
//
//
//actual fun zeroP3(memScope: AutoMemory?): P3 = P3Impl(ge_p3_identity, memScope!!)
//
//
//actual fun BasePoint(memScope: AutoMemory?): P3 = BasePointImpl(memScope)
//
//actual object PointParser {
//    actual fun parse(p: CompressedPoint, helper: AutoMemory?, precomp: Boolean/*TODO*/): P3 =
//        parseNative(p, helper!! as NativePlacement)
//    internal fun parseNative(p: CompressedPoint/*, boolean precomputeSingleAndDouble*/, autoMem: NativePlacement): P3 {
//        val p3 = P3Impl.allocStruct(autoMem)
//        require(ge_frombytes_vartime(p3.ptr, p.ubytes.refTo(0)) == 0) {
//            "ge_frombytes_vartime err: ${p.bytes.hexEnc()}"
//        }
//        return P3Impl(p3, autoMem)
//    }
//}
//
//actual fun ge_fromfe_frombytes_vartime(s: FeLeUInt, memScope: AutoMemory?): P2 {
//    val p2 = P2Impl.allocStruct(memScope!!)
//    ge_fromfe_frombytes_vartime(p2.ptr, s.ubytes.refTo(0))
//    return P2Impl(p2, memScope)
//}
//
//class BasePointImpl(memScope: AutoMemory?): P3Impl(__BASE__, memScope!!/* ?: nativeHeap*/) {
//    override fun scalarMultiply(scal: EcScalar): P3 {
//        val res: ge_p3 = P3Impl.allocStruct(autoMem)
//        ge_scalarmult_base(res.ptr, scal.ubytes.refTo(0))
//        return P3Impl(res, autoMem)
//    }
//    override fun doubleScalarMultiplyVariableTime(A: P3, a: LeUInt32, b: LeUInt32): P2 {
//        val res: ge_p2 = P2Impl.allocStruct(autoMem)
//        ge_double_scalarmult_base_vartime(
//            res.ptr,
//            a.ubytes.refTo(0),
//            (A as P3Impl).p3.ptr,
//            b.ubytes.refTo(0))
//        return P2Impl(res, autoMem)
//    }
//
//    override fun doubleScalarMultiplyVariableTimeP3(A: P3, a: LeUInt32, b: LeUInt32): P3 {
//        //TODO @see GroupElementMulTest.testDoubleScalarMultiplyVariableTime
//        return PointParser.parseNative(doubleScalarMultiplyVariableTime(A, a, b).compress(), autoMem)
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
//abstract class ComparableEcPointAutoMem(autoMem: NativePlacement): Compressable, AutoMem(autoMem) {
//
//    override fun equals(other: Any?): Boolean =
//        if(other is Compressable) bytes contentEquals other.bytes else false
//
//    override fun hashCode(): Int = bytes.contentHashCode()
//}
//
//internal class P2Impl(val p2: ge_p2, autoMem: NativePlacement): P2, ComparableEcPointAutoMem(autoMem) {
//    override fun toP2(): P2 = this
//
//    override fun compress(): CompressedPoint {
//        val u : UByteArray = UByteArray(32)
//        ge_tobytes(u.refTo(0), p2.ptr)
//        return u.toByteArray().asCompressedPoint()
//    }
//
//    override fun dbl(): P1P1 {
//        val p1p1: ge_p1p1 = P1P1Impl.allocStruct(autoMem)
//        ge_p2_dbl(p1p1.ptr,  p2.ptr)
//        return P1P1Impl(p1p1, autoMem)
//    }
//
//    override fun mul8(): P1P1 {
//        val p1p1: ge_p1p1 = P1P1Impl.allocStruct(autoMem)
//        ge_mul8(p1p1.ptr, p2.ptr)
//        return P1P1Impl(p1p1, autoMem)
//    }
//
//    companion object {
//        fun allocStruct(autoMem: NativePlacement): ge_p2 = autoMem.alloc<ge_p2>()
//    }
//}
//
//internal class P1P1Impl(val p1p1: ge_p1p1, autoMem: NativePlacement): P1P1, ComparableEcPointAutoMem(autoMem) {
//    override fun toP2(): P2 {
//        val p2: ge_p2 = P2Impl.allocStruct(autoMem)
//        ge_p1p1_to_p2(p2.ptr, p1p1.ptr)
//        return P2Impl(p2, autoMem)
//    }
//
//    override fun compress(): CompressedPoint = toP2().compress()
//
//    override fun toP3(precomp: Boolean): P3 {//TODO
//        val p3: ge_p3 = P3Impl.allocStruct(autoMem)
//        ge_p1p1_to_p3(p3.ptr, p1p1.ptr)
//        return P3Impl(p3, autoMem)
//    }
//
//    companion object {
//        fun allocStruct(autoMem: NativePlacement): ge_p1p1 = autoMem.alloc<ge_p1p1>()
//    }
//
//}
//
//open class P3Impl(val p3: ge_p3, autoMem: NativePlacement): P3, ComparableEcPointAutoMem(autoMem) {
//    override fun negate(): P1P1  = zeroP3(this.autoMem as AutoMemory).sub(toCached())
//
//
//    override fun doubleScalarMultiplyVariableTimeP3(A: P3, a: LeUInt32, b: LeUInt32): P3 {
//        //TODO @see GroupElementMulTest.testDoubleScalarMultiplyVariableTime
//         return PointParser.parseNative(doubleScalarMultiplyVariableTime(A, a, b).compress(), autoMem)
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
//        val p2: ge_p2 = P2Impl.allocStruct(autoMem)
//        val ths_dsmp = autoMem.allocArray<ge_cached>(8)//.reinterpret<ge_cached>()
//        ge_dsm_precomp(ths_dsmp , p3.ptr)
//        val A_dsmp = autoMem.allocArray<ge_cached>(8)//.reinterpret<ge_cached>()
//        ge_dsm_precomp(A_dsmp , (A as P3Impl).p3.ptr)
//        ge_double_scalarmult_precomp_vartime2(
//            p2.ptr,
//            a.ubytes.refTo(0),
//            A_dsmp,//.ptr,
//            b.ubytes.refTo(0),
//            ths_dsmp//.ptr
//        )
//        return P2Impl(p2, autoMem)
//    }
//
//    override fun scalarMultiply(scal: EcScalar): P3 {
//        val res: ge_p3 = P3Impl.allocStruct(autoMem)
//        ge_scalarmult_p3(res.ptr, scal.ubytes.refTo(0), p3.ptr)
//        return P3Impl(res, autoMem)
//    }
//
//    override fun toP2(): P2 {
//        val p2: ge_p2 = P2Impl.allocStruct(autoMem)
//        ge_p3_to_p2(p2.ptr, p3.ptr)
//        return P2Impl(p2, autoMem)
//    }
//
//    override fun compress(): CompressedPoint {
//        val u = UByteArray(32)
//        ge_p3_tobytes(u.refTo(0), p3.ptr)
//        return u.toByteArray().asCompressedPoint()
//    }
//
//    override fun dbl(): P1P1 = toP2().dbl()
//
//    override fun mul8(): P1P1 = toP2().mul8()
//
//    override fun toCached(): Cached {
//        val cached: ge_cached = CachedImpl.allocStruct(autoMem)
//        ge_p3_to_cached(cached.ptr,  p3.ptr)
//        return CachedImpl(cached, autoMem)
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
//        val p1p1: ge_p1p1 = P1P1Impl.allocStruct(autoMem)
//        ge_add(p1p1.ptr, p3.ptr, (other as CachedImpl).cached.ptr)
//        return P1P1Impl(p1p1, autoMem)
//    }
//
//    override fun sub(other: Cached): P1P1 {
//        val p1p1: ge_p1p1 = P1P1Impl.allocStruct(autoMem)
//        ge_sub(p1p1.ptr, p3.ptr, (other as CachedImpl).cached.ptr)
//        return P1P1Impl(p1p1, autoMem)
//    }
//
//    companion object {
//        fun allocStruct(autoMem: NativePlacement): ge_p3 = autoMem.alloc<ge_p3>()
//    }
//}
//
//internal class CachedImpl(val cached: ge_cached, @Suppress("UNUSED_PARAMETER") autoMem: NativePlacement): Cached {
//    companion object {
//        fun allocStruct(autoMem: NativePlacement): ge_cached = autoMem.alloc<ge_cached>()
//    }
//}
//
//internal class PrecompImpl(val precomp: ge_precomp, @Suppress("UNUSED_PARAMETER") autoMem: NativePlacement): Precomp {
//    companion object {
//        fun allocStruct(autoMem: NativePlacement): ge_precomp = autoMem.alloc<ge_precomp>()
//    }
//}
//
//
//actual fun AutoMemory?.p3(X: Fe, Y: Fe, Z: Fe, T: Fe): P3 {
//    val p3: ge_p3 = P3Impl.allocStruct(this!!)
//    new_ge_p3(p3.ptr, (X as FeImpl).e, (Y as FeImpl).e, (Z as FeImpl).e, (T as FeImpl).e)
//    return P3Impl(p3, this)
//}