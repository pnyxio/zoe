package io.pnyx.zoe.ed25519


import io.pnyx.zoe.bytes.LeUInt32
import io.pnyx.zoe.bytes.UInt512
import io.pnyx.zoe.util.AutoMemory
import net.i2p.crypto.eddsa.math.FieldElement
import net.i2p.crypto.eddsa.math.GroupElement
import net.i2p.crypto.eddsa.math.ed25519.*
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable


private val edDSANamedCurveSpec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!
internal val curve = edDSANamedCurveSpec.curve

internal actual fun AutoMemory?.zeroP3(): P3 = P3Impl(edDSANamedCurveSpec.curve.getZero(GroupElement.Representation.P3))

private val Bp = BasePointImpl()
internal actual fun AutoMemory?.BasePoint(): P3 = Bp


class BasePointImpl: P3Impl(edDSANamedCurveSpec.b) {
    override fun scalarMultiply(scal: EcScalar): P3 = P3Impl(edDSANamedCurveSpec.b.scalarMultiply(scal.bytes))
    override fun doubleScalarMultiplyVariableTime(A: P3/*TODO !!! precomputed*/, a: LeUInt32, b: LeUInt32): P2 {
        val age = (A as P3Impl).ge
        val ageDblPrecomp = GroupElement.p3(age.curve, age.x, age.y, age.z, age.t, true)
        return P2Impl(edDSANamedCurveSpec.b.doubleScalarMultiplyVariableTime(ageDblPrecomp, a.bytes, b.bytes))
    }
    override fun doubleScalarMultiplyVariableTimeP3(A: P3, a: LeUInt32, b: LeUInt32): P3 {
        val age = (A as P3Impl).ge
        val ageDblPrecomp = GroupElement.p3(age.curve, age.x, age.y, age.z, age.t, true)
        return PointParser.parse(
            CompressedPoint(edDSANamedCurveSpec.b.doubleScalarMultiplyVariableTime(ageDblPrecomp, a.bytes, b.bytes).toByteArray()), null)
    }

}
//actual object GroupBase : P3, P3Impl(edDSANamedCurveSpec.b) {
//    override fun scalarMultiply(scal: EcScalar): P3 = P3Impl(edDSANamedCurveSpec.b.scalarMultiply(scal.bytes))
//    actual fun doubleScalarMultiplyVariableTime(A: P3/*TODO !!! precomputed*/, a: LeUInt32, b: LeUInt32): P3 {
//        return P3Impl(edDSANamedCurveSpec.b.doubleScalarMultiplyVariableTime((A as P3Impl).ge, a.bytes, b.bytes))
//    }
//}

actual object EdGroup : GroupOps {
    private val ops = Ed25519ScalarOps()
//    override val B get() = Bp

    override fun reduce(s: UInt512): EcScalar = EcScalar(ops.reduce(s.bytes))

    override fun multiplyAndAdd(a: LeUInt32, b: LeUInt32, c: LeUInt32): EcScalar =
        EcScalar(ops.multiplyAndAdd(a.bytes, b.bytes, c.bytes))

}

internal actual object PointParser {
    actual fun parse(p: CompressedPoint, helper: AutoMemory?, precomp: Boolean): P3 =
        P3Impl(GroupElement(curve, p.bytes, precomp))
}


//internal
open class P3Impl(val ge: GroupElement): P3, ComparableEcPoint() {
    override fun negate(): P1P1 = null.zeroP3().sub(toCached())

    init {
        require(ge.representation == GroupElement.Representation.P3)
    }

    override fun doubleScalarMultiplyVariableTime(A: P3, a: LeUInt32, b: LeUInt32): P2 {
        val age = (A as P3Impl).ge
        val ageDblPrecomp = GroupElement.p3(age.curve, age.x, age.y, age.z, age.t, true)
        return P2Impl(ge.doubleScalarMultiplyVariableTime(ageDblPrecomp, a.bytes, b.bytes))
    }

    override fun doubleScalarMultiplyVariableTimeP3(A: P3, a: LeUInt32, b: LeUInt32): P3 {
        val age = (A as P3Impl).ge
        val ageDblPrecomp = GroupElement.p3(age.curve, age.x, age.y, age.z, age.t, true)
        return PointParser.parse(
            CompressedPoint(ge.doubleScalarMultiplyVariableTime(ageDblPrecomp, a.bytes, b.bytes).toByteArray()), null)
    }

    override fun scalarMultiply(scal: EcScalar): P3 = P3Impl(ge.scalarMultiply(scal.bytes))

    override fun scalarMultiplyP2(scal: EcScalar): P2 = scalarMultiply(scal).toP2()

    override fun toP2(): P2 = P2Impl(ge.toP2())

    override fun compress(): CompressedPoint = ge.toByteArray().asCompressedPoint()

    override fun dbl(): P1P1 = P1P1Impl(ge.dbl())

    override fun toCached(): Cached = CachedImpl(ge.toCached())

//    override fun madd(other: Precomp): P1P1 = P1P1Impl(ge.madd((other as PrecompImpl).ge))
//
//    override fun msub(other: Precomp): P1P1 = P1P1Impl(ge.msub((other as PrecompImpl).ge))

    override fun add(other: Cached): P1P1 = P1P1Impl(ge.add((other as CachedImpl).ge))

    override fun sub(other: Cached): P1P1 = P1P1Impl(ge.sub((other as CachedImpl).ge))

}

internal class P2Impl(val ge: GroupElement): P2, ComparableEcPoint() {
    init {
        require(ge.representation == GroupElement.Representation.P2)
    }

    override fun toP2(): P2 = this

    override fun compress(): CompressedPoint = ge.toByteArray().asCompressedPoint()

    override fun dbl(): P1P1 = P1P1Impl(ge.dbl())
}

internal class P1P1Impl(val ge: GroupElement): P1P1, ComparableEcPoint() {
    init {
        require(ge.representation == GroupElement.Representation.P1P1)
    }

    override fun compress(): CompressedPoint = toP2().compress()//TODO ge.toP2().toByteArray()

    override fun toP3(precomp: Boolean): P3 = P3Impl(if(precomp) ge.toP3PrecomputeDouble() else ge.toP3())

    override fun toP2(): P2 = P2Impl(ge.toP2())

}

internal class CachedImpl(val ge: GroupElement): Cached {
    init {
        require(ge.representation == GroupElement.Representation.CACHED)
    }

}

internal class PrecompImpl(val ge: GroupElement): Precomp {
    init {
        require(ge.representation == GroupElement.Representation.PRECOMP)
    }

}

/* sqrt(x) is such an integer y that 0 <= y <= p - 1, y % 2 = 0, and y^2 = x (mod p). */
/* d = -121665 / 121666 */
private val fe_d: FieldElement = Ed25519FieldElement(curve.field, intArrayOf(-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116)) /* d */
private val fe_sqrtm1: FieldElement = Ed25519FieldElement(curve.field, intArrayOf(-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482)) /* sqrt(-1) */
private val fe_d2: FieldElement = Ed25519FieldElement(curve.field, intArrayOf(-21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199)) /* 2 * d */


private val fe_ma2: FieldElement = Ed25519FieldElement(curve.field, intArrayOf(-12721188, -3529, 0, 0, 0, 0, 0, 0, 0, 0)) /* -A^2 */
private val fe_ma: FieldElement = Ed25519FieldElement(curve.field,intArrayOf(-486662, 0, 0, 0, 0, 0, 0, 0, 0, 0)) /* -A */
private val fe_fffb1: FieldElement = Ed25519FieldElement(curve.field,intArrayOf(-31702527, -2466483, -26106795, -12203692, -12169197, -321052, 14850977, -10296299, -16929438, -407568)) /* sqrt(-2 * A * (A + 2)) */
private val fe_fffb2: FieldElement = Ed25519FieldElement(curve.field,intArrayOf(8166131, -6741800, -17040804, 3154616, 21461005, 1466302, -30876704, -6368709, 10503587, -13363080)) /* sqrt(2 * A * (A + 2)) */
private val fe_fffb3: FieldElement = Ed25519FieldElement(curve.field,intArrayOf(-13620103, 14639558, 4532995, 7679154, 16815101, -15883539, -22863840, -14813421, 13716513, -6477756)) /* sqrt(-sqrt(-1) * A * (A + 2)) */
private val fe_fffb4: FieldElement = Ed25519FieldElement(curve.field,intArrayOf(-21786234, -12173074, 21573800, 4524538, -4645904, 16204591, 8012863, -8444712, 3212926, 6885324)) /* sqrt(sqrt(-1) * A * (A + 2)) */
//private val ge_p3 ge_p3_identity = { {0}, {1, 0}, {1, 0}, {0} };
private val ge_p3_H = GroupElement.p3(
    curve,
    Ed25519FieldElement(curve.field,intArrayOf(7329926, -15101362, 31411471, 7614783, 27996851, -3197071, -11157635, -6878293, 466949, -7986503)),
    Ed25519FieldElement(curve.field,intArrayOf(5858699, 5096796, 21321203, -7536921, -5553480, -11439507, -5627669, 15045946, 19977121, 5275251)),
    Ed25519FieldElement(curve.field,intArrayOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0)),
    Ed25519FieldElement(curve.field,intArrayOf(23443568, -5110398, -8776029, -4345135, 6889568, -14710814, 7474843, 3279062, 14550766, -7453428)),
    true
)


private val enc by lazy {
    val en = Ed25519LittleEndianEncoding()
    en.setField(curve.field)
    en
}


//TODO also common impl
actual fun AutoMemory?.ge_fromfe_frombytes_vartime(s: FeLeUInt): P2 {
    val u = enc.decode(s.bytes)

    val v = u.squareAndDouble()/* 2 * u^2 */

    val w = v.addOne()/* w = 2 * u^2 + 1 */

    var x = w.square() /* w^2 */
    var y = fe_ma2.multiply(v)//fe_mul(y, fe_ma2, v); /* -2 * A^2 * u^2 */

    x = x.add(y) /* x = w^2 - 2 * A^2 * u^2 */
    var X = fe_divpowm1(w, x); /* (w / x)^(m + 1) */
    y = X.square()
    x = x.multiply(y)
    y = w.subtract(x)

    var z = fe_ma
    val signNegative: Boolean
    if (y.isNonZero) {
        y = w.add(x)
        if (y.isNonZero) {
            x = x.multiply(fe_sqrtm1)
            y = w.subtract(x)
            if (y.isNonZero) {
                //assert((fe_add(y, w, x), !fe_isnonzero(y)));
                X = X.multiply(fe_fffb3)
            } else {
                X = X.multiply(fe_fffb4)
            }
            /* r->X = sqrt(A * (A + 2) * w / x) */
            /* z = -A */
            signNegative = true
        } else {
            X = X.multiply(fe_fffb1)
            X = X.multiply(u) /* u * sqrt(2 * A * (A + 2) * w / x) */
            z = z.multiply(v); /* -2 * A * u^2 */
            signNegative = false
        }
    } else {
        X = X.multiply(fe_fffb2)
        X = X.multiply(u) /* u * sqrt(2 * A * (A + 2) * w / x) */
        z = z.multiply(v); /* -2 * A * u^2 */
        signNegative = false
    }
    if (X.isNegative() != signNegative) {
//    assert(fe_isnonzero(X))
        X = X.negate()
    }

    val Z = z.add(w)
    val Y = z.subtract(w)
    X = X.multiply(Z)
// check code
//        var check_iz = Z.invert()
//        var check_x = X.multiply(check_iz);
//        var check_y = Y.multiply(check_iz);
//        check_x = check_x.square()
//        check_y = check_y.square()
//        var check_v = check_x.multiply(check_y);
//        check_v =  fe_d.multiply(check_v);
//        check_v = check_v.add(check_x);
//        check_v = check_v.subtract(check_y)
//        check_v = check_v.addOne()
//        require(! check_v.isNonZero);
    return P2Impl(GroupElement.p2(curve, X,Y,Z))

}

fun fe_divpowm1(u: FieldElement, v: FieldElement): FieldElement {
    val v3 = v.square().multiply(v)/* v3 = v^3 */
    val uv7 = v3.square().multiply(v).multiply(u)
    val t0 = uv7.pow22523()
    /* t0 = (uv^7)^((q-5)/8) */
    return t0.multiply(v3).multiply(u)/* u^(m+1)v^(-(m+1)) */
}

//internal fun isP3OrP3dblPrecompGroupElement(ge: GroupElement): Boolean =
//    ge.representation == GroupElement.Representation.P3PrecomputedDouble
//            || ge.representation == GroupElement.Representation.P3
//
//
//internal fun dblPrecompP3GroupElementIfNeeded(ge: GroupElement): GroupElement = when {
//    ge.representation == GroupElement.Representation.P3PrecomputedDouble -> ge
//    ge.representation == GroupElement.Representation.P3 -> GroupElement.p3(ge.curve, ge.x, ge.y, ge.z, ge.t, true)
//    else -> throw IllegalArgumentException()
//}
//
//class ScalPointMul(private val scal: UInt256, private val point: GePoint) : Point {
//
//    private val p3: P3 get() = P3(point.ge.scalarMultiply(scal.bytes))
//
//    override fun toP2(): P2 = p3.toP2()
//    fun toP3(): P3 = p3
//
//    override fun compress(): CompressedPoint = p3.compress()
//
//    fun mul8(): P1P1 = p3.mul8()
//
//    fun dbl(): P1P1 = p3.dbl()
//
//    operator fun plus(pt: Point): GePoint = when {
//        pt is GeCached -> P1P1(p3.ge.add(pt.ge))
//        pt is P3 -> P1P1(p3.ge.add(pt.ge.toCached()))
//        pt is ScalPointMul
//                && isP3OrP3dblPrecompGroupElement(point.ge)
//                && isP3OrP3dblPrecompGroupElement(pt.point.ge) -> {
//            P2(
//                dblPrecompP3GroupElementIfNeeded(point.ge).doubleScalarMultiplyVariableTime(
//                    dblPrecompP3GroupElementIfNeeded(pt.point.ge), pt.scal.bytes, scal.bytes))
//        }
//        pt is ScalPointMul -> p3 + pt.p3
//        else -> throw IllegalArgumentException()
//    }
//
//    fun toCached(): GeCached = p3.toCached()
//
//}
//
//actual class P3 internal constructor(val ge: GroupElement) : Point/*, GePoint(ge)*/ {
//    init {
//        require(ge.representation == GroupElement.Representation.P3)
//    }
//    constructor(pt: CompressedPoint) : this(GroupElement(curve, pt))
//    actual constructor(pt: CompressedPoint, precomp: Boolean) : this(
//        GroupElement(
//            curve,
//            pt,
//            precomp
//        )
//    )//miki precomp))
//
//    override fun toP2(): P2 = P2(ge.toP2())
//
//    fun mul8(): P1P1 = dbl().toP2().dbl().toP2().dbl()
//
//    fun dbl(): P1P1 = P1P1(ge.dbl())
//
//
//    operator fun plus(pt: Point): P1P1 = when {
//        pt is GeCached -> P1P1(ge.add(pt.ge))
//        //pt is GePrecomp -> P1P1(ge.madd(pt.ge))
//        else -> throw IllegalArgumentException()
//    }
//
//    fun toCached(): GeCached = GeCached(ge.toCached())
//    fun toP3DblPrecomp() : P3 = P3(dblPrecompP3GroupElementIfNeeded(ge))
//
//    operator fun minus(pt: GeCached): P1P1 = P1P1(ge.sub(pt.ge))
//
//    actual fun scalarMultiply(a: UInt256/*TODO actually left byte < 127 @see EcPoint*/): P3 = times(a)
//    operator fun times(scal: UInt256): P3 {
//        if(false) {//this is b and scal[31]<127
//            return P3(
//                //toP3DblPrecomp().
//                ge.scalarMultiply(scal.bytes))
//
//        } else {
//            return P3(scalarMulByDoubleAndAdd(ge, scal))
//        }
//    }
//    override fun compress(): CompressedPoint = ge.toByteArray()
//
//}
//internal fun scalarMulByDoubleAndAdd(ge: GroupElement, scal: UInt256): GroupElement {
//    var A =
//        Ed25519Scalar.reduce(scal.toUInt512())//TODO optimize cmq necessario per il 254 nel loop //toBigEndian(scal)
//    var S = ge.toCached()
//    var R = curve.getZero(GroupElement.Representation.P3)
//    for(i in 254 downTo 0) {
//        R = R.dbl().toP3()
//        if(Bytes.bitAt(A.bytes, i) == 1) {
//            R = R.add(S).toP3()
//        }
//    }
//    return R
//}
//
//
//actual class P2 internal constructor(ge: GroupElement) : GePoint(ge) {
//    init {
//        require(ge.representation == GroupElement.Representation.P2)
//    }
//    override fun toP2(): P2 = P2(ge.toP2())
//    fun mul8(): P1P1 = dbl().toP2().dbl().toP2().dbl()
//
//    fun dbl(): P1P1 = P1P1(ge.dbl())
//
//}
//
////TODO init assert
//class P1P1 internal constructor(ge: GroupElement) : GePoint(ge) {
//    init {
//        require(ge.representation == GroupElement.Representation.P1P1)
//    }
//
//    override fun toP2(): P2 = P2(ge.toP2())
//
//}
//
//class GeCached internal constructor(ge: GroupElement) : GePoint(ge) {
//    init {
//        require(ge.representation == GroupElement.Representation.CACHED)
//    }
//
//    override fun toP2(): P2 = TODO()
//
//}
//
////class GePrecomp internal constructor(ge: GroupElement) : GePoint(ge) {
////    init {
////        Assert.isTrue(ge.representation == GroupElement.Representation.PRECOMP)
////    }
////
////    override fun toP2(): P2 = TODO()
////
////}
//actual object Ed25519Scalar {
//    private val _ed25519ScalarOps = Ed25519ScalarOps()
//    /**
//     * Reduction modulo the group order $q$.
//     *
//     *
//     * Input:
//     * $s[0]+256*s[1]+\dots+256^{63}*s[63] = s$
//     *
//     *
//     * Output:
//     * $s[0]+256*s[1]+\dots+256^{31}*s[31] = s \bmod q$
//     * where $q = 2^{252} + 27742317777372353535851937790883648493$.
//     */
//    actual fun reduce(s: UInt512): GroupOrderReducedUInt = GroupOrderReducedUInt(_ed25519ScalarOps.reduce(s.bytes))
//
//    /**
//     * $(ab+c) \bmod q$
//     *
//     *
//     * Input:
//     *
//     *  * $a[0]+256*a[1]+\dots+256^{31}*a[31] = a$
//     *  * $b[0]+256*b[1]+\dots+256^{31}*b[31] = b$
//     *  * $c[0]+256*c[1]+\dots+256^{31}*c[31] = c$
//     *
//     *
//     * Output:
//     * $result[0]+256*result[1]+\dots+256^{31}*result[31] = (ab+c) \bmod q$
//     * where $q = 2^{252} + 27742317777372353535851937790883648493$.
//     *
//     *
//     * See the comments in [.reduce] for an explanation of the algorithm.
//     */
//    actual fun multiplyAndAdd(a: UInt256, b: UInt256, c: UInt256): GroupOrderReducedUInt =
//        GroupOrderReducedUInt(_ed25519ScalarOps.multiplyAndAdd(a.bytes, b.bytes, c.bytes))
//
//
//
//}

actual fun AutoMemory?.p3(X: Fe, Y: Fe, Z: Fe, T: Fe): P3 =
    P3Impl(GroupElement.p3(curve, unwrap(X), unwrap(Y), unwrap(Z), unwrap(T)))
