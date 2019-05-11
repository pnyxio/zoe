package io.pnyx.zoe.ed25519

import io.pnyx.keddsa.math.FieldElement
import io.pnyx.keddsa.math.GroupElement
import io.pnyx.keddsa.math.ed22519.Ed25519FieldElement
import io.pnyx.keddsa.math.ed22519.Ed25519LittleEndianEncoding
import io.pnyx.keddsa.math.ed22519.Ed25519ScalarOps
import io.pnyx.keddsa.spec.EdDSACurveSpec
import io.pnyx.keddsa.spec.EdDSACurveSpec.curve
import io.pnyx.zoe.bytes.LeUInt32
import io.pnyx.zoe.bytes.UInt512
import io.pnyx.zoe.util.AutoMemory

//private val edDSANamedCurveSpec = EdDSACurveSpec
//private val curve = edDSANamedCurveSpec.curve
//val fieldEncoding = edDSANamedCurveSpec.curve.field.getEncoding()
//val B = P3(edDSANamedCurveSpec.b.toByteArray())

//actual object GroupBase : P3, P3Impl(EdDSACurveSpec.B) {
//    //  a[31] <= 127
//    override fun scalarMultiply(scal: EcScalar): P3 = P3Impl(EdDSACurveSpec.B.scalarMultiply(scal.bytes))
//    actual fun doubleScalarMultiplyVariableTime(A: P3/*TODO !!! precomputed*/, a: LeUInt32, b: LeUInt32): P3 {
//        return P3Impl(EdDSACurveSpec.B.doubleScalarMultiplyVariableTime((A as P3Impl).ge, a.bytes, b.bytes))
//    }
//}
private val Bp = BasePointImpl()
internal actual fun AutoMemory?.BasePoint(): P3 = Bp


internal actual fun AutoMemory?.zeroP3(): P3 = P3Impl(EdDSACurveSpec.curve.getZero(GroupElement.Representation.P3))

class BasePointImpl(): P3Impl(EdDSACurveSpec.B) {
    override fun scalarMultiply(scal: EcScalar): P3 = P3Impl(EdDSACurveSpec.B.scalarMultiply(scal.bytes))
    override fun doubleScalarMultiplyVariableTime(A: P3/*TODO !!! precomputed*/, a: LeUInt32, b: LeUInt32): P2 {
        return P2Impl(EdDSACurveSpec.B.doubleScalarMultiplyVariableTime((A as P3Impl).ge, a.bytes, b.bytes))
    }
    override fun doubleScalarMultiplyVariableTimeP3(A: P3, a: LeUInt32, b: LeUInt32): P3 {
        val age = (A as P3Impl).ge
        val ageDblPrecomp = GroupElement.p3(age.curve, age.x, age.y, age.z, age.t, true)
        return PointParser.parse(
            CompressedPoint(EdDSACurveSpec.B.doubleScalarMultiplyVariableTime(ageDblPrecomp, a.bytes, b.bytes).toByteArray()), null)
    }
}


actual object EdGroup : GroupOps {
    private val ops = Ed25519ScalarOps()
//    override val B get() = GroupBase

    override fun reduce(s: UInt512): EcScalar = EcScalar(ops.reduce(s.bytes))

    override fun multiplyAndAdd(a: LeUInt32, b: LeUInt32, c: LeUInt32): EcScalar =
        EcScalar(ops.multiplyAndAdd(a.bytes, b.bytes, c.bytes))

}

internal actual object PointParser {
    actual fun parse(p: CompressedPoint, helper: AutoMemory?, precomp: Boolean): P3 =
        P3Impl(GroupElement(EdDSACurveSpec.curve, p.bytes,precomp))
}


//internal
open class P3Impl(val ge: GroupElement): P3, ComparableEcPoint() {
    init {
        require(ge.representation == GroupElement.Representation.P3)
    }
    override fun negate(): P1P1 = null.zeroP3().sub(toCached())

    override fun doubleScalarMultiplyVariableTime(A: P3, a: LeUInt32, b: LeUInt32): P2 =
        P2Impl(ge.doubleScalarMultiplyVariableTime((A as P3Impl).ge, a.bytes, b.bytes))

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


private val enc = Ed25519LittleEndianEncoding()
actual fun AutoMemory?.ge_fromfe_frombytes_vartime(s: FeLeUInt): P2 {
    val u = enc.decode(s.bytes)
    val v = u.squareAndDouble()/* 2 * u^2 */

    val w = v.add(curve.field.ONE)/* w = 2 * u^2 + 1 */

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
    if (X.isNegative != signNegative) {
//    assert(fe_isnonzero(X))
        X = X.negate()
    }
    val Z = z.add(w)
    val Y = z.subtract(w)
    X = X.multiply(Z)
    return P2Impl(GroupElement.p2(curve, X,Y,Z))

}
fun fe_divpowm1(u: FieldElement, v: FieldElement): FieldElement {
    val v3 = v.square().multiply(v)/* v3 = v^3 */
    val uv7 = v3.square().multiply(v).multiply(u)
    val t0 = uv7.pow22523()
    /* t0 = (uv^7)^((q-5)/8) */
    return t0.multiply(v3).multiply(u)/* u^(m+1)v^(-(m+1)) */
}

actual fun AutoMemory?.p3(X: Fe, Y: Fe, Z: Fe, T: Fe): P3 =
    P3Impl(GroupElement.Companion.p3(EdDSACurveSpec.curve, unwrap(X), unwrap(Y), unwrap(Z), unwrap(T)))