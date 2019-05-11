package io.pnyx.zoe.ed25519

import io.pnyx.zoe.bytes.*
import io.pnyx.zoe.hash.HashingAlgo
import io.pnyx.zoe.util.AutoMemory
import io.pnyx.zoe.util.Rand


class CompressedPoint(bytes: ByteArray): Bytes32, BytesWrap(bytes) {
    companion object {
        infix fun of(b: ByteArray): CompressedPoint = b.asCompressedPoint()

        val infinity = CompressedPoint(byteArrayOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

        fun equals(p1: CompressedPoint, p2: CompressedPoint) = byteArrayEquals(p1.bytes, p2.bytes)

    }
    fun AutoMemory?.parse(precomp: Boolean = false) = this.p3(this@CompressedPoint, precomp)
}

//TODO move or remove
typealias SecretKey = EcScalar

@Suppress("NOTHING_TO_INLINE")
inline fun ByteArray.asCompressedPoint(): CompressedPoint {
    require(size == 32) { "expected 32 bytes, found ${size}" }
    return CompressedPoint(this)
}

//TODO move or remove
typealias PublicKey = CompressedPoint

//TODO remove ????????
//@see https://github.com/monero-project/research-lab/tree/master/whitepaper/ge_fromfe_writeup
expect fun AutoMemory?.ge_fromfe_frombytes_vartime(s: FeLeUInt): P2

//TODO aliases choose one ?
expect fun AutoMemory?.p3(X: Fe, Y: Fe, Z: Fe, T: Fe): P3

fun AutoMemory?.p3(p: CompressedPoint, precomp: Boolean = false) = PointParser.parse(p, this, precomp)
fun AutoMemory?.parsePoint(p: CompressedPoint/*, boolean precomputeSingleAndDouble*/, precomp: Boolean = false): P3 = p3(p, precomp)
internal expect object PointParser {
    fun parse(p: CompressedPoint/*, boolean precomputeSingleAndDouble*/, helper: AutoMemory?, precomp: Boolean = false): P3

}




val AutoMemory?.BPt: P3 get() = BasePoint()
internal expect fun AutoMemory?.BasePoint(): P3

val AutoMemory?.ZERO_P3: P3 get() = zeroP3()
internal expect fun AutoMemory?.zeroP3(): P3


interface GroupOps {
    val b: Int get() = 256
    val hash512 get() = HashingAlgo.SHA_512.factory.getInstance()
    fun reduce(s: UInt512): EcScalar
    fun multiplyAndAdd(a: LeUInt32, b: LeUInt32, c: LeUInt32): EcScalar
    fun randomGroupScalar(): EcScalar = reduce(UInt512 of Rand.get().randomBytes(64))
}
expect object EdGroup: GroupOps {


}



//fun PublicKey.check_key(): Boolean {
//    try {
//        autoMem {
//            p3(this@check_key)
//        }
//        return true
//    } catch(e: Exception) {
//        return false
//    }
//
//}



interface EcPoint {
    //TODO override equals e hashcode toString


}

abstract class ComparableEcPoint(): Compressable, ComparableBytes() {
    override fun equals(other: Any?): Boolean =
        if(other is Compressable) bytes contentEquals other.bytes else false

    override fun hashCode() = super.hashCode()

}


interface ToP2Support: Compressable {
    fun toP2(): P2
//    fun isOnCurve(): Boolean
}

//?? expect abstract class
interface Compressable: EcPoint, Bytes {
    fun compress(): CompressedPoint
    override val bytes: ByteArray get() = compress().bytes
    override fun equals(other: Any?): Boolean
    override fun hashCode(): Int
}

//?? expect abstract class come si fa con dbl()
interface ProjectivePoint: ToP2Support {
    fun dbl(): P1P1//what if P3PrecomputedDouble ? not valid method mv to other interface
    fun mul8(): P1P1 = dbl().toP2().dbl().toP2().dbl()
}

interface P2: ProjectivePoint {

//miki to P3 x,z e t a 1
}

interface P3: ProjectivePoint {

    fun toCached(): Cached
    fun add(other: Cached) : P1P1
    fun add(other: P3) = add(other.toCached())
    fun sub(other: Cached) : P1P1

    /**
     * $r = a * A + b * B$ where $a = a[0]+256*a[1]+\dots+256^{31} a[31]$,
     * $b = b[0]+256*b[1]+\dots+256^{31} b[31]$ and $B$ is this point.
     * <p>
     * $A$ must have been previously precomputed.
     *
     * @param A in P3 representation.
     * @param a $= a[0]+256*a[1]+\dots+256^{31} a[31]$
     * @param b $= b[0]+256*b[1]+\dots+256^{31} b[31]$
     * @return the GroupElement
     */
    fun doubleScalarMultiplyVariableTime(A: P3, a: LeUInt32, b: LeUInt32): P2
    fun doubleScalarMultiplyVariableTimeP3(A: P3, a: LeUInt32, b: LeUInt32): P3
    fun scalarMultiply(scal: EcScalar): P3
    fun scalarMultiplyP2(scal: EcScalar): P2
    operator fun plus(p: Cached): P1P1 = add(p)
    operator fun plus(p: P3): P1P1 = add(p.toCached())

    operator fun minus(p: Cached): P1P1 = sub(p)
    operator fun minus(p: P3): P1P1 = sub(p.toCached())
    fun negate(): P1P1

}

interface P1P1: ToP2Support {
    fun toP3(precomp: Boolean = false): P3
    //fun toP3Precomp(): P3
}

interface Precomp: EcPoint

interface Cached: EcPoint

//TODO returns null when pt not found ??
fun AutoMemory?.geFromFeFromBytesVartime2(s: FeLeUInt): P3? {
    val Y = FeVal.parse(s.bytes)
    val Z = FeVal.fe1
    var u = Y.square()
    var v = u * FeVal.fe_d
    u = u - Z /* u = y^2-1 */
    v = v + Z /* v = dy^2+1 */

    var X = divPowM1(u, v) /* x = uv^3(uv^7)^((q-5)/8) */
    var vxx = X.square()
    vxx = vxx * v
    var check = vxx - u
    if (check.isNonZero) {
        check = vxx + u  /* vx^2+u */
        if (check.isNonZero) {
            return null;
        }
        X = X * FeVal.fe_sqrtm1

    }

    val sMostSignificativeBitIsZero = (s.bytes[31].toInt() shr 7) == 0
    if (X.isNegative && sMostSignificativeBitIsZero
        || (!X.isNegative && !sMostSignificativeBitIsZero) //TODO
    ) {//fe_isnegative(h->X) != (s[31] >> 7)
        /* If x = 0, the sign must be positive */
        if (X.isZero) {
            return null
        }
        X = X.negate()
    }
    val T = X * Y
    return p3(X, Y, Z, T)
}

