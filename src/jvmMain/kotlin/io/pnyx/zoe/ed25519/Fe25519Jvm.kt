package io.pnyx.zoe.ed25519

import net.i2p.crypto.eddsa.math.FieldElement
import net.i2p.crypto.eddsa.math.ed25519.Ed25519FieldElement
import net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding
import net.i2p.crypto.eddsa.math.ed25519.Ed25519ScalarOps


private val enc = Ed25519LittleEndianEncoding()
private val ops = Ed25519ScalarOps()

actual object FeVal {
    init {
        enc.setField(curve.field)
    }
    actual val fe0: Fe = FeImpl(curve.field.ZERO)
    actual val fe1: Fe = FeImpl(curve.field.ONE)
    actual val fe2: Fe = FeImpl(curve.field.TWO)
    actual val fe_d get() = parse(intArrayOf(-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116))
    actual val fe_sqrtm1 get() = parse(intArrayOf(-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482)) /* sqrt(-1) */
    actual fun parse(bytes: ByteArray): Fe = FeImpl(enc.decode(bytes))
    actual fun parse(ints: IntArray): Fe = FeImpl(Ed25519FieldElement(curve.field, ints))
}
//
//
//actual object FeParser {
//    actual fun parse(bytes: ByteArray): Fe = FeImpl(enc.decode(bytes))
//    actual fun parse(ints: IntArray): Fe = FeImpl(Ed25519FieldElement(curve.field, ints))
//}
//
class FeImpl(val fe: FieldElement): Fe {
    override val bytes: ByteArray get() = enc.encode(fe)

    override val isNonZero: Boolean get() = fe.isNonZero

    override val isNegative: Boolean get() = fe.isNegative

    override fun invert() = FeImpl(fe.invert())

    override fun add(value: Fe) = FeImpl(fe.add(unwrap(value)))

//    override fun addOne() = FeImpl(fe.addOne())

    override fun subtract(value: Fe) = FeImpl(fe.subtract(unwrap(value)))

//    override fun subtractOne() = FeImpl(fe.subtractOne())

    override fun negate() = FeImpl(fe.negate())

//    override fun divide(value: Fe) = FeImpl(fe.divide(unwrap(value)))

    override fun multiply(value: Fe) = FeImpl(fe.multiply(unwrap(value)))

    override fun square() = FeImpl(fe.square())

    override fun squareAndDouble() = FeImpl(fe.squareAndDouble())

    override fun pow22523() = FeImpl(fe.pow22523())

//    override fun divPowM1(u: Fe, v: Fe) = FeImpl(fe_divpowm1(unwrap(u), unwrap(v)))

    override fun hashCode() = fe.hashCode()

    override fun equals(other: Any?)= if(other is FeImpl) fe.equals(other.fe) else false

}

internal fun unwrap(value: Fe): FieldElement = (value as FeImpl).fe
