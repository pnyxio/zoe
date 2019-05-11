package net.i2p.crypto.eddsa.math.ed25519

import net.i2p.crypto.eddsa.math.FieldElement
import net.i2p.crypto.eddsa.math.ed25519.Ed25519FieldElement
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable

fun fe(f: FieldElement): String {
    return (f as Ed25519FieldElement).t.joinToString("|") { it.toString()}
}

private val f = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!.curve.field


//fun decode2(`in`: ByteArray): FieldElement {
//    var h0 = Ed25519LittleEndianEncoding.load_4(`in`, 0)
//    var h1 = (Ed25519LittleEndianEncoding.load_3(`in`, 4) shl 6).toLong()
//    var h2 = (Ed25519LittleEndianEncoding.load_3(`in`, 7) shl 5).toLong()
//    var h3 = (Ed25519LittleEndianEncoding.load_3(`in`, 10) shl 3).toLong()
//    var h4 = (Ed25519LittleEndianEncoding.load_3(`in`, 13) shl 2).toLong()
//    var h5 = Ed25519LittleEndianEncoding.load_4(`in`, 16)
//    var h6 = (Ed25519LittleEndianEncoding.load_3(`in`, 20) shl 7).toLong()
//    var h7 = (Ed25519LittleEndianEncoding.load_3(`in`, 23) shl 5).toLong()
//    var h8 = (Ed25519LittleEndianEncoding.load_3(`in`, 26) shl 4).toLong()
//    var h9 = (Ed25519LittleEndianEncoding.load_3(`in`, 29) and 0x7FFFFF shl 2).toLong()
//    val carry0: Long
//    val carry1: Long
//    val carry2: Long
//    val carry3: Long
//    val carry4: Long
//    val carry5: Long
//    val carry6: Long
//    val carry7: Long
//    val carry8: Long
//    val carry9: Long
//
//    // Remember: 2^255 congruent 19 modulo p
//    carry9 = h9 + (1 shl 24).toLong() shr 25
//    h0 += carry9 * 19
//    h9 -= carry9 shl 25
//    carry1 = h1 + (1 shl 24).toLong() shr 25
//    h2 += carry1
//    h1 -= carry1 shl 25
//    carry3 = h3 + (1 shl 24).toLong() shr 25
//    h4 += carry3
//    h3 -= carry3 shl 25
//    carry5 = h5 + (1 shl 24).toLong() shr 25
//    h6 += carry5
//    h5 -= carry5 shl 25
//    carry7 = h7 + (1 shl 24).toLong() shr 25
//    h8 += carry7
//    h7 -= carry7 shl 25
//
//    carry0 = h0 + (1 shl 25).toLong() shr 26
//    h1 += carry0
//    h0 -= carry0 shl 26
//    carry2 = h2 + (1 shl 25).toLong() shr 26
//    h3 += carry2
//    h2 -= carry2 shl 26
//    carry4 = h4 + (1 shl 25).toLong() shr 26
//    h5 += carry4
//    h4 -= carry4 shl 26
//    carry6 = h6 + (1 shl 25).toLong() shr 26
//    h7 += carry6
//    h6 -= carry6 shl 26
//    carry8 = h8 + (1 shl 25).toLong() shr 26
//    h9 += carry8
//    h8 -= carry8 shl 26
//
//    val h = IntArray(10)
//    h[0] = h0.toInt()
//    h[1] = h1.toInt()
//    h[2] = h2.toInt()
//    h[3] = h3.toInt()
//    h[4] = h4.toInt()
//    h[5] = h5.toInt()
//    h[6] = h6.toInt()
//    h[7] = h7.toInt()
//    h[8] = h8.toInt()
//    h[9] = h9.toInt()
//    return Ed25519FieldElement(f, h)
//}
