package io.pnyx

import io.pnyx.zoe.bytes.hexDec
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import org.junit.Test

class ATest {
    private val edDSANamedCurveSpec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!
    private val curve = edDSANamedCurveSpec.curve

    @Test
    fun cc() {
        val p = "0100000000000000000000000000000000000000000000000000000000000080".hexDec()
        val pt = curve.createPoint(p, false)
        val r = pt.representation
        val x = pt.x
        val y = pt.y
        val z = pt.z
        val t = pt.t
        println()
    }
}