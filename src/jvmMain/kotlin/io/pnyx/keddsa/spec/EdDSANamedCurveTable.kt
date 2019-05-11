package io.pnyx.keddsa.spec


import io.pnyx.keddsa.Utils
import io.pnyx.keddsa.math.Curve
import io.pnyx.keddsa.math.Field
import io.pnyx.keddsa.math.ed22519.Ed25519LittleEndianEncoding
import io.pnyx.keddsa.math.ed22519.Ed25519ScalarOps

object EdDSANamedCurveTable {
    val ED_25519 = "Ed25519"

    private val ed25519field = Field(
        256, // b
        Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
        Ed25519LittleEndianEncoding()
    )

    private val ed25519curve = Curve(
        ed25519field,
        Utils.hexToBytes("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352"), // d
        ed25519field.fromByteArray(Utils.hexToBytes("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b"))
    ) // I

    val ED_25519_CURVE_SPEC = EdDSANamedCurveSpec(
        ED_25519,
        ed25519curve,
        "SHA-512", // H
        Ed25519ScalarOps(), // l
        ed25519curve.createPoint( // B
            Utils.hexToBytes("5866666666666666666666666666666666666666666666666666666666666666"),
            true
        )
    ) // Precompute tables for B

//TODO    @Volatile
    private var curves = HashMap<String, EdDSANamedCurveSpec>()

    //TODO    @Synchronized
    private fun putCurve(name: String, curve: EdDSANamedCurveSpec) {
        val newCurves = HashMap(curves)
        newCurves[name] = curve
        curves = newCurves
    }

    fun defineCurve(curve: EdDSANamedCurveSpec) {
        putCurve(curve.name.toLowerCase(), curve)
    }

    internal fun defineCurveAlias(name: String, alias: String) {
        val curve = curves[name.toLowerCase()] ?: throw IllegalStateException()
        putCurve(alias.toLowerCase(), curve)
    }

    init {
        // RFC 8032
        defineCurve(ED_25519_CURVE_SPEC)
    }

    fun getByName(name: String): EdDSANamedCurveSpec? {
        return curves[name.toLowerCase()]
    }
}
