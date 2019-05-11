package io.pnyx.keddsa.spec


import io.pnyx.keddsa.Utils
import io.pnyx.keddsa.math.Curve
import io.pnyx.keddsa.math.Field
import io.pnyx.keddsa.math.ed22519.Ed25519LittleEndianEncoding
import io.pnyx.zoe.hash.HashingAlgo

object EdDSACurveSpec {

    val field = Field(
        256, // b
        Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
        Ed25519LittleEndianEncoding()
    )

    val curve = Curve(
        field,
        Utils.hexToBytes("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352"), // d
        field.fromByteArray(Utils.hexToBytes("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b"))
    ) // I

    val hashingAlgo = HashingAlgo.SHA_512
    val hash = hashingAlgo.factory.getInstance()
    val B = curve.createPoint( // B
        Utils.hexToBytes("5866666666666666666666666666666666666666666666666666666666666666"),
        true
    )

}
