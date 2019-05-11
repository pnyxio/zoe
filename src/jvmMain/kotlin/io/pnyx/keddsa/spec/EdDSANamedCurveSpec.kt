package io.pnyx.keddsa.spec

import io.pnyx.keddsa.math.Curve
import io.pnyx.keddsa.math.GroupElement
import io.pnyx.keddsa.math.ScalarOps

class EdDSANamedCurveSpec(
    val name: String, curve: Curve,
    hashAlgo: String, sc: ScalarOps, B: GroupElement
) : EdDSAParameterSpec(curve, hashAlgo, sc, B)
