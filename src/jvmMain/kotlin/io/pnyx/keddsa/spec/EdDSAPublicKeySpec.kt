package io.pnyx.keddsa.spec

import java.security.spec.KeySpec

import io.pnyx.keddsa.math.GroupElement

class EdDSAPublicKeySpec : KeySpec {
    val a: GroupElement
    private var Aneg: GroupElement? = null
    val params: EdDSAParameterSpec

    // Only read Aneg once, otherwise read re-ordering might occur between here and return. Requires all GroupElement's fields to be final.
    val negativeA: GroupElement?
        get() {
            var ourAneg = Aneg
            if (ourAneg == null) {
                ourAneg = a.negate()
                Aneg = ourAneg
            }
            return ourAneg
        }

    /**
     * @param pk the public key
     * @param spec the parameter specification for this key
     * @throws IllegalArgumentException if key length is wrong
     */
    constructor(pk: ByteArray, spec: EdDSAParameterSpec) {
        if (pk.size != spec.curve.field.getb() / 8)
            throw IllegalArgumentException("public-key length is wrong")

        this.a = GroupElement(spec.curve, pk)
        this.params = spec
    }

    constructor(A: GroupElement, spec: EdDSAParameterSpec) {
        this.a = A
        this.params = spec
    }
}

