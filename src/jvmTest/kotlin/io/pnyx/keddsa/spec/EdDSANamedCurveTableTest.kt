package io.pnyx.keddsa.spec

import io.pnyx.keddsa.spec.EdDSANamedCurveTable.ED_25519
import io.pnyx.keddsa.spec.EdDSANamedCurveTable.ED_25519_CURVE_SPEC
import org.hamcrest.CoreMatchers.*
import org.junit.Assert.*

import org.junit.Test

class EdDSANamedCurveTableTest {
    /**
     * Ensure curve names are case-inspecific
     */
    @Test
    fun curveNamesAreCaseInspecific() {
        val mixed = EdDSANamedCurveTable.getByName("Ed25519")
        val lower = EdDSANamedCurveTable.getByName("ed25519")
        val upper = EdDSANamedCurveTable.getByName("ED25519")

        assertThat(lower, `is`(equalTo(mixed)))
        assertThat(upper, `is`(equalTo(mixed)))
    }

    @Test
    fun testConstants() {
        val spec = EdDSANamedCurveTable.getByName(ED_25519)
        assertThat("Named curve and constant should match", spec, `is`(equalTo(ED_25519_CURVE_SPEC)))
    }
}
