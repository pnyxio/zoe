package io.pnyx.keddsa

import io.pnyx.keddsa.spec.EdDSAParameterSpec


interface EdDSAKey {

    /**
     * @return a parameter specification representing the EdDSA domain
     * parameters for the key.
     */
    val params: EdDSAParameterSpec

    companion object {
        /**
         * The reported key algorithm for all EdDSA keys
         */
        val KEY_ALGORITHM = "EdDSA"
    }
}
