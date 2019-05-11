package io.pnyx.keddsa.spec

import java.security.spec.AlgorithmParameterSpec

/**
 * Implementation of AlgorithmParameterSpec that holds the name of a named
 * EdDSA curve specification.
 * @author str4d
 */
class EdDSAGenParameterSpec(val name: String) : AlgorithmParameterSpec
