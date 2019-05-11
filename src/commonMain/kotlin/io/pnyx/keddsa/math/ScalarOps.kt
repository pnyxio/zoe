package io.pnyx.keddsa.math

interface ScalarOps {
    /**
     * Reduce the given scalar mod $l$.
     *
     *
     * From the Ed25519 paper:<br></br>
     * Here we interpret $2b$-bit strings in little-endian form as integers in
     * $\{0, 1,..., 2^{(2b)}-1\}$.
     * @param s the scalar to reduce
     * @return $s \bmod l$
     */
    fun reduce(s: ByteArray): ByteArray

    /**
     * $r = (a * b + c) \bmod l$
     * @param a a scalar
     * @param b a scalar
     * @param c a scalar
     * @return $(a*b + c) \bmod l$
     */
    fun multiplyAndAdd(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray

}