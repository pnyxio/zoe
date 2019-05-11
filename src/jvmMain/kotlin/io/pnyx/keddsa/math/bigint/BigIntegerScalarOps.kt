package io.pnyx.keddsa.math.bigint


import java.math.BigInteger

import io.pnyx.keddsa.math.Field
import io.pnyx.keddsa.math.ScalarOps

class BigIntegerScalarOps(f: Field, private val l: BigInteger) : ScalarOps {
    private val enc: BigIntegerLittleEndianEncoding

    init {
        enc = BigIntegerLittleEndianEncoding()
        enc.setField(f)
    }

    override fun reduce(s: ByteArray): ByteArray {
        return enc.encode(enc.toBigInteger(s).mod(l))
    }

    override fun multiplyAndAdd(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray {
        return enc.encode(enc.toBigInteger(a).multiply(enc.toBigInteger(b)).add(enc.toBigInteger(c)).mod(l))
    }

}
