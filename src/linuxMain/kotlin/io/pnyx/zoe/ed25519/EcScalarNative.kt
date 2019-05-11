package io.pnyx.zoe.ed25519

import io.pnyx.ed25519monero.sc_add
import io.pnyx.ed25519monero.sc_muladd
import io.pnyx.ed25519monero.sc_mulsub
import kotlinx.cinterop.refTo


actual fun scalarAdd(a: EcScalar, b: EcScalar): EcScalar {
    val res = UByteArray(32)
    sc_add(res.refTo(0), a.bytes.asUByteArray().refTo(0), b.bytes.asUByteArray().refTo(0))
    return EcScalar(res.asByteArray())
}

actual fun scalarMulSub(a: EcScalar, b: EcScalar, c: EcScalar): EcScalar {
    val res = UByteArray(32)
    sc_mulsub(res.refTo(0), a.bytes.asUByteArray().refTo(0), b.bytes.asUByteArray().refTo(0), c.bytes.asUByteArray().refTo(0))
    return EcScalar(res.asByteArray())
}

//(c+ab) mod l
actual fun scalarMulAdd(a: EcScalar, b: EcScalar, c: EcScalar): EcScalar {
    val res = UByteArray(32)
    sc_muladd(res.refTo(0), a.bytes.asUByteArray().refTo(0), b.bytes.asUByteArray().refTo(0), c.bytes.asUByteArray().refTo(0))
    return EcScalar(res.asByteArray())
}