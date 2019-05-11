package io.pnyx.zoe.ed25519

actual fun scalarAdd(a: EcScalar, b: EcScalar) =
    EcScalar(sc_add(a.bytes.asUByteArray(), b.bytes.asUByteArray()).toByteArray())

actual fun scalarMulSub(a: EcScalar, b: EcScalar, c: EcScalar): EcScalar =
    EcScalar(sc_mulsub(a.bytes.asUByteArray(), b.bytes.asUByteArray(), c.bytes.asUByteArray()).toByteArray())

//(c+ab) mod l
actual fun scalarMulAdd(a: EcScalar, b: EcScalar, c: EcScalar): EcScalar =
    EcScalar(sc_muladd(a.bytes.asUByteArray(), b.bytes.asUByteArray(), c.bytes.asUByteArray()).toByteArray())