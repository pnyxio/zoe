package io.pnyx.zoe.ed25519

import io.pnyx.zoe.bytes.BytesWrap
import io.pnyx.zoe.bytes.UInt512
import io.pnyx.zoe.bytes.byteArrayEquals
import io.pnyx.zoe.ed25519.EdGroup.b
import io.pnyx.zoe.ed25519.EdGroup.hash512
import io.pnyx.zoe.util.AutoMemory
import io.pnyx.zoe.util.Rand
import io.pnyx.zoe.util.autoMem
import kotlin.experimental.and
import kotlin.experimental.or

class Seed(bytes: ByteArray) : BytesWrap(bytes) {
    init {
        require(bytes.size == 32)
    }

    companion object {
        fun generate() = Seed(Rand.get().randomBytes(b / 8))
    }

}
class EdDSAKeyPair(val seed: Seed) {
    val pk: PublicKey get() = autoMem { A().compress() }
    fun AutoMemory?.A(): P3 = (a * BasePoint())
    val a: EcScalar get() = EcScalar(h.copyOf(32))
    val h: ByteArray
    init {
        h = hash512(seed)
        //TODO extract and name algo
        h[0] = (h[0].toUByte() and 248.toUByte()).toByte()
        h[31] = h[31] and 63
        h[31] = h[31] or 64
    }
}

data class EdDSASignature(val R: ByteArray, val S: ByteArray)

object EdDSA {
    fun generateKeyPair(): EdDSAKeyPair = generateKeyPairFromSeed(Seed(Rand.get().randomBytes(32)))

    fun generateKeyPairFromSeed(seed: Seed) = EdDSAKeyPair(seed)


    fun sign(kp: EdDSAKeyPair, vararg msgChunks: ByteArray): ByteArray/*64*/ {//TODO not signature ???
        autoMem {
            // r = H(h_b,...,h_2b-1,M) mod l
            val r64 = hash512(
                kp.h.copyOfRange(32, 64),
                *msgChunks
            )
            val r = EdGroup.reduce(UInt512 of r64)
            // R = rB
            val R = r * BPt
            val Rbyte = R.compress()
            // S = (r + H(Rbar,Abar,M)*a) mod l
            val h = EdGroup.reduce(
                UInt512 of
                        hash512(Rbyte.bytes, kp.pk.bytes, *msgChunks)
            )
            //r + h * a
            val S = scalarMulAdd(h, kp.a, r)
            // R+S
            val res = Rbyte.bytes.copyOf(64)
            S.bytes.copyInto(res, 32)
            return res
        }
    }
    fun verify(pk: PublicKey, sig: ByteArray, vararg msgChunks: ByteArray): Boolean {
        autoMem {
            require(sig.size == 64) { "signature length is wrong" }
            val R = sig.copyOfRange(0, 32)
            val S = sig.copyOfRange(32, 64)
            //h = H(Rbar,Abar,M)
            val h = EdGroup.reduce(
                UInt512 of
                        hash512(R, pk.bytes, *msgChunks)
            )
            // R = SB - hA
            val R1 = BPt.doubleScalarMultiplyVariableTime(p3(pk).negate().toP3(), h, S.asEcScalar())
            return byteArrayEquals(R1.compress().bytes, R)
        }
    }


}