package io.pnyx.zoe.hash

import io.pnyx.ed25519monero.KECCAK_CTX
import io.pnyx.ed25519monero.keccak_finish
import io.pnyx.ed25519monero.keccak_init
import io.pnyx.ed25519monero.keccak_update
import io.pnyx.zoe.bytes.Bytes
import io.pnyx.zoe.bytes.ubytes
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.refTo

actual class Sha512 : HashingFunction {
    override fun invoke(vararg args: Bytes): ByteArray {
        val d = SHA512Digest()
        for(b in args) {
            d.update(b.bytes, 0, b.size)
        }

        val res = ByteArray(64)
        d.doFinal(res, 0)
        return res
    }

    actual companion object : HashingFunctionFactory {
        override fun getInstance() = Sha512()
    }

}

actual class Keccak256 : HashingFunction {
    override fun invoke(vararg args: Bytes): ByteArray {
        val res = UByteArray(32)
        memScoped {
            val kc = alloc<KECCAK_CTX>()
            keccak_init(kc.ptr)
            for(arr in args) {
                if(arr.size > 0) {
                    keccak_update(kc.ptr, arr.ubytes.refTo(0), arr.size.toULong())
                }
            }
            keccak_finish(kc.ptr, res.refTo(0))
        }
        return res.asByteArray()
    }

    actual companion object : HashingFunctionFactory {
        override fun getInstance(): HashingFunction = Keccak256()
    }

}

actual class Sha256 : HashingFunction {
    override fun invoke(vararg args: Bytes): ByteArray {
        val d = SHA256Digest()
        for(b in args) {
            d.update(b.bytes, 0, b.size)
        }

        val res = ByteArray(32)
        d.doFinal(res, 0)
        return res
    }

    actual companion object : HashingFunctionFactory {
        override fun getInstance() = Sha256()
    }
}