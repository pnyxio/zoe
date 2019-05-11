package io.pnyx.zoe.hash

import io.pnyx.zoe.bytes.Bytes
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.jcajce.provider.digest.Keccak


actual class Sha512 : HashingFunction {
    override fun invoke(vararg args: Bytes): ByteArray {
        val digest = SHA512Digest()
        for(b in args) {
            digest.update(b.bytes, 0, b.size)
        }
        val res = ByteArray(64)
        digest.doFinal(res, 0)
        return res
    }

    actual companion object : HashingFunctionFactory {
        override fun getInstance() = Sha512()
    }

}

actual class Keccak256 : HashingFunction {
    override fun invoke(vararg args: Bytes): ByteArray {
        val digest = Keccak.Digest256()
        for(b in args) {
            digest.update(b.bytes, 0, b.size)
        }
        return digest.digest()
    }

    actual companion object : HashingFunctionFactory {
        override fun getInstance() = Keccak256()
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