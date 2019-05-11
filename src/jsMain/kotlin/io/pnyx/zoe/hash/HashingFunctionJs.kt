package io.pnyx.zoe.hash

import io.pnyx.zoe.bytes.Bytes

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
        override fun getInstance() = io.pnyx.zoe.hash.Sha512()
    }

}
//TODO https://www.npmjs.com/package/keccak
actual class Keccak256 : HashingFunction {
    override fun invoke(vararg args: Bytes): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    actual companion object : HashingFunctionFactory {
        override fun getInstance(): Keccak256 {
            TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
        }
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
        override fun getInstance() = io.pnyx.zoe.hash.Sha256()
    }
}