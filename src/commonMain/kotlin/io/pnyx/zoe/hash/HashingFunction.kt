package io.pnyx.zoe.hash

import io.pnyx.zoe.bytes.Bytes
import io.pnyx.zoe.bytes.toBytes

interface HashingFunctionFactory {

    fun getInstance(): HashingFunction
}

expect class Sha512: HashingFunction {

    companion object: HashingFunctionFactory {
    }
}

expect class Sha256: HashingFunction {

    companion object: HashingFunctionFactory {
    }
}

expect class Keccak256: HashingFunction {

    companion object: HashingFunctionFactory {
    }
}


enum class HashingAlgo(val fixedLength: Boolean, val digestLength/*in bits -1 for varlen*/: Int, val factory: HashingFunctionFactory) {
    SHA_512(true, 512, Sha512),
    KECCAK_256(true, 256, Keccak256),
    SHA_256(true, 256, Sha256),

}

val keccak256 get() = HashingAlgo.KECCAK_256.factory.getInstance()

interface HashingFunction {
    operator fun invoke(vararg args: Bytes): ByteArray

    operator fun invoke(vararg args: ByteArray): ByteArray =
        invoke(*(args.map { it.toBytes() }.toTypedArray()))

}

//object HashingAlgoFactory {
//    fun getInstance(algo: HashingAlgo): HashingFunction = algo.factory.getInstance()
//
//}