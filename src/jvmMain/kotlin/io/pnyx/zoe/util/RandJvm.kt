package io.pnyx.zoe.util

import java.security.NoSuchAlgorithmException
import java.security.SecureRandom

actual interface Rand: RandomGenerator {

//    actual companion object {
//        private val impl = RandImpl()
//        actual fun get(): Rand = impl
//
//    }
    actual companion object {
        actual fun get(): Rand {
            try {
                return JvmRand(SecureRandom.getInstance("NativePRNGNonBlocking"))
            } catch (e: NoSuchAlgorithmException) {
                throw RuntimeException(e)
            }
        }

    }


}

class JvmRand(private val rng: SecureRandom) : Rand {
    override fun nextLong() = rng.nextLong()

    override fun randomBytes(i: Int): ByteArray {
        val res = ByteArray(i)
        rng.nextBytes(res)
        return res
    }

    override fun rint(roof: Int): Int = rng.nextInt(roof)

}

