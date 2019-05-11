package io.pnyx.zoe.util

import kotlin.random.Random

interface RandomGenerator {
    fun randomBytes(i: Int): ByteArray

    fun rint(roof: Int): Int

    fun nextLong(): Long

}

expect interface Rand : RandomGenerator {

    companion object {
        fun get(): Rand
    }
}

open class RandImpl: Rand {
    override fun randomBytes(i: Int): ByteArray = Random.nextBytes(i)

    override fun rint(roof: Int): Int = Random.nextInt(roof)

    override fun nextLong(): Long = Random.nextLong()

}