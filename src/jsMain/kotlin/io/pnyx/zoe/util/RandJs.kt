package io.pnyx.zoe.util

actual interface Rand: RandomGenerator {
    actual companion object {
        private val impl = RandImpl()
        actual fun get(): Rand = impl
    }

}