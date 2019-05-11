package io.pnyx.zoe.util

actual typealias AutoMemory = Void

actual inline fun <R> autoMem(block: AutoMemory?.()->R): R {
        return null.block()
}