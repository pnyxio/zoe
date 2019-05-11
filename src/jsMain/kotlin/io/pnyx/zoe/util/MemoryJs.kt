package io.pnyx.zoe.util

import kotlin.js.Date

actual typealias AutoMemory = Date

actual inline fun <R> autoMem(block: AutoMemory?.()->R): R {
        return null.block()
}