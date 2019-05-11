package io.pnyx.zoe.util

import kotlinx.cinterop.MemScope
import kotlinx.cinterop.NativePlacement
import kotlinx.cinterop.memScoped

abstract class AutoMem(val autoMem: NativePlacement) {

}
actual typealias AutoMemory = MemScope

actual inline fun <R> autoMem(block: AutoMemory?.()->R): R = memScoped(block)


