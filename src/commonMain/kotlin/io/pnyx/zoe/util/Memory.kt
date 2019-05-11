package io.pnyx.zoe.util

expect class AutoMemory

expect inline fun <R> autoMem(block: AutoMemory?.()->R): R

