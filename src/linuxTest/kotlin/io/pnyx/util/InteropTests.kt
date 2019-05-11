package io.pnyx.util

import io.pnyx.ed25519monero.fe
import io.pnyx.ed25519monero.int32_t
import kotlinx.cinterop.*
import kotlin.test.Test
import kotlin.test.assertEquals

class InteropTests {

    @Test
    fun getRndVal() {
        val _fe:fe = nativeHeap.allocArray<IntVarOf<int32_t>>(10)
        assertEquals(0, _fe[0])
        nativeHeap.free(_fe)
    }
}


