package io.pnyx.zoe.util

import io.pnyx.zoe.ed25519.BPt
import io.pnyx.zoe.ed25519.PointParser
import kotlin.test.Test
import kotlin.test.assertEquals

class AutoMemoryTest {

    @Test
    fun testOne() {
        assertEquals("hello", autoMem {
            PointParser.parse(BPt.compress(), this)
            "hello"
        })
    }
}