package io.pnyx.zoe.bytes

import kotlin.test.Test
import kotlin.test.assertEquals


class BtcVarIntTest {

    @Test
    fun testBytes() {
        val a = BtcVarInt(10) // with widening conversion
        assertEquals(1, a.sizeInBytes)
        assertEquals(1, a.encode().size)
        assertEquals(10, BtcVarInt(a.encode(), 0).value)
    }

    @Test
    fun testShorts() {
        val a = BtcVarInt(64000) // with widening conversion
        assertEquals(3, a.sizeInBytes)
        assertEquals(3, a.encode().size)
        assertEquals(64000, BtcVarInt(a.encode(), 0).value)
    }

    @Test
    fun testShortFFFF() {
        val a = BtcVarInt(0xFFFFL)
        assertEquals(3, a.sizeInBytes)
        assertEquals(3, a.encode().size)
        assertEquals(0xFFFFL, BtcVarInt(a.encode(), 0).value)
    }

    @Test
    fun testInts() {
        val a = BtcVarInt(0xAABBCCDDL)
        assertEquals(5, a.sizeInBytes)
        assertEquals(5, a.encode().size)
        val bytes = a.encode()
        assertEquals(0xAABBCCDDL, 0xFFFFFFFFL and BtcVarInt(bytes, 0).value)
    }

    @Test
    fun testIntFFFFFFFF() {
        val a = BtcVarInt(0xFFFFFFFFL)
        assertEquals(5, a.sizeInBytes)
        assertEquals(5, a.encode().size)
        val bytes = a.encode()
        assertEquals(0xFFFFFFFFL, 0xFFFFFFFFL and BtcVarInt(bytes, 0).value)
    }

    @Test
    fun testLong() {
        val a = BtcVarInt(-0x3501454121524111L)
        assertEquals(9, a.sizeInBytes)
        assertEquals(9, a.encode().size)
        val bytes = a.encode()
        assertEquals(-0x3501454121524111L, BtcVarInt(bytes, 0).value)
    }

    @Test
    fun testSizeOfNegativeInt() {
        // shouldn't normally be passed, but at least stay consistent (bug regression test)
        assertEquals(BtcVarInt.Companion.sizeOf(-1L), BtcVarInt(-1).encode().size)
    }
}

