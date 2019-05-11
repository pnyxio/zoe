package io.pnyx.monero

import kotlin.test.Test

class MoneroComplTests {

    @Test
    fun allTests() {
        val tester = MoneroCompl()

        val testsIs = MoneroComplTests::class.java.getResourceAsStream("tests.txt")

        val br = testsIs.bufferedReader()

        br.lines().forEach {
            tester.testLine(it)
        }

    }
}