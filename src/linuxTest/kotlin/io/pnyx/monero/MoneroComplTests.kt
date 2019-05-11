package io.pnyx.monero

import io.pnyx.zoe.bytes.asciiEnc
import kotlinx.cinterop.*
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fread
import kotlin.test.Test

class MoneroComplTests {
    @Test
    fun allTests() {
        memScoped {
            val path = "src/commonTest/resources/io/pnyx/monero/tests.txt"
            val tester = MoneroCompl()
            val MAXLEN: ULong = (1024 * 1024 * 16).toULong()
            val all = ByteArray(MAXLEN.toInt())
            val fp = fopen(path, "r")
            require(fp != null)
            val nread = fread(all.refTo(0), 1, MAXLEN, fp)
            val str = all.copyOfRange(0, nread.toInt()).asciiEnc()
            str.split("\n").forEach {
                tester.testLine(it)
            }
            fclose(fp)
        }
    }
}