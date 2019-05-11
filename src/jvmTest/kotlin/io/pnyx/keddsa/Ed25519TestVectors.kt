package io.pnyx.keddsa

import io.pnyx.keddsa.Utils

import java.io.BufferedReader
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.util.ArrayList

object Ed25519TestVectors {

    var testCases = getTestData("test.data")

    class TestTuple(line: String) {
        var caseNum: Int = 0
        var seed: ByteArray
        var pk: ByteArray
        var message: ByteArray
        var sig: ByteArray

        init {
            caseNum = ++numCases
            val x = line.split(":".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
            seed = Utils.hexToBytes(x[0].substring(0, 64))
            pk = Utils.hexToBytes(x[1])
            message = Utils.hexToBytes(x[2])
            sig = Utils.hexToBytes(x[3].substring(0, 128))
        }

        companion object {
            var numCases: Int = 0
        }
    }

    fun getTestData(fileName: String): Collection<TestTuple> {
        val testCases = ArrayList<TestTuple>()
        var file: BufferedReader? = null
        try {
            val `is` = Ed25519TestVectors::class.java.getResourceAsStream(fileName)
                ?: throw IOException("Resource not found: $fileName")
            file = BufferedReader(InputStreamReader(`is`))
            var line: String? = file.readLine()
            do {
                testCases.add(TestTuple(line!!))
                line = file.readLine()
            } while (line != null)
        } catch (e: IOException) {
            e.printStackTrace()
        } finally {
            if (file != null) try {
                file.close()
            } catch (e: IOException) {
            }

        }
        return testCases
    }
}
