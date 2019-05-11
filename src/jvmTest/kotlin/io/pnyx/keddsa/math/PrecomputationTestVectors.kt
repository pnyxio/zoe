package io.pnyx.keddsa.math


import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader

import io.pnyx.keddsa.Utils
import io.pnyx.keddsa.spec.*


object PrecomputationTestVectors {
    // Test files were generated using base.py and base2.py from ref10
    // (by printing hex(x%q) instead of the radix-255 representation).
    internal var testPrecmp = getPrecomputation("basePrecmp")
    internal var testDblPrecmp = getDoublePrecomputation("baseDblPrecmp")

    fun precmpRow(): Array<GroupElement> {
        @Suppress("UNCHECKED_CAST")
        return arrayOfNulls<GroupElement>(8) as  Array<GroupElement>
    }
    fun getPrecomputation(fileName: String): Array<Array<GroupElement>> {
        val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)!!
        val curve = ed25519.curve
        val field = curve.field
        val precmp = Array<Array<GroupElement>>(32) { precmpRow() }
        var file: BufferedReader? = null
        var row = 0
        var col = 0
        try {
            val `is` = PrecomputationTestVectors::class.java.getResourceAsStream(fileName)
                ?: throw IOException("Resource not found: $fileName")
            file = BufferedReader(InputStreamReader(`is`))
            var line = file.readLine()
            while (line != null) {
                if (line == " },")
                    col += 1
                else if (line == "},") {
                    col = 0
                    row += 1
                } else if (line.startsWith("  { ")) {
                    val ypxStr = line.substring(4, line.lastIndexOf(' '))
                    val ypx = field.fromByteArray(
                        Utils.hexToBytes(ypxStr)
                    )
                    line = file.readLine()
                    val ymxStr = line.substring(4, line.lastIndexOf(' '))
                    val ymx = field.fromByteArray(
                        Utils.hexToBytes(ymxStr)
                    )
                    line = file.readLine()
                    val xy2dStr = line.substring(4, line.lastIndexOf(' '))
                    val xy2d = field.fromByteArray(
                        Utils.hexToBytes(xy2dStr)
                    )
                    precmp[row][col] = GroupElement.Companion.precomp(
                        curve,
                        ypx, ymx, xy2d
                    )
                }
                line = file.readLine()
            }
        } catch (e: IOException) {
            e.printStackTrace()
        } finally {
            if (file != null) try {
                file.close()
            } catch (e: IOException) {
            }

        }
        return precmp
    }

    fun getDoublePrecomputation(fileName: String): Array<GroupElement> {
        val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
        val curve = ed25519!!.curve
        val field = curve.field
        val dblPrecmp = precmpRow()
        var file: BufferedReader? = null
        var row = 0
        try {
            val `is` = PrecomputationTestVectors::class.java.getResourceAsStream(fileName)
                ?: throw IOException("Resource not found: $fileName")
            file = BufferedReader(InputStreamReader(`is`))
            var line = file.readLine()
            while (line != null) {
                if (line == " },") {
                    row += 1
                } else if (line.startsWith("  { ")) {
                    val ypxStr = line.substring(4, line.lastIndexOf(' '))
                    val ypx = field.fromByteArray(
                        Utils.hexToBytes(ypxStr)
                    )
                    line = file.readLine()
                    val ymxStr = line.substring(4, line.lastIndexOf(' '))
                    val ymx = field.fromByteArray(
                        Utils.hexToBytes(ymxStr)
                    )
                    line = file.readLine()
                    val xy2dStr = line.substring(4, line.lastIndexOf(' '))
                    val xy2d = field.fromByteArray(
                        Utils.hexToBytes(xy2dStr)
                    )
                    dblPrecmp[row] = GroupElement.Companion.precomp(
                        curve,
                        ypx, ymx, xy2d
                    )
                }
                line = file.readLine()
            }
        } catch (e: IOException) {
            e.printStackTrace()
        } finally {
            if (file != null) try {
                file.close()
            } catch (e: IOException) {
            }

        }
        return dblPrecmp
    }
}
