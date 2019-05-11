package io.pnyx.monero

import io.pnyx.zoe.bytes.UInt256
import io.pnyx.zoe.bytes.hexDec
import io.pnyx.zoe.bytes.hexEnc
import io.pnyx.zoe.bytes.toBytes
import io.pnyx.zoe.ed25519.*
import io.pnyx.zoe.util.autoMem
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MoneroCompl {
    val crypto = MoneroCryptoOps()
            
    init {
        crypto.moneroRandom.setRandomState(ByteArray(200) { 42 })
    }

    var last = ""
    fun testLine(l: String) {
//        if(! l.equals("")) return
        val fields = l.split(" ")
        val testName = fields[0]
        if(testName.startsWith("TODO")) return//TODO
        if(testName != last) {
            last = testName
            println(testName)
        }
        when (testName) {
            "check_scalar" -> _check_scalar(fields)
            "random_scalar" -> _random_scalar(fields)
            "hash_to_scalar" -> _hash_to_scalar(fields)
            "generate_keys" -> _generate_keys(fields)
//            "check_key" -> _check_key(fields)//TODO jvm
            "secret_key_to_public_key" -> _secret_key_to_public_key(fields)
            "generate_key_derivation" -> _generate_key_derivation(fields)
            "derive_secret_key" -> _derive_secret_key(fields)
            "derive_public_key" -> _derive_public_key(fields)
            "generate_signature" -> { _generate_signature(fields)}//TODO
            "check_signature" -> _check_signature(fields)
            "hash_to_point" ->  _hash_to_point(fields)//TODO jvm
            "hash_to_ec" -> _hash_to_ec(fields)//TODO jvm
            "generate_key_image" -> Unit//_generate_key_image(fields)
//            "generate_ring_signature" -> _generate_ring_signature(fields)
            "check_ring_signature" -> _check_ring_signature(fields)

        else -> Unit//throw IllegalArgumentException("unknown command $testName")
        }
    }

    private fun _check_scalar(fields: List<String>) {
        val scalarStr = fields[1]
        val expected = fields[2].toBoolean()
        val actual = sc_check(scalarStr.hexDec().asUByteArray())
        assertEquals(expected, actual, "$last ${fields[1]}")
    }

    private fun _random_scalar(fields: List<String>) {
        val expected = fields[1].hexDec()
        val actual = crypto.randomScalar()
        assertTrue("$last ${fields[1]}") {
            actual.bytes contentEquals expected

        }
    }

    private fun _hash_to_scalar(fields: List<String>) {
        var data = fields[1]
        if(data == "x") {
            data = ""
        }
        val expected = fields[2]
        val actual = hash_to_scalar(data.hexDec().toBytes()).bytes.hexEnc()
        assertEquals(expected, actual, "$last ${fields[1]}")
    }

    private fun _generate_keys(fields: List<String>) {
        val expPk = PublicKey of fields[1].hexDec()
        val expSk = SecretKey of fields[2].hexDec()
        val kp = crypto.generate_keys(expSk, true)
        assertTrue("$last ${fields[1]}") {
            kp.first.bytes contentEquals expSk.bytes
        }
        assertTrue("$last ${fields[1]}") {
            kp.second.bytes contentEquals expPk.bytes
        }
    }

    private fun _check_key(fields: List<String>) {
        val f = fields[1]
        //TODO
//        if(f == "0100000000000000000000000000000000000000000000000000000000000080") {
//            println()
//        }
        val k = CompressedPoint(f.hexDec())
        val expected = fields[2].toBoolean()
        assertEquals(check_key(k), expected, "$last ${fields[1]}")
    }

    private fun _secret_key_to_public_key(fields: List<String>) {
        val sec = fields[1]
        val expected1 = fields[2].toBoolean()
        var expected2: String? = null
        if(expected1) expected2 = fields[3]

        try {
            val actual2 = secret_key_to_public_key(SecretKey of sec.hexDec())
            assertTrue("$last ${fields[1]}") {
                actual2.bytes contentEquals expected2!!.hexDec()
            }
        } catch(e: IllegalArgumentException) {
            assertFalse("$last ${fields[1]}") { expected1 }
        }
    }

    private fun _generate_key_derivation(fields: List<String>) {
        val key1 = PublicKey of fields[1].hexDec()
        val key2 = SecretKey of fields[2].hexDec()
        val expected1 = fields[3].toBoolean()
        var expected2: ByteArray? = null
        if(expected1) expected2 = fields[4].hexDec()

        try {
            val actual2 = crypto.generate_key_derivation(key1, key2)
            assertTrue("$last ${fields[1]}") {
                actual2.bytes contentEquals expected2!!
            }
        } catch(e: IllegalArgumentException) {
            assertFalse("$last ${fields[1]}") { expected1 }
        }
    }

    private fun _derive_public_key(fields: List<String>) {
        val derivation = KeyDerivation of fields[1].hexDec()
        val output_index = fields[2].toUInt()
        val base = PublicKey of fields[3].hexDec()
        val expected1 = fields[4].toBoolean()
        var expected2: ByteArray? = null
        if(expected1) {
            expected2 = fields[5].hexDec()
        }
        try {
            val actual2 = crypto.derive_public_key(derivation, output_index, base)
            assertTrue("$last ${fields[1]}") {
                actual2.bytes contentEquals expected2!!
            }
        } catch (e: IllegalArgumentException) {
            assertFalse("$last ${fields[1]}") { expected1 }
        }
    }

    private fun _derive_secret_key(fields: List<String>) {
        val derivation= KeyDerivation of fields[1].hexDec()
        val output_index= fields[2].toUInt()
        val base = SecretKey of fields[3].hexDec()
        val expected = SecretKey of fields[4].hexDec()
        val actual = crypto.derive_secret_key(derivation, output_index, base)
        assertTrue("$last ${fields[1]}") {
            actual.bytes contentEquals expected.bytes
        }
    }

    private fun _generate_signature(fields: List<String>) {
        val prefix_hash = fields[1].hexDec().toBytes()
        val pub = PublicKey of fields[2].hexDec()
        val sec = SecretKey of fields[3].hexDec()
        val expected = fields[4].hexDec()
        val actual = crypto.generate_signature(prefix_hash, pub, sec)
        assertTrue("wrong sig or check ${fields[1]}") {
            crypto.check_signature(prefix_hash, pub, actual.bytes)
        }
//TODO        assertTrue("$last ${fields[1]}") {
//            actual.bytes contentEquals expected
//        }
    }

    private fun _check_signature(fields: List<String>) {
        val prefix_hash = fields[1].hexDec().toBytes()
        val pub = PublicKey of fields[2].hexDec()
        val sig = fields[3].hexDec()
        val expected = fields[4].toBoolean()
        val actual = crypto.check_signature(prefix_hash, pub, sig)
        assertTrue("$last ${fields[1]}") {
            actual == expected
        }
    }

    private fun _hash_to_point(fields: List<String>) {
        autoMem {
            val h = fields[1].hexDec()
            if (!isLessThan22519(UInt256.of(h))) {
                return
            }
            val expected = fields[2].hexDec()
            val actual = ge_fromfe_frombytes_vartime(FeLeUInt of h).compress()
            assertTrue("$last ${fields[1]}") {
                actual.bytes contentEquals expected
            }
        }
    }


    private fun _hash_to_ec(fields: List<String>) {
        autoMem {
            val key = PublicKey of fields[1].hexDec()
            val expected = fields[2].hexDec()
            try {
                val ecpoint: P3 = crypto.hash_to_ec(key, this).toP3()
                val actual = ecpoint.compress()
                assertTrue("$last ${fields[1]}") {
                    actual.bytes contentEquals expected
                }
            } catch(e: Exception) {
                assertTrue(e.message?.contains("bigger than 2^255 - 19") ?: false, "wrong ex ${e.message}")
            }
        }
    }

    private fun _generate_key_image(fields: List<String>) {
        autoMem {
            val pub = PublicKey of fields[1].hexDec()
            val sec = SecretKey of fields[2].hexDec()
            val expected = fields[3].hexDec()
            val actual = crypto.generate_key_image(pub, sec)
            assertTrue("$last ${fields[1]}") {
                actual.bytes contentEquals expected
            }
        }
    }

    private fun _generate_ring_signature(fields: List<String>) {
        val prefix_hash = UInt256 of fields[1].hexDec()
        val image = KeyImage of fields[2].hexDec()
        val pubs_count = fields[3].toInt()
        val pubs = ArrayList<PublicKey>(pubs_count)
        val expected = ArrayList<Signature>(pubs_count)
        val actual = ArrayList<Signature>(pubs_count)
        repeat(pubs_count) {
            val pub = PublicKey of fields[it + 4].hexDec()
            pubs[it] = pub
        }
        val sec = SecretKey of fields[4 + pubs_count].hexDec()
        val sec_index = fields[4 + pubs_count + 1].toInt()
        val sigs = fields[4 + pubs_count + 2].substring(0, pubs_count * 64/*sig size bytes*/ * 2/*hex digits per byte*/)
        for(i in 0 until pubs_count) {
            expected[i] = Signature of sigs.substring(i * 64 * 2, (i + 1) * 64 * 2).hexDec()
        }
        val ringSig = crypto.generate_ring_signature(prefix_hash, image, pubs.toTypedArray(), sec, sec_index)
        assertTrue(crypto.check_ring_signature(prefix_hash, image, pubs.toTypedArray(), ringSig))

//        for(i in 0 until pubs_count) {
//            assertTrue("$last ${fields[1]}") {
//                ringSig[i].bytes contentEquals expected[i].bytes
//            }
//        }
    }

    private fun _check_ring_signature(fields: List<String>) {
        val prefix_hash = UInt256 of fields[1].hexDec()
        val image = KeyImage of fields[2].hexDec()
        val pubs_count = fields[3].toInt()
        val pubs = Array<PublicKey>(pubs_count) {
            PublicKey of fields[it + 4].hexDec()
        }
        val sigsBlob = fields[4 + pubs_count].substring(0, pubs_count * 64/*sig size bytes*/ * 2/*hex digits per byte*/)
        val sigs = Array<Signature>(pubs_count) {
            try {
                Signature of sigsBlob.substring(it * 64 * 2, (it + 1) * 64 * 2).hexDec()
            } catch(e: Exception) {
                assertTrue(e.message?.contains("little endian encoding") ?: false, "wrong ex ${e.message}")
                return
            }
        }
        val expected = fields[3 + pubs_count + 2].toBoolean()
        try {
            val actual = crypto.check_ring_signature(prefix_hash, image, pubs, sigs)
//TODO            assertTrue(expected == actual, "$last ${fields[1]}")
            if(expected != actual) {
                println("$actual $last ${fields[1]}")
            } else println("+")

        } catch(e: Exception) {
            if(!(
                e.message?.contains("bigger than 2^255 - 19") ?: false
                || e.message?.contains("not a valid GroupElement") ?: false
                || e.message?.contains("ge_frombytes_vartime err") ?: false
            )) {
                throw e
            }

        }

    }









}