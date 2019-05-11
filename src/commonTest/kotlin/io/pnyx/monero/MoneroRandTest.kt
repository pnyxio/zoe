package io.pnyx.monero

import io.pnyx.zoe.hash.KeccakPermutation
import io.pnyx.zoe.ed25519.sc_reduce32
import io.pnyx.zoe.bytes.hexEnc
import kotlin.test.Test
import kotlin.test.assertEquals

class MoneroRandTest {

    @Test
    fun testFirst10() {

        val randz = KeccakPermutation(ByteArray(200) { 42 })
        repeat(10) {
            val rnd = randz.next().copyOfRange(0, 32)
            sc_reduce32(rnd.asUByteArray())
            assertEquals(expected[it], rnd.hexEnc())
        }
    }

    val expected = arrayOf(
        "6cf2e94a33a801b7f0822fb93a0bbeda3b1ae2b869bc48d1a4fbee82e1d85b09",
        "b380e50df296578856654800f5b9d67d49aa9558546a670420732287b4c75e00",
        "921c21906cac3499d38f8ee5eb5bdc943a0f19358524d97ca9ad694ba3780707",
        "c6164059b6e29b4f34101c3116625c245a56b8353cf276aacb54f08318ff5e0d",
        "0d54c3c5d8046ad415e0bb9e99d359f60ddbaa07cf12cdb069ba80fa35021102",
        "23b888c3387955b2950af690c5b9bab6ca3af8ed9a9ffb951789277d50332e0b",
        "42e4b4d13ed6f9302b0a050f7fac7fb7022d79976b9795c93946c433e2665d06",
        "347065b13ad735ff9e1cd8b471aca4f97d7690b326173fecbbd78528a6d8990e",
        "a843cbb2a416c655669cbf1a5f452beddba17c8f5c17711c9af6d2580b4b890a",
        "93dba1d862d13f16c84fb050117483e48d5821979a4bf468901cf954f6b86d0c",
        "307e5c1c1643cba6aec9b1f7c67fde082ff1686c6a53376b2b4a8a84af2c3f0f",
        "f02178e283466b8e7747fff209c242dc90b0a4df7f1bb98acb81c6d2332d8806",
        "b92d6b60e266e5ffddd530548d77dfb7a3b251748acd16f6ffefab5ecdf2f902",
        "9e6d32f8ac881f5821a146969b33b89dd16e4dfcaa1dcae522aa080021caee0f",
        "17072c56bfe20546f15c8bd14e91c861d7795bedd3bedf9120233c4e289c7906"
    )









//    fun yyy(s: ByteArray): LongArray {
//        require(s.size == 200)
//        val res = LongArray(25)
//        for(i in 0 until 25) {
//            res[i] = littleEndianToLong(s, i * 8)
//        }
//        return res
//    }
//
//    fun zzz(s: ULongArray): ByteArray {
//        require(s.size == 25)
//        val res = ByteArray(200)
//        for(i in 0 until 25) {
//            longToLittleEndian(s[i].toLong()).copyInto(res, i * 8)
//        }
//        return res
//    }
//
//    @Test
//    fun allTests() {
//        var seed = ByteArray(200) {42}
//
//        repeat(10) {
//            val x = yyy(seed)//ULongArray(25)
//            val oo = x.toULongArray()
//            keccakf(oo.refTo(0), 24)
//            val res = zzz(oo)
//            seed = res.copyOf()
//            val t  = res.copyOf(32)
//            sc_reduce32(t.asUByteArray())
//            println(t.hexEnc())
//        }
////        memScoped {
////            val path = "src/commonTest/resources/io/pnyx/zoe/monero/tests.txt"
////            val tester = MoneroCompl()
////            val MAXLEN: ULong = (1024 * 1024 * 16).toULong()
////            val all = ByteArray(MAXLEN.toInt())
////            val fp = fopen(path, "r")
////            require(fp != null)
////            var nread = fread(all.refTo(0), 1, MAXLEN, fp)
////            println("nread: $nread")
////            val str = all.copyOfRange(0, nread.toInt()).asciiEnc()
////            println("str: ${str.length}")
////            str.split("\n").forEach {
////                tester.testLine(it)
////            }
////            fclose(fp)
////        }
//
//    }
}