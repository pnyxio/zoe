package io.pnyx.zoe.ed25519

//import java.util.*

object Utilz {

//    fun bitString(bitstring: ByteArray): String {
//        val sb = StringBuilder()
//        for (b in bitstring) {
//            sb.append(byteToString(b))
//            sb.append(".")
//        }
//        return sb.toString()
//    }

//    fun byteToString(b: Byte): String {
//        return Integer.toBinaryString((b.toInt() and 0xFF) + 0x100).substring(1)
//    }
//
//    fun toUInt512(uint256: UInt256) : UInt512 {
//        return UInt512(Arrays.copyOf(uint256.bytes, 64))
//    }
//
//    /*private*/ fun coerceToLTimes8(barr32: ByteArray): UInt256 {
//        //TODO enforce 32 bytes ? should work anyway
//        val res = barr32.clone()
//        res[0] = res[0] and 0xF8.toByte()
//        res[31] = res[31] and 0x3F.toByte()
//        res[31] = res[31] or 0x40.toByte()
//        return UInt256(res)
//    }

//    fun randScal(): UInt256 {
//        val randomBytes32 = Rand.get().randomBytes(32)
//        randomBytes32[31] = randomBytes32[31] and 0x7F.toByte()
//        if(randomBytes32[31] != 0x7F.toByte()) {
//            return UInt256(randomBytes32)
//        }
//        for(i in 1 until 30) {
//            if(randomBytes32[i] != 0xFF.toByte()) {
//                return UInt256(randomBytes32)
//            }
//        }
//        var lsb = randomBytes32[0].toInt()
//        while(lsb >= 237) {
//            //TODO proiettare su tutti i 255 se i è nei byte superiori o nei primi tre bit basta settarlo ne no check while
//            val mask = (1 shl Rand.get().rint(8)).inv() and 0x000000FF
//            lsb = lsb or mask
//        }
//        randomBytes32[0] = lsb.toByte()
//        return UInt256(randomBytes32)
//    }
//    fun randModGroupOrder() = Ed25519Scalar.reduce(UInt512(Rand.get().randomBytes(64)))
//    fun bitAtIsset(bytes: ByteArray, pos: Int): Boolean {//true 1 false 0
//        val nbyte = pos / 8
//        val nbit = pos % 8
//        val mask = (1 shl (7 - nbit)).toByte()
//        return (bytes[nbyte] and mask) != 0.toByte()
//    }

}
