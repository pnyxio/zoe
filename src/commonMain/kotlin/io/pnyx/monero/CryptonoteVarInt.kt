package io.pnyx.monero

/**
 * Class providing a variable length representation of integers.
 *
 * <style type="text/css"> pre-fw { color: rgb(0, 0, 0); display: block;
 * font-family:courier, "courier new", monospace; font-size: 13px; white-space:
 * pre; } </style>
 *
 * <h2>Base 128 Varints serializer</h2>
 * <p>
 * This serializer is efficient in terms of computing costs as well as
 * bandwith/memory usage.
 * </p>
 * <p>
 * The average memory usage overall the range 0 to
 * {@link java.lang.Integer#MAX_VALUE} is 4.87 bytes per number which is not far
 * from the canonical form ({@link RawInt32}), however varints are an
 * interesting solution since the small values (which are supposed to be more
 * frequent) are using less bytes.
 * </p>
 * <p>
 * All bytes forming a varint except the last one have the most significant bit
 * (MSB) set. The lower 7 bits of each byte contains the actual representation
 * of the two's complement representation of the number (least significant group
 * first).
 * </p>
 * <p>
 * n.b. This serializer is fully compatible with the 128 Varint mechanism
 * shipped with the <a
 * href="https://developers.google.com/protocol-buffers/docs/encoding#varints" >
 * Google Protocol Buffer stack</a> as default representation of messages sizes.
 * </p>
 * <h2>On-wire representation</h2>
 * <p>
 * Encoding of the value 812
 *
 * <pre-fw>
 *
 * 1001 1100  0000 0110
 * ↑          ↑
 * 1          0           // the most significant bit being unset designs the last byte
 *  ___↑____   ___↑____
 *  001 1100   000 0110   // the remaining bits defines the value itself
 * →      44          6   // 44 + 128 * 6 = 812
 * </pre-fw>
 *
 * </p>
 * <p>
 * n.b. This class doesn't have any dependency against Google Protocol Buffer or
 * any other library in order to provide this convenient integer serialization
 * module to any software using FramedMINA.
 * </p>
 *
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 */

import kotlin.IllegalArgumentException
import kotlin.IndexOutOfBoundsException


class CryptonoteVarInt private constructor() {
    companion object {
        fun decode(vint: ByteArray): UInt {
            var pos = 0
            var size: UInt = 0u
            try {
                var i = 0
                while (true) {
                    val tmp = vint[pos++].toUInt()
                    if (tmp and 0x80u == 0u && (i != 4 * 7 || tmp < (1 shl 3).toUInt())) {
                        return size or (tmp shl i)
                    } else if (i < 4 * 7) {
                        size = size or (tmp and 0x7fu shl i)
                    } else {
                        throw IllegalArgumentException("Not the varint representation of a signed int32")
                    }
                    i += 7
                }
            } catch (e: IndexOutOfBoundsException) {
                throw IllegalArgumentException("Not the varint representation of a signed int32 (IndexOutOfBoundsException)")
            }
        }

        fun encode(message: UInt/*, buffer: ByteBuffer*/): ByteArray {
            val res = UByteArray(getEncodedSize(message))
            var pos = 0
            var value = message
            // VarInts don't support negative values
            require(value >= 0u)
            while (value > 0x7fu) {
                res[pos++] = (value and 0x7fu or 0x80u).toUByte()
                value = value shr 7
            }
            res[pos] = value.toUByte()
            return res.asByteArray()
        }

        fun getEncodedSize(message: UInt): Int {
            if (message < 1u) {
                return 1
            } else {
                val log2 = 32 - numberOfLeadingZeros(message)
                return (log2 + 6) / 7
            }
        }

        fun numberOfLeadingZeros(value: UInt): Int {
            for(i in 31 downTo 0) {
                if(0u != value shr i) {
                    return 31 - i
                }
            }
            return 32
        }
    }
}