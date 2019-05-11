package io.pnyx.zoe.hash

import io.pnyx.zoe.bytes.littleEndianToLong
import io.pnyx.zoe.bytes.longToLittleEndian
import kotlin.experimental.or
import kotlin.math.min


/**
 * implementation of Keccak based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
 * <p>
 * Following the naming conventions used in the C source code to enable easy review of the implementation.
 */
open class KeccakDigest {
    protected var state = LongArray(25)
    protected var dataQueue = ByteArray(192)
    protected var rate: Int = 0
    protected var bitsInQueue: Int = 0
    protected var fixedOutputLength: Int = 0
    protected var squeezing: Boolean = false

    constructor(bitLength: Int) {
        init(bitLength)
    }

    constructor() : this(288)

    constructor(source: KeccakDigest) {
        source.state.copyInto(state)
        source.dataQueue.copyInto(dataQueue)
        this.rate = source.rate
        this.bitsInQueue = source.bitsInQueue
        this.fixedOutputLength = source.fixedOutputLength
        this.squeezing = source.squeezing
    }

    private fun init(bitLength: Int) {
        when (bitLength) {
            128, 224, 256, 288, 384, 512 -> initSponge(1600 - (bitLength shl 1))
            else -> throw IllegalArgumentException("bitLength must be one of 128, 224, 256, 288, 384, or 512.")
        }
    }
    fun getDigestSize(): Int {
        return fixedOutputLength / 8
    }
    fun update(input: Byte) {
        absorb(byteArrayOf(input), 0, 1)
    }

    fun update(input: ByteArray, inOff: Int, len: Int) {
        absorb(input, inOff, len)
    }

    fun doFinal(out: ByteArray, outOff: Int): Int {
        squeeze(out, outOff, fixedOutputLength.toLong())

        reset()

        return getDigestSize()
    }

    protected fun doFinal(out: ByteArray, outOff: Int, partialByte: Byte, partialBits: Int): Int {
        if (partialBits > 0) {
            absorbBits(partialByte.toInt(), partialBits)
        }

        squeeze(out, outOff, fixedOutputLength.toLong())

        reset()

        return getDigestSize()
    }

    /**
     * Return the size of block that the compression function is applied to in bytes.
     *
     * @return internal byte length of a block.
     */
    fun getByteLength(): Int {
        return rate / 8
    }

    fun reset() {
        init(fixedOutputLength)
    }

    private fun initSponge(rate: Int) {
        if (rate <= 0 || rate >= 1600 || rate % 64 != 0) {
            throw IllegalStateException("invalid rate value")
        }

        this.rate = rate
        for (i in state.indices) {
            state[i] = 0L
        }
        ZEROED_DATAQUEUE.copyInto(this.dataQueue)
        this.bitsInQueue = 0
        this.squeezing = false
        this.fixedOutputLength = (1600 - rate) / 2
    }

    protected fun absorb(data: ByteArray, off: Int, len: Int) {
        if (bitsInQueue % 8 != 0) {
            throw IllegalStateException("attempt to absorb with odd length queue")
        }
        if (squeezing) {
            throw IllegalStateException("attempt to absorb while squeezing")
        }

        var bytesInQueue = bitsInQueue shr 3
        val rateBytes = rate shr 3

        var count = 0
        while (count < len) {
            if (bytesInQueue == 0 && count <= len - rateBytes) {
                do {
                    KeccakAbsorb(data, off + count)
                    count += rateBytes
                } while (count <= len - rateBytes)
            } else {
                val partialBlock = min(rateBytes - bytesInQueue, len - count)
                data.copyInto(dataQueue, bytesInQueue, off + count, off + count +partialBlock)

                bytesInQueue += partialBlock
                count += partialBlock

                if (bytesInQueue == rateBytes) {
                    KeccakAbsorb(dataQueue, 0)
                    bytesInQueue = 0
                }
            }
        }

        bitsInQueue = bytesInQueue shl 3
    }

    protected fun absorbBits(data: Int, bits: Int) {
        if (bits < 1 || bits > 7) {
            throw IllegalArgumentException("'bits' must be in the range 1 to 7")
        }
        if (bitsInQueue % 8 != 0) {
            throw IllegalStateException("attempt to absorb with odd length queue")
        }
        if (squeezing) {
            throw IllegalStateException("attempt to absorb while squeezing")
        }

        val mask = (1 shl bits) - 1
        dataQueue[bitsInQueue shr 3] = (data and mask).toByte()

        // NOTE: After this, bitsInQueue is no longer a multiple of 8, so no more absorbs will work
        bitsInQueue += bits
    }

    private fun padAndSwitchToSqueezingPhase() {
        dataQueue[bitsInQueue shr 3] = dataQueue[bitsInQueue shr 3] or (1L shl (bitsInQueue and 7)).toByte()

        if (++bitsInQueue == rate) {
            KeccakAbsorb(dataQueue, 0)
            bitsInQueue = 0
        }

        run {
            val full = bitsInQueue shr 6
            val partial = bitsInQueue and 63
            var off = 0
            for (i in 0 until full) {
                state[i] = state[i] xor littleEndianToLong(dataQueue, off)
                off += 8
            }
            if (partial > 0) {
                val mask = (1L shl partial) - 1L
                state[full] = state[full] xor (littleEndianToLong(dataQueue, off) and mask)
            }
            state[rate - 1 shr 6] = state[rate - 1 shr 6] xor (1L shl 63)
        }

        KeccakPermutation()

        KeccakExtract()
        bitsInQueue = rate

        squeezing = true
    }

    protected fun squeeze(output: ByteArray, offset: Int, outputLength: Long) {
        if (!squeezing) {
            padAndSwitchToSqueezingPhase()
        }
        if (outputLength % 8 != 0L) {
            throw IllegalStateException("outputLength not a multiple of 8")
        }

        var i: Long = 0
        while (i < outputLength) {
            if (bitsInQueue == 0) {
                KeccakPermutation()
                KeccakExtract()
                bitsInQueue = rate
            }
            val partialBlock = min(bitsInQueue.toLong(), outputLength - i).toInt()
            dataQueue.copyInto(output,
                offset + (i / 8).toInt(),(rate - bitsInQueue) / 8, (rate - bitsInQueue) / 8+ partialBlock / 8)//TODO simplify
            bitsInQueue -= partialBlock
            i += partialBlock.toLong()
        }
    }

    private fun KeccakAbsorb(data: ByteArray, _off: Int) {
        var off = _off
        val count = rate shr 6
        for (i in 0 until count) {
            state[i] = state[i] xor littleEndianToLong(data, off)
            off += 8
        }

        KeccakPermutation()
    }


    private fun KeccakExtract() {
        longToLittleEndian(state, 0, rate shr 6, dataQueue, 0)
    }

    protected fun KeccakPermutation() = keccakf(state, 24)

    companion object {
        private val ZEROED_DATAQUEUE = ByteArray(192) { 0.toByte() }

        fun keccakf(A: LongArray, nrounds: Int) {

            var a00 = A[0]
            var a01 = A[1]
            var a02 = A[2]
            var a03 = A[3]
            var a04 = A[4]
            var a05 = A[5]
            var a06 = A[6]
            var a07 = A[7]
            var a08 = A[8]
            var a09 = A[9]
            var a10 = A[10]
            var a11 = A[11]
            var a12 = A[12]
            var a13 = A[13]
            var a14 = A[14]
            var a15 = A[15]
            var a16 = A[16]
            var a17 = A[17]
            var a18 = A[18]
            var a19 = A[19]
            var a20 = A[20]
            var a21 = A[21]
            var a22 = A[22]
            var a23 = A[23]
            var a24 = A[24]

            for (i in 0 until nrounds) {
                // theta
                var c0 = a00 xor a05 xor a10 xor a15 xor a20
                var c1 = a01 xor a06 xor a11 xor a16 xor a21
                val c2 = a02 xor a07 xor a12 xor a17 xor a22
                val c3 = a03 xor a08 xor a13 xor a18 xor a23
                val c4 = a04 xor a09 xor a14 xor a19 xor a24

                val d1 = c1 shl 1 or c1.ushr(-1) xor c4
                val d2 = c2 shl 1 or c2.ushr(-1) xor c0
                val d3 = c3 shl 1 or c3.ushr(-1) xor c1
                val d4 = c4 shl 1 or c4.ushr(-1) xor c2
                val d0 = c0 shl 1 or c0.ushr(-1) xor c3

                a00 = a00 xor d1
                a05 = a05 xor d1
                a10 = a10 xor d1
                a15 = a15 xor d1
                a20 = a20 xor d1
                a01 = a01 xor d2
                a06 = a06 xor d2
                a11 = a11 xor d2
                a16 = a16 xor d2
                a21 = a21 xor d2
                a02 = a02 xor d3
                a07 = a07 xor d3
                a12 = a12 xor d3
                a17 = a17 xor d3
                a22 = a22 xor d3
                a03 = a03 xor d4
                a08 = a08 xor d4
                a13 = a13 xor d4
                a18 = a18 xor d4
                a23 = a23 xor d4
                a04 = a04 xor d0
                a09 = a09 xor d0
                a14 = a14 xor d0
                a19 = a19 xor d0
                a24 = a24 xor d0

                // rho/pi
                c1 = a01 shl 1 or a01.ushr(63)
                a01 = a06 shl 44 or a06.ushr(20)
                a06 = a09 shl 20 or a09.ushr(44)
                a09 = a22 shl 61 or a22.ushr(3)
                a22 = a14 shl 39 or a14.ushr(25)
                a14 = a20 shl 18 or a20.ushr(46)
                a20 = a02 shl 62 or a02.ushr(2)
                a02 = a12 shl 43 or a12.ushr(21)
                a12 = a13 shl 25 or a13.ushr(39)
                a13 = a19 shl 8 or a19.ushr(56)
                a19 = a23 shl 56 or a23.ushr(8)
                a23 = a15 shl 41 or a15.ushr(23)
                a15 = a04 shl 27 or a04.ushr(37)
                a04 = a24 shl 14 or a24.ushr(50)
                a24 = a21 shl 2 or a21.ushr(62)
                a21 = a08 shl 55 or a08.ushr(9)
                a08 = a16 shl 45 or a16.ushr(19)
                a16 = a05 shl 36 or a05.ushr(28)
                a05 = a03 shl 28 or a03.ushr(36)
                a03 = a18 shl 21 or a18.ushr(43)
                a18 = a17 shl 15 or a17.ushr(49)
                a17 = a11 shl 10 or a11.ushr(54)
                a11 = a07 shl 6 or a07.ushr(58)
                a07 = a10 shl 3 or a10.ushr(61)
                a10 = c1

                // chi
                c0 = a00 xor (a01.inv() and a02)
                c1 = a01 xor (a02.inv() and a03)
                a02 = a02 xor (a03.inv() and a04)
                a03 = a03 xor (a04.inv() and a00)
                a04 = a04 xor (a00.inv() and a01)
                a00 = c0
                a01 = c1

                c0 = a05 xor (a06.inv() and a07)
                c1 = a06 xor (a07.inv() and a08)
                a07 = a07 xor (a08.inv() and a09)
                a08 = a08 xor (a09.inv() and a05)
                a09 = a09 xor (a05.inv() and a06)
                a05 = c0
                a06 = c1

                c0 = a10 xor (a11.inv() and a12)
                c1 = a11 xor (a12.inv() and a13)
                a12 = a12 xor (a13.inv() and a14)
                a13 = a13 xor (a14.inv() and a10)
                a14 = a14 xor (a10.inv() and a11)
                a10 = c0
                a11 = c1

                c0 = a15 xor (a16.inv() and a17)
                c1 = a16 xor (a17.inv() and a18)
                a17 = a17 xor (a18.inv() and a19)
                a18 = a18 xor (a19.inv() and a15)
                a19 = a19 xor (a15.inv() and a16)
                a15 = c0
                a16 = c1

                c0 = a20 xor (a21.inv() and a22)
                c1 = a21 xor (a22.inv() and a23)
                a22 = a22 xor (a23.inv() and a24)
                a23 = a23 xor (a24.inv() and a20)
                a24 = a24 xor (a20.inv() and a21)
                a20 = c0
                a21 = c1

                // iota
                a00 = a00 xor KeccakRoundConstants[i]
            }

            A[0] = a00
            A[1] = a01
            A[2] = a02
            A[3] = a03
            A[4] = a04
            A[5] = a05
            A[6] = a06
            A[7] = a07
            A[8] = a08
            A[9] = a09
            A[10] = a10
            A[11] = a11
            A[12] = a12
            A[13] = a13
            A[14] = a14
            A[15] = a15
            A[16] = a16
            A[17] = a17
            A[18] = a18
            A[19] = a19
            A[20] = a20
            A[21] = a21
            A[22] = a22
            A[23] = a23
            A[24] = a24
        }

        private val KeccakRoundConstants = longArrayOf(
            0x0000000000000001L,
            0x0000000000008082L,
            -0x7fffffffffff7f76L,
            -0x7fffffff7fff8000L,
            0x000000000000808bL,
            0x0000000080000001L,
            -0x7fffffff7fff7f7fL,
            -0x7fffffffffff7ff7L,
            0x000000000000008aL,
            0x0000000000000088L,
            0x0000000080008009L,
            0x000000008000000aL,
            0x000000008000808bL,
            -0x7fffffffffffff75L,
            -0x7fffffffffff7f77L,
            -0x7fffffffffff7ffdL,
            -0x7fffffffffff7ffeL,
            -0x7fffffffffffff80L,
            0x000000000000800aL,
            -0x7fffffff7ffffff6L,
            -0x7fffffff7fff7f7fL,
            -0x7fffffffffff7f80L,
            0x0000000080000001L,
            -0x7fffffff7fff7ff8L
        )

    }
}

expect class KeccakPermutation(seed: ByteArray) {
    fun setState(s: ByteArray)
    fun next(): ByteArray
}


class KeccakPermutationImpl(seed: ByteArray) {
        private val state = LongArray(25)
        init {
            setState(seed)
        }
        fun setState(s: ByteArray) {
            require(s.size == 200)
            yyy(s).copyInto(state)
        }

        fun next(): ByteArray {
            KeccakDigest.keccakf(state, 24)
            return zzz(state.toULongArray())
        }
        fun yyy(s: ByteArray): LongArray {
            require(s.size == 200)
            val res = LongArray(25)
            for(i in 0 until 25) {
                res[i] = littleEndianToLong(s, i * 8)
            }
            return res
        }

        fun zzz(s: ULongArray): ByteArray {
            require(s.size == 25)
            val res = ByteArray(200)
            for(i in 0 until 25) {
                longToLittleEndian(s[i].toLong()).copyInto(res, i * 8)
            }
            return res
        }

    }