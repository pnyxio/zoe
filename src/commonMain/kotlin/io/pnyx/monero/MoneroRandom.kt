package io.pnyx.monero

import io.pnyx.zoe.hash.KeccakPermutation
import io.pnyx.zoe.util.Rand
import io.pnyx.zoe.util.RandomGenerator


class MoneroRandom: RandomGenerator {
    override fun nextLong(): Long {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    private val HASH_DATA_AREA = 136
    private val kekkak = KeccakPermutation(Rand.get().randomBytes(32).copyOf(200))

    fun setRandomState(state: ByteArray) {
        require(state.size == 200)
        kekkak.setState(state)
    }

    override fun randomBytes(i: Int) = generate_random_bytes_thread_safe(i)

    override fun rint(roof: Int): Int {
        TODO("not implemented")
    }



    fun generate_random_bytes_not_thread_safe(size: Int): ByteArray {
        val res = ByteArray(size)
        if (size == 0) {
            return res
        }
        var n = size
        var pos = 0
        while (true) {
            val data = kekkak.next()
            //println("GENERATED ${state.hexEnc()}")
            if (n <= HASH_DATA_AREA) {
                data.copyInto(res, destinationOffset = pos, endIndex = n)
                return res
            } else {
                data.copyInto(res, destinationOffset = pos, endIndex = HASH_DATA_AREA)
                pos += HASH_DATA_AREA
                n -= HASH_DATA_AREA
            }
        }
    }

    fun generate_random_bytes_thread_safe(size: Int): ByteArray {
        //TODO https://kotlinlang.org/docs/reference/coroutines/shared-mutable-state-and-concurrency.html#mutual-exclusion
        return generate_random_bytes_not_thread_safe(size)
    }

}