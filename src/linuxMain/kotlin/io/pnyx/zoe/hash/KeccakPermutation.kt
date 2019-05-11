package io.pnyx.zoe.hash

import io.pnyx.ed25519monero.keccakf
import kotlinx.cinterop.ULongVar
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.refTo
import kotlinx.cinterop.reinterpret



//actual typealias KeccakPermutation = KeccakPermutationImpl

actual class KeccakPermutation actual constructor(seed: ByteArray) {
    private val state = ByteArray(200)
    init {
        setState(seed)
    }
    actual fun setState(s: ByteArray) {
        require(s.size == 200)
        s.copyInto(state)
    }

    actual fun next(): ByteArray {
        memScoped {
            val k = state.refTo(0).getPointer(this).reinterpret<ULongVar>()
            keccakf(k, 24)
            return state.copyOf()
        }
    }

}
