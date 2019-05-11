package io.pnyx.zoe

import io.pnyx.monero.hash_to_scalar
import io.pnyx.zoe.bytes.Bytes
import io.pnyx.zoe.ed25519.*
import io.pnyx.zoe.ed25519.EcScalar.Companion.SC_ONE
import io.pnyx.zoe.hash.HashingAlgo
import io.pnyx.zoe.util.AutoMemory
import io.pnyx.zoe.util.Rand
import io.pnyx.zoe.util.autoMem

//https://github.com/monero-project/research-lab/blob/master/source-code/StringCT-java/src/how/monero/hodl/bulletproof/MultiBulletproof.java
//TODO vector_powers optimization bulletproofs.cc


// NOTE: this interchanges the roles of G and H to match other code's behavior
class ProofTuple(
    val V: Array<P3>,
    val A: P3,
    val S: P3,
    val T1: P3,
    val T2: P3,
    val taux: EcScalar,
    val mu: EcScalar,
    val L: Array<P3>,
    val R: Array<P3>,
    val a: EcScalar,
    val b: EcScalar,
    val t: EcScalar
)

class MultiBulletproof(
    // Test parameters: currently only works when batching proofs of the same aggregation size
    private val NEXP: Int = 6,
    private val MAXEXP: Int = 4, // the maximum number of outputs used is 2^MAXEXP
    aMem: AutoMemory?
) {
    private val N: Int = Math.pow(2.0, NEXP.toDouble()).toInt() // number of bits in amount range (so amounts are 0..2^(N-1))
    private lateinit var G: P3
    private lateinit var H: P3
    private lateinit var Gi: Array<P3>
    private lateinit var Hi: Array<P3>

    init {
        autoMem {
            // Set the curve base points
            G = BPt
            H = hashToPoint(G, this)
            val MAXM = Math.pow(2.0, MAXEXP.toDouble()).toInt()
            Gi = Array<P3>(MAXM * N) {
                getHpnGLookup(2 * it, this)
            }
            Hi = Array<P3>(MAXM * N) {
                getHpnGLookup(2 * it + 1, this)
            }
        }
    }
    /* Given two scalar arrays, construct a vector commitment */
    fun VectorExponent(a: Array<EcScalar>, b: Array<EcScalar>, aMem: AutoMemory?): P3 {
        assert(a.size == b.size)

        var Result: P3 = aMem.zeroP3()
        for (i in 0 until a.size) {
            Result = Result.add(Gi[i].scalarMultiply(a[i])).toP3()
            Result = Result.add(Hi[i].scalarMultiply(b[i])).toP3()
        }
        return Result
    }


    /* Construct an aggregate range proof */
    fun PROVE(v: Array<EcScalar>, gamma: Array<EcScalar>, logM: Int, aMem: AutoMemory?): ProofTuple {
        val M = v.size
        val logMN = logM + NEXP

        val first = H.scalarMultiply(v[0]).add(G.scalarMultiply(gamma[0])).toP3()
        // This hash is updated for Fiat-Shamir throughout the proof
        var hashCache = hash_to_scalar(first)
        val V = Array(M) {j ->
            when(j) {
                0 -> first
                else -> {
                    val ret = H.scalarMultiply(v[j]).add(G.scalarMultiply(gamma[j])).toP3()
                    hashCache = hash_to_scalar(hashCache, ret)
                    ret
                }
            }
        }

        // PAPER LINES 36-37
        //TODO
        val aL = Array<EcScalar>(M * N) { SC_ONE }
        val aR = Array<EcScalar>(M * N) { SC_ONE }

/*
        for (j in 0 until M) {
            var tempV = v[j].toBigInteger()
            for (i in N - 1 downTo 0) {
                val basePow = BigInteger.valueOf(2).pow(i)
                if (tempV.divide(basePow).equals(BigInteger.ZERO)) {
                    aL[j * N + i] = EcScalar.ZERO
                } else {
                    aL[j * N + i] = EcScalar.ONE
                    tempV = tempV.subtract(basePow)
                }

                aR[j * N + i] = aL[j * N + i].sub(EcScalar.ONE)
            }
        }
*/
        // PAPER LINES 38-39
        val alpha = randEcScalar()
        val A = VectorExponent(aL, aR, aMem).add(G.scalarMultiply(alpha)).toP3()

        // PAPER LINES 40-42
        val sL = Array<EcScalar>(M * N) {
            randEcScalar()
        }
        val sR = Array<EcScalar>(M * N) {
            randEcScalar()
        }
        val rho = randEcScalar()
        val S = VectorExponent(sL, sR, aMem).add(G.scalarMultiply(rho)).toP3()

        // PAPER LINES 43-45
        hashCache = hash_to_scalar(hashCache, A)
        hashCache = hash_to_scalar(hashCache, S)
        val y = hashCache
        hashCache = hash_to_scalar(hashCache)
        val z = hashCache

        // Polynomial construction by coefficients
        val l0: Array<EcScalar>
        val l1: Array<EcScalar>
        var r0: Array<EcScalar>
        val r1: Array<EcScalar>

        l0 = VectorSubtract(aL, VectorScalar(VectorPowers(SC_ONE, M * N), z))
        l1 = sL

        // This computes the ugly sum/concatenation from PAPER LINE 65
        val zerosTwos = Array<EcScalar>(M * N) {EcScalar.SC_ZERO}//TODO
        /* arrayOfNulls<EcScalar>(M * N)
        for (i in 0 until M * N) {
            zerosTwos[i] = EcScalar.SC_ZERO
            for (j in 1..M)
            // note this starts from 1
            {
                var temp = EcScalar.SC_ZERO
                if (i >= (j - 1) * N && i < j * N)
                    temp = EcScalar.SC_TWO.pow(i - (j - 1) * N) // exponent ranges from 0..N-1
                zerosTwos[i] = zerosTwos[i].add(z.pow(1 + j).mul(temp))
            }
        }
        */

        r0 = VectorAdd(aR, VectorScalar(VectorPowers(SC_ONE, M * N), z))
        r0 = Hadamard(r0, VectorPowers(y, M * N))
        r0 = VectorAdd(r0, zerosTwos)
        r1 = Hadamard(VectorPowers(y, M * N), sR)

        // Polynomial construction before PAPER LINE 46
        val t0 = InnerProduct(l0, r0)
        val t1 = InnerProduct(l0, r1) + InnerProduct(l1, r0)
        val t2 = InnerProduct(l1, r1)

        // PAPER LINES 47-48
        val tau1 = randEcScalar()
        val tau2 = randEcScalar()
        val T1 = H.scalarMultiply(t1).add(G.scalarMultiply(tau1)).toP3()
        val T2 = H.scalarMultiply(t2).add(G.scalarMultiply(tau2)).toP3()

        // PAPER LINES 49-51
        hashCache = hash_to_scalar(hashCache, z)
        hashCache = hash_to_scalar(hashCache, T1)
        hashCache = hash_to_scalar(hashCache, T2)
        val x = hashCache

        // PAPER LINES 52-53
        var taux = tau1 * x  + (tau2 * x.sq())
        for (j in 1..M)
        // note this starts from 1
        {
            taux += z.pow(1 + j) * (gamma[j - 1])
        }
        val mu = x * rho + alpha

        // PAPER LINES 54-57
        var l = l0
        l = VectorAdd(l, VectorScalar(l1, x))
        var r = r0
        r = VectorAdd(r, VectorScalar(r1, x))

        val t = InnerProduct(l, r)

        // PAPER LINES 32-33
        hashCache = hash_to_scalar(hashCache, x)
        hashCache = hash_to_scalar(hashCache, taux)
        hashCache = hash_to_scalar(hashCache, mu)
        hashCache = hash_to_scalar(hashCache, t)
        val x_ip = hashCache

        // These are used in the inner product rounds
        var nprime = M * N
        var Gprime = Array<P3>(M * N) { Gi[it] }
        var Hprime = Array<P3>(M * N) {
            Hi[it].scalarMultiply(Invert(y).pow(it))
        }
        var aprime = Array<EcScalar>(M * N) { l[it] }
        var bprime = Array<EcScalar>(M * N) { r[it] }

        val L = arrayOfNulls<P3>(logMN)
        val R = arrayOfNulls<P3>(logMN)
        var round = 0 // track the index based on number of rounds
        val w = arrayOfNulls<EcScalar>(logMN) // this is the challenge x in the inner product protocol

        // PAPER LINE 13
        while (nprime > 1) {
            // PAPER LINE 15
            nprime /= 2

            // PAPER LINES 16-17
            val cL = InnerProduct(ScalarSlice(aprime, 0, nprime), ScalarSlice(bprime, nprime, bprime.size))
            val cR = InnerProduct(ScalarSlice(aprime, nprime, aprime.size), ScalarSlice(bprime, 0, nprime))

            // PAPER LINES 18-19
            L[round] = VectorExponentCustom(
                CurveSlice(Gprime, nprime, Gprime.size),
                CurveSlice(Hprime, 0, nprime),
                ScalarSlice(aprime, 0, nprime),
                ScalarSlice(bprime, nprime, bprime.size),
                aMem
            ).add(H.scalarMultiply(cL * x_ip)).toP3()
            R[round] = VectorExponentCustom(
                CurveSlice(Gprime, 0, nprime),
                CurveSlice(Hprime, nprime, Hprime.size),
                ScalarSlice(aprime, nprime, aprime.size),
                ScalarSlice(bprime, 0, nprime),
                aMem
            ).add(H.scalarMultiply(cR *x_ip)).toP3()

            // PAPER LINES 21-22
            hashCache = hash_to_scalar(hashCache, L[round]!!)
            hashCache = hash_to_scalar(hashCache, R[round]!!)
            w[round] = hashCache

            // PAPER LINES 24-25
            Gprime = Hadamard2(
                VectorScalar2(CurveSlice(Gprime, 0, nprime), Invert(w[round]!!)),
                VectorScalar2(CurveSlice(Gprime, nprime, Gprime.size), w[round]!!)
            )
            Hprime = Hadamard2(
                VectorScalar2(CurveSlice(Hprime, 0, nprime), w[round]!!),
                VectorScalar2(CurveSlice(Hprime, nprime, Hprime.size), Invert(w[round]!!))
            )

            // PAPER LINES 28-29
            aprime = VectorAdd(
                VectorScalar(ScalarSlice(aprime, 0, nprime), w[round]!!),
                VectorScalar(ScalarSlice(aprime, nprime, aprime.size), Invert(w[round]!!))
            )
            bprime = VectorAdd(
                VectorScalar(ScalarSlice(bprime, 0, nprime), Invert(w[round]!!)),
                VectorScalar(ScalarSlice(bprime, nprime, bprime.size), w[round]!!)
            )

            round += 1
        }

        // PAPER LINE 58 (with inclusions from PAPER LINE 8 and PAPER LINE 20)
        val _L: Array<P3> = Array(L.size) { L[it]!! }
        val _R: Array<P3> = Array(R.size) { R[it]!! }
        return ProofTuple(V, A, S, T1, T2, taux, mu, _L, _R, aprime[0], bprime[0], t)
    }

    /* Generate a random proof with specified bit size and number of outputs */
    fun randomProof(mExp: Int, aMem: AutoMemory?): ProofTuple {
        val M = Math.pow(2.0, mExp.toDouble()).toInt()

        val rando = Rand.get()
        val amounts = Array(M) {
            var amount = -1L
            while (amount > Math.pow(2.0, N.toDouble()) - 1 || amount < 0L) {
                //TODO Java doesn't handle random long ranges very well
                amount = rando.nextLong()
            }
            EcScalar ofUInt amount.toUInt()
        }
        val masks = Array(M) {
            randEcScalar()
        }
        // Run and return the proof
        // Have to pass in lg(M) because Java is stupid about logarithms
        println("Generating proof with $M outputs...")
        return PROVE(amounts, masks, mExp, aMem)
    }

    /* Given a range proof, determine if it is valid */
    fun VERIFY(proofs: Array<ProofTuple>): Boolean {
        autoMem {
            // Figure out which proof is longest
            var maxLength = 0
            for (p in proofs.indices) {
                if (proofs[p].L.size > maxLength)
                    maxLength = proofs[p].L.size
            }
            val maxMN = Math.pow(2.0, maxLength.toDouble()).toInt()

            // Set up weighted aggregates for the first check
            var y0 = EcScalar.SC_ZERO // tau_x
            var y1 = EcScalar.SC_ZERO // t-(k+z+Sum(y^i))
            var Y2: P3 = ZERO_P3 // z-V sum
            var Y3: P3 = ZERO_P3 // xT_1
            var Y4: P3 = ZERO_P3 // x^2T_2


            // Set up weighted aggregates for the second check
            var Z0: P3 = ZERO_P3 // A + xS
            var z1 = EcScalar.SC_ZERO // mu
            var Z2: P3 = ZERO_P3 // Li/Ri sum
            var z3 = EcScalar.SC_ZERO // (t-ab)x_ip
            val z4 = Array(maxMN) {
                // g scalar sum
                EcScalar.SC_ZERO
            }
            val z5 = Array(maxMN) {
                // g scalar sum
                EcScalar.SC_ZERO
            }

            for (p in proofs.indices) {
                val proof = proofs[p]
                val logMN = proof.L.size
                val M = Math.pow(2.0, logMN.toDouble()).toInt() / N

                // For the current proof, get a random weighting factor
                // NOTE: This must not be deterministic! Only the verifier knows it
                val weight = randEcScalar()

                // Reconstruct the challenges
                var hashCache = hash_to_scalar(proof.V[0])
                for (j in 1 until M)
                    hashCache = hash_to_scalar(hashCache, proof.V[j])
                hashCache = hash_to_scalar(hashCache, proof.A)
                hashCache = hash_to_scalar(hashCache, proof.S)
                val y = hashCache
                hashCache = hash_to_scalar(hashCache)
                val z = hashCache
                hashCache = hash_to_scalar(hashCache, z)
                hashCache = hash_to_scalar(hashCache, proof.T1)
                hashCache = hash_to_scalar(hashCache, proof.T2)
                val x = hashCache
                hashCache = hash_to_scalar(hashCache, x)
                hashCache = hash_to_scalar(hashCache, proof.taux)
                hashCache = hash_to_scalar(hashCache, proof.mu)
                hashCache = hash_to_scalar(hashCache, proof.t)
                val x_ip = hashCache

                // PAPER LINE 61
                y0 = y0 + (proof.taux * weight)

                var k = EcScalar.SC_ZERO
//                .sub
//TODO sq()                (z.sq().mul(InnerProduct(VectorPowers(EcScalar.SC_ONE, M * N), VectorPowers(y, M * N))))
                for (j in 1..M)
                // note this starts from 1
                {
                    k = k
                    //TODO pow().sub(z.pow(j + 2).mul(InnerProduct(VectorPowers(EcScalar.SC_ONE, N), VectorPowers(EcScalar.SC_TWO, N))))
                }

                y1 = y1 + (
                        proof.t - (
                                k + (
                                        z * (
                                                InnerProduct(
                                                    VectorPowers(SC_ONE, M * N),
                                                    VectorPowers(y, M * N)
                                                )
                                                )
                                        )
                                ) * (weight)
                        )

                var temp: P3 = ZERO_P3
                for (j in 0 until M) {
                    //TODO pow
                    //temp = temp.add(proof.V[j].scalarMultiply(z.pow(j + 2))).toP3()
                }
                Y2 = Y2.add(temp.scalarMultiply(weight)).toP3()
                Y3 = Y3.add(proof.T1.scalarMultiply(x * (weight))).toP3()
                Y4 = Y4.add(proof.T2.scalarMultiply(x.sq() * weight)).toP3()

                // PAPER LINE 62
                Z0 = Z0.add(
                    proof.A.add(proof.S.scalarMultiply(x)).toP3()
                        .scalarMultiply(weight)
                ).toP3()

                // PAPER LINES 21-22
                // The inner product challenges are computed per round
                hashCache = hash_to_scalar(hashCache, proof.L[0])
                hashCache = hash_to_scalar(hashCache, proof.R[0])
                val w = Array(logMN) {
                    if (it == 0) {
                        hashCache
                    } else {
                        hashCache = hash_to_scalar(hashCache, proof.L[it])
                        hashCache = hash_to_scalar(hashCache, proof.R[it])
                        hashCache
                    }
                }
                // Basically PAPER LINES 24-25
                // Compute the curvepoints from G[i] and H[i]
                for (i in 0 until M * N) {
                    // Convert the index to binary IN REVERSE and construct the scalar exponent
                    var index = i
                    var gScalar: EcScalar = proof.a
                    var hScalar = proof.b * (Invert(y)/*TODO.pow(i)*/)

                    for (j in logMN - 1 downTo 0) {
                        val J = w.size - j - 1 // because this is done in reverse bit order
                        val basePow = Math.pow(2.0, j.toDouble()).toInt() //TODO!!! assumes we don't get too big
                        if (index / basePow == 0)
                        // bit is zero
                        {
                            gScalar = gScalar * (Invert(w[J]))
                            hScalar = hScalar * (w[J])
                        } else
                        // bit is one
                        {
                            gScalar = gScalar * (w[J])
                            hScalar = hScalar * (Invert(w[J]))
                            index -= basePow
                        }
                    }

                    gScalar = gScalar + z
                    hScalar =
                        hScalar.minus(z.times(y.pow(i)).plus(z.pow(2 + i / N).times(EcScalar.SC_TWO.pow(i % N))).times(Invert(y).pow(i)))

                    // Now compute the basepoint's scalar multiplication
                    z4[i] = z4[i] + (gScalar * (weight))
                    z5[i] = z5[i] + (hScalar * (weight))
                }

                // PAPER LINE 26
                z1 = z1 + (proof.mu * (weight))

                temp = ZERO_P3
                for (i in 0 until logMN) {
                    //TODO
//                temp = temp.add(proof.L[i].scalarMultiply(w[i].sq()))
//                temp = temp.add(proof.R[i].scalarMultiply(Invert(w[i]).sq()))
                }
                Z2 = Z2.add(temp.scalarMultiply(weight)).toP3()
                //TODO
                z3 = z3.plus(proof.t.minus(proof.a.times(proof.b)).times(x_ip).times(weight))

            }

            // Perform the first- and second-stage check on all proofs at once
            // NOTE: These checks could benefit from multiexp operations
            var Check1: P3 = ZERO_P3
            Check1 = Check1.add(G.scalarMultiply(y0)).toP3()
            Check1 = Check1.add(H.scalarMultiply(y1)).toP3()
            Check1 = Check1.add(Y2.scalarMultiply(EcScalar.SC_ZERO.minus(SC_ONE))).toP3()
            Check1 = Check1.add(Y3.scalarMultiply(EcScalar.SC_ZERO.minus(SC_ONE))).toP3()
            Check1 = Check1.add(Y4.scalarMultiply(EcScalar.SC_ZERO.minus(SC_ONE))).toP3()
            if (!Check1.equals(ZERO_P3)) {
                println("Failed first-stage check")
                return false
            }

            var Check2: P3 = ZERO_P3
            Check2 = Check2.add(Z0).toP3()
            Check2 = Check2.add(G.scalarMultiply(EcScalar.SC_ZERO.minus(z1))).toP3()
            Check2 = Check2.add(Z2).toP3()
            Check2 = Check2.add(H.scalarMultiply(z3)).toP3()

            for (i in 0 until maxMN) {
                Check2 = Check2.add(Gi[i].scalarMultiply(EcScalar.SC_ZERO.minus(z4[i]))).toP3()
                Check2 = Check2.add(Hi[i].scalarMultiply(EcScalar.SC_ZERO.minus(z5[i]))).toP3()
            }

            if (!Check2.equals(ZERO_P3)) {
                println("Failed second-stage check")
                return false
            }

            return true
        }
    }

    fun _main(args: Array<String>) {
        autoMem {
            // Test parameters: currently only works when batching proofs of the same aggregation size
            val PROOFS = 5 // number of proofs in batch
    
    
            // Set up all the proofs
                val rando = Rand.get()
            val proofs = Array(PROOFS) {
                // Pick a random proof length: 2^0,...,2^MAXEXP
                randomProof(rando.rint(MAXEXP + 1), this)
            }
            // Verify the batch
            println("Verifying proof batch...")
            if (VERIFY(proofs))
                println("Success!")
            else
                println("ERROR: failed verification")
            }
    }

}


val fastHash = HashingAlgo.KECCAK_256.factory.getInstance()
//fun hashToScalar(a: ByteArray): EcScalar {
//    val res = fastHash(a)
//    sc_reduce32(res.asUByteArray())
//    return EcScalar(res)
//}
fun hashToPoint(a: Bytes, aMem: AutoMemory?): P3 {
    return aMem.BasePoint().scalarMultiply(hash_to_scalar(a))
}
fun hashToPoint(a: P3, aMem: AutoMemory?): P3 {
    return hashToPoint(a, aMem)
}

//TODO not already Gi[] ????
//val HpnGLookup: MutableMap<Int, P3> = HashMap()
fun getHpnGLookup(n: Int, aMem: AutoMemory?): P3 {
    require(n >= 0)
//    if (!HpnGLookup.containsKey(n)) {
        val HpnG = hashToPoint(aMem.BasePoint().scalarMultiply(EcScalar.ofUInt(n.toUInt())), aMem)
    return HpnG
//        HpnGLookup[n] = HpnG
//    }
//    return HpnGLookup[n]!!
}



/* Compute a custom vector-scalar commitment */
fun VectorExponentCustom(
    A: Array<P3>,
    B: Array<P3>,
    a: Array<EcScalar>,
    b: Array<EcScalar>,
    aMem: AutoMemory?
): P3 {
    assert(a.size == A.size && b.size == B.size && a.size == b.size)

    var Result: P3 = aMem.zeroP3()
    for (i in a.indices) {
        Result = Result.add(A[i].scalarMultiply(a[i])).toP3()
        Result = Result.add(B[i].scalarMultiply(b[i])).toP3()
    }
    return Result
}

/* Given a scalar, construct a vector of powers */
fun VectorPowers(x: EcScalar, size: Int): Array<EcScalar> {
    val result = Array<EcScalar>(size) {
        x.pow(it)
    }
    return result
}

/* Given two scalar arrays, construct the inner product */
fun InnerProduct(a: Array<EcScalar>, b: Array<EcScalar>): EcScalar {
    assert(a.size == b.size)

    var result = EcScalar.SC_ZERO
    for (i in a.indices) {
        result = result + (a[i] * b[i])
    }
    return result
}

/* Given two scalar arrays, construct the Hadamard product */
fun Hadamard(a: Array<EcScalar>, b: Array<EcScalar>): Array<EcScalar> {
    assert(a.size == b.size)

    val result = Array<EcScalar>(a.size) {
        a[it] * b[it]
    }
    return result
}

/* Given two curvepoint arrays, construct the Hadamard product */
fun Hadamard2(A: Array<P3>, B: Array<P3>): Array<P3> {
    assert(A.size == B.size)

    val Result = Array<P3>(A.size) {
        A[it].add(B[it]).toP3()
    }
    return Result
}

/* Add two vectors */
fun VectorAdd(a: Array<EcScalar>, b: Array<EcScalar>): Array<EcScalar> {
    assert(a.size == b.size)

    val result = Array<EcScalar>(a.size) {
        a[it] + b[it]
    }
    return result
}

/* Subtract two vectors */
fun VectorSubtract(a: Array<EcScalar>, b: Array<EcScalar>): Array<EcScalar> {
    assert(a.size == b.size)

    val result = Array<EcScalar>(a.size) {
        a[it] - b[it]
    }
    return result
}

/* Multiply a scalar and a vector */
fun VectorScalar(a: Array<EcScalar>, x: EcScalar): Array<EcScalar> {
    val result = Array<EcScalar>(a.size) {
        a[it] * x
    }
    return result
}

/* Exponentiate a curve vector by a scalar */
fun VectorScalar2(A: Array<P3>, x: EcScalar): Array<P3> {
    val Result = Array<P3>(A.size) {
        x * A[it]
    }
    return Result
}

/* Compute the inverse of a scalar, the stupid way */
fun Invert(x: EcScalar): EcScalar {//TODO
//        val inverse = EcScalar(x.toBigInteger().modInverse(CryptoUtil.l))
//
//        assert(x.mul(inverse).equals(EcScalar.ONE))
//        return inverse
    return EcScalar(ByteArray(32))
}

/* Compute the slice of a curvepoint vector */
fun CurveSlice(a: Array<P3>, start: Int, stop: Int): Array<P3> {
    val Result = Array<P3>(stop - start) {
        a[it + start]
    }
    return Result
}

/* Compute the slice of a scalar vector */
fun ScalarSlice(a: Array<EcScalar>, start: Int, stop: Int): Array<EcScalar> {
    val result = Array<EcScalar>(stop - start) {
        a[it + start]
    }
    return result
}
