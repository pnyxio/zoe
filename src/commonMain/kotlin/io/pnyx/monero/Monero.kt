package io.pnyx.monero

import io.pnyx.zoe.bytes.*
import io.pnyx.zoe.ed25519.*
import io.pnyx.zoe.hash.HashingAlgo
import io.pnyx.zoe.util.AutoMemory
import io.pnyx.zoe.util.autoMem

internal typealias KeyPair = Pair<SecretKey,PublicKey>

private val fast_hash get() = HashingAlgo.KECCAK_256.factory.getInstance()
typealias KeyDerivation = CompressedPoint

class Signature(
    val c: EcScalar,
    val r: EcScalar
): ComparableBytes() {
    override val bytes: ByteArray get() {
        val res = c.bytes.copyOf(64)
        r.bytes.copyInto(res, 32)
        return res
    }
    companion object {
        infix fun of(sig: ByteArray): Signature =
            Signature(EcScalar of sig.copyOfRange(0, 32), EcScalar of sig.copyOfRange(32, 64))
    }
}

typealias KeyImage = CompressedPoint


private fun less32(k0: UByteArray, k1: UByteArray): Boolean {
    for (n in 31 downTo 0)  {
        if (k0[n] < k1[n])
            return true
        if (k0[n] > k1[n])
            return false
    }
    return false
}

// l = 2^252 + 27742317777372353535851937790883648493.
// it fits 15 in 32 bytes
internal fun hash_to_scalar(vararg data: Bytes): EcScalar {
    val res = fast_hash(*data)
    sc_reduce32(res.asUByteArray())
    return EcScalar(res)
}

private fun KeyDerivation.toScalar(output_index: UInt): EcScalar {
    val res = fast_hash(this, CryptonoteVarInt.encode(output_index).toBytes())
    sc_reduce32(res.asUByteArray())
    return EcScalar(res)
}

internal fun check_key(pk: PublicKey): Boolean {
    try {
        autoMem {
            p3(pk)
        }
    } catch(e: Exception) {
        return false
    }
    return true
}

internal fun secret_key_to_public_key(sk: SecretKey): PublicKey =
    autoMem { BPt.scalarMultiply(sk).compress() }

class MoneroCryptoOps {
    val moneroRandom = MoneroRandom()

    private val random32_unbiased_limit = ubyteArrayOf( 0xe3.toUByte(), 0x6a.toUByte(), 0x67.toUByte(), 0x72.toUByte(), 0x8b.toUByte(), 0xce.toUByte(), 0x13.toUByte(), 0x29.toUByte(), 0x8f.toUByte(), 0x30.toUByte(), 0x82.toUByte(), 0x8c.toUByte(), 0x0b.toUByte(), 0xa4.toUByte(), 0x10.toUByte(), 0x39.toUByte(), 0x01.toUByte(), 0x00.toUByte(), 0x00.toUByte(), 0x00.toUByte(), 0x00.toUByte(), 0x00.toUByte(), 0x00.toUByte(), 0x00.toUByte(), 0x00.toUByte(), 0x00.toUByte(), 0x00.toUByte(), 0x00.toUByte(), 0x00.toUByte(), 0x00.toUByte(), 0x00.toUByte(), 0xf0.toUByte() )
    fun random32_unbiased(): EcScalar {
        var res: UByteArray
        do
        {
            res = moneroRandom.generate_random_bytes_thread_safe(32).asUByteArray()// Rand.get().randomBytes(32).asUByteArray()
        } while (sc_iszero(res) && !less32(res, random32_unbiased_limit)) // should be good about 15/16 of the time
        sc_reduce32(res)
        return EcScalar(res.asByteArray())
    }

    fun randomScalar(): EcScalar = random32_unbiased()

    fun generate_keys(recoveryKey: SecretKey? = null, recover: Boolean): KeyPair {
        autoMem {
            val sec = if (recover) recoveryKey!! else randomScalar()
            sc_reduce32(sec.bytes.asUByteArray())
            return KeyPair(sec, (sec * BPt).compress())
        }
    }

    fun generate_key_derivation(publicKey: PublicKey, secretKey: SecretKey): KeyDerivation =
        autoMem {
            (secretKey * p3(publicKey, true)).mul8().compress()
        }

    fun derive_public_key(derivation: KeyDerivation, output_index: UInt, base: PublicKey): PublicKey =
        autoMem {
            (p3(base) + (derivation.toScalar(output_index) * BPt)).compress()
        }

    fun derive_secret_key(derivation: KeyDerivation, output_index: UInt, base: SecretKey): SecretKey {
        return base + derivation.toScalar(output_index)
    }

    fun derive_subaddress_public_key(out_key: PublicKey, derivation: KeyDerivation, output_index: UInt): PublicKey {
        autoMem {
            return (p3(out_key) - derivation.toScalar(output_index) * BPt).compress()
        }
    }

    fun generate_signature(prefix_hash: Bytes, pub: PublicKey, sec: SecretKey): Signature {
        autoMem {
            while (true) {
                val k = randomScalar()
                if (k.bytes[0] == 0.toByte()) {//not too small
                    continue
                }
                val tmp3 = k * BPt
                val c = hash_to_scalar(prefix_hash, pub, tmp3.compress())
//                sc_reduce32(fh.asUByteArray())
//                val c = EcScalar of fh
////                    EdGroup.reduce(
////                    UInt512 of
////                            fast_hash(prefix_hash, pub.bytes, tmp3.compress().bytes).copyOf(64)
////                )
                if (sc_iszero(c.bytes.asUByteArray())) {
                    continue
                }
                val r = scalarMulSub(c, sec, k)
                if (sc_iszero(r.bytes.asUByteArray())) {
                    continue
                }
                return Signature(c, r)
            }
            @Suppress("UNREACHABLE_CODE")
            throw IllegalStateException("unreachable code")
        }
    }

    fun check_signature(prefix_hash: Bytes, pub: PublicKey, sig: ByteArray): Boolean {
        try {
            autoMem {
                //unneded require(check_key(pub))
                require(sig.size == 64)
                val _c = EcScalar of sig.copyOfRange(0, 32)
                val _r = EcScalar of sig.copyOfRange(32, 64)
                if (sc_iszero(_c.ubytes)) {
                    return false
                }
                val tmp2 = BPt.doubleScalarMultiplyVariableTime(p3(pub), _c, _r).compress()
                if (CompressedPoint.equals(
                        tmp2,
                        CompressedPoint.infinity
                    )
                ) {
                    return false
                }
                val c = hash_to_scalar(prefix_hash, pub, tmp2)

                return sc_iszero(c - _c)

            }
        } catch (e: Exception) {
            return false
        }
    }
    //TODO ?? extension fun Scalar isZero
    private fun sc_iszero(s: EcScalar) = !sc_isnonzero(s.bytes.asUByteArray())

    fun generate_tx_proof(prefix_hash: LeUInt32, pkR: PublicKey, pkA: PublicKey, pkB: PublicKey?, pkD: PublicKey, r: SecretKey): Signature {
        autoMem {

            /*val R = validation*/ p3(pkR)//TODO sure ? why unused parameter ?
            val A = p3(pkA)
            val B = if (pkB != null) p3(pkB) else null
            val D = p3(pkD)
            // pick random k
            val k = randomScalar()
            val X = if (B != null) k * B else k * BPt
            val Y = k * A
            // sig.c = Hs(Msg || D || X || Y)
            val sig_c = hash_to_scalar(
                prefix_hash,
                D.compress()/*aka pkD but just for being sure it is validated*/,
                X.compress(),
                Y.compress()
            )
            // sig.r = k - sig.c*r
            val sig_r =
                sc_mulsub(
                    sig_c.bytes.asUByteArray(),
                    r.bytes.asUByteArray(),
                    k.bytes.asUByteArray()
                ).asByteArray()
            return Signature(sig_c, EcScalar(sig_r))
        }
    }


    fun check_tx_proof(prefix_hash: LeUInt32, pkR: PublicKey, pkA: PublicKey, pkB: PublicKey?, pkD: PublicKey, sig: Signature): Boolean {
        autoMem {
            val R = p3(pkR)
            val A = p3(pkA)
            val B = if (pkB != null) p3(pkB) else null
            val D = p3(pkD)

            // compute sig.c*R
            //TODO unneded ? val cR_p3 = sig.c * R
            //val X: P1P1 = if(B != null) sig.c * R + sig.r * B else sig.c * R + sig.r * BPt
            val X = if (B != null) B.doubleScalarMultiplyVariableTime(
                R,
                sig.c,
                sig.r
            ) else BPt.doubleScalarMultiplyVariableTime(R, sig.c, sig.r)
            // compute sig.c*D
            //TODO unneded ? val cD = sig.c * D

            // compute sig.r*A
            //TODO unneded ? val rA = sig.r * A

            // compute Y = sig.c*D + sig.r*A
            //val Y: P1P1 = sig.c*D + sig.r*A
            val Y = D.doubleScalarMultiplyVariableTime(A, sig.r, sig.c)

            // compute c2 = Hs(Msg || D || X || Y)
            val c2 = hash_to_scalar(
                prefix_hash,
                D.compress(),
                X.compress(),
                Y.compress()
            );

            // test if c2 == sig.c
            return sc_iszero(c2 - sig.c)
        }
    }

    /*TODO check impl
  static void hash_to_ec(const public_key &key, ge_p3 &res) {
    hash h;
    ge_p2 point;
    ge_p1p1 point2;
    cn_fast_hash(std::addressof(key), sizeof(public_key), h);
    ge_fromfe_frombytes_vartime(&point, reinterpret_cast<const unsigned char *>(&h));
    ge_mul8(&point2, &point);
    ge_p1p1_to_p3(&res, &point2);
  }

  void crypto_ops::generate_key_image(const public_key &pub, const secret_key &sec, key_image &image) {
    ge_p3 point;
    ge_p2 point2;
    assert(sc_check(&sec) == 0);
    hash_to_ec(pub, point);
    ge_scalarmult(&point2, &unwrap(sec), &point);
    ge_tobytes(&image, &point2);
  }


*/
    fun hash_to_ec(key: PublicKey, aMem: AutoMemory?): P1P1 {
        val hash = fast_hash(key)
        val point = aMem.ge_fromfe_frombytes_vartime(hash.asFeUInt())//throws
        return point.mul8()
    }

    fun generate_key_image(pub: PublicKey, sec: SecretKey): KeyImage {
        autoMem {
            val point = hash_to_ec(pub, this)
            return (sec * point.toP3()).compress()
        }
    }

//TODO    void crypto_ops::generate_ring_signature(const hash &prefix_hash, const key_image &image,
//    const public_key *const *pubs, size_t pubs_count,
//    const secret_key &sec, size_t sec_index,
//    signature *sig) {
//        size_t i;
//        ge_p3 image_unp;
//        ge_dsmp image_pre;
//        ec_scalar sum, k, h;
//        boost::shared_ptr<rs_comm> buf(reinterpret_cast<rs_comm *>(malloc(rs_comm_size(pubs_count))), free);
//        if (!buf)
//            local_abort("malloc failure");
//        assert(sec_index < pubs_count);
//        #if !defined(NDEBUG)
//        {
//            ge_p3 t;
//            public_key t2;
//            key_image t3;
//            assert(sc_check(&sec) == 0);
//            ge_scalarmult_base(&t, &sec);
//            ge_p3_tobytes(&t2, &t);
//            assert(*pubs[sec_index] == t2);
//            generate_key_image(*pubs[sec_index], sec, t3);
//            assert(image == t3);
//            for (i = 0; i < pubs_count; i++) {
//            assert(check_key(*pubs[i]));
//        }
//        }
//        #endif
//        if (ge_frombytes_vartime(&image_unp, &image) != 0) {
//            local_abort("invalid key image");
//        }
//        ge_dsm_precomp(image_pre, &image_unp);
//        sc_0(&sum);
//        buf->h = prefix_hash;
//        for (i = 0; i < pubs_count; i++) {
//            ge_p2 tmp2;
//            ge_p3 tmp3;
//            if (i == sec_index) {
//                random_scalar(k);
//                ge_scalarmult_base(&tmp3, &k);
//                ge_p3_tobytes(&buf->ab[i].a, &tmp3);
//                hash_to_ec(*pubs[i], tmp3);
//                ge_scalarmult(&tmp2, &k, &tmp3);
//                ge_tobytes(&buf->ab[i].b, &tmp2);
//            } else {
//                random_scalar(sig[i].c);
//                random_scalar(sig[i].r);
//                if (ge_frombytes_vartime(&tmp3, &*pubs[i]) != 0) {
//                    local_abort("invalid pubkey");
//                }
//                ge_double_scalarmult_base_vartime(&tmp2, &sig[i].c, &tmp3, &sig[i].r);
//                ge_tobytes(&buf->ab[i].a, &tmp2);
//                hash_to_ec(*pubs[i], tmp3);
//                ge_double_scalarmult_precomp_vartime(&tmp2, &sig[i].r, &tmp3, &sig[i].c, image_pre);
//                ge_tobytes(&buf->ab[i].b, &tmp2);
//                sc_add(&sum, &sum, &sig[i].c);
//            }
//        }
//        hash_to_scalar(buf.get(), rs_comm_size(pubs_count), h);
//        sc_sub(&sig[sec_index].c, &h, &sum);
//        sc_mulsub(&sig[sec_index].r, &sig[sec_index].c, &unwrap(sec), &k);
//    }


    fun generate_ring_signature(prefix_hash: LeUInt32, image: KeyImage, pubs: Array<PublicKey>, sec: SecretKey, sec_index: Int): Array<Signature> {
        autoMem {
            val sigs = ArrayList<Signature>(pubs.size)
            require(sec_index < pubs.size)
            val image_unp = p3(image)
            var sum = EcScalar(ByteArray(32))
            sc_0(sum.bytes.asUByteArray())
            var k: EcScalar? = null
            val ab = ArrayList<Bytes>(pubs.size)
            for (i in 0 until pubs.size) {
                if (i == sec_index) {
                    val abi = ByteArray(64)
                    k = randomScalar()
                    var tmp3 = k * BPt
                    tmp3.compress().bytes.copyInto(abi, destinationOffset = 0)//ab[i].a
                    tmp3 = hash_to_ec(pubs[i], this).toP3()//TODO
                    val tmp2 = tmp3.scalarMultiply(k)
                    tmp2.compress().bytes.copyInto(abi, destinationOffset = 32)//ab[i].b
                    ab[i] = abi.toBytes()
                } else {
                    val abi = ByteArray(64)
                    val sig =
                        Signature(randomScalar(), randomScalar())
                    sigs[i] = sig
                    var tmp3 = p3(pubs[i])
                    var tmp2 = BPt.doubleScalarMultiplyVariableTime(tmp3, sig.c, sig.r)
                    tmp2.compress().bytes.copyInto(abi, destinationOffset = 0)//ab[i].a

                    tmp3 = hash_to_ec(pubs[i], this).toP3(true)
                    tmp2 = tmp3.doubleScalarMultiplyVariableTime(image_unp, sig.r, sig.c)
                    tmp2.compress().bytes.copyInto(abi, destinationOffset = 32)//ab[i].b

                    sum += sig.c
                    ab[i] = abi.toBytes()
                }
            }
            val h = hash_to_scalar(prefix_hash, *ab.toTypedArray())

            val c = h - sum
            val r = EcScalar(
                sc_mulsub(
                    c.bytes.asUByteArray(),
                    sec.bytes.asUByteArray(),
                    k!!.bytes.asUByteArray()
                ).asByteArray()
            )
            sigs[sec_index] = Signature(c, r)
            return sigs.toTypedArray()
        }
    }

//TODO REDO    bool crypto_ops::check_ring_signature(const hash &prefix_hash, const key_image &image,
//    const public_key *const *pubs, size_t pubs_count,
//    const signature *sig) {
//        size_t i;
//        ge_p3 image_unp;
//        ge_dsmp image_pre;
//        ec_scalar sum, h;
//        boost::shared_ptr<rs_comm> buf(reinterpret_cast<rs_comm *>(malloc(rs_comm_size(pubs_count))), free);
//        if (!buf)
//            return false;
//        #if !defined(NDEBUG)
//        for (i = 0; i < pubs_count; i++) {
//            assert(check_key(*pubs[i]));
//        }
//        #endif
//        if (ge_frombytes_vartime(&image_unp, &image) != 0) {
//            return false;
//        }
//        ge_dsm_precomp(image_pre, &image_unp);
//        sc_0(&sum);
//        buf->h = prefix_hash;
//        for (i = 0; i < pubs_count; i++) {
//            ge_p2 tmp2;
//            ge_p3 tmp3;
//            if (sc_check(&sig[i].c) != 0 || sc_check(&sig[i].r) != 0) {
//            return false;
//        }
//            if (ge_frombytes_vartime(&tmp3, &*pubs[i]) != 0) {
//            return false;
//        }
//            ge_double_scalarmult_base_vartime(&tmp2, &sig[i].c, &tmp3, &sig[i].r);
//            ge_tobytes(&buf->ab[i].a, &tmp2);
//            hash_to_ec(*pubs[i], tmp3);
//            ge_double_scalarmult_precomp_vartime(&tmp2, &sig[i].r, &tmp3, &sig[i].c, image_pre);
//            ge_tobytes(&buf->ab[i].b, &tmp2);
//            sc_add(&sum, &sum, &sig[i].c);
//        }
//        hash_to_scalar(buf.get(), rs_comm_size(pubs_count), h);
//        sc_sub(&h, &h, &sum);
//        return sc_isnonzero(&h) == 0;
//    }

    fun check_ring_signature(prefix_hash: LeUInt32, image: KeyImage, pubs: Array<PublicKey>, sigs: Array<Signature>): Boolean {
        autoMem {
            val image_unp = p3(image)
            var sum = EcScalar(ByteArray(32))
            sc_0(sum.bytes.asUByteArray())
            val ab: MutableList<Bytes> = ArrayList(pubs.size)

            for (i in 0 until pubs.size) {
                val abi = ByteArray(64)
                var tmp3 = p3(pubs[i])
                var tmp2 = BPt.doubleScalarMultiplyVariableTime(tmp3, sigs[i].c, sigs[i].r)
                tmp2.compress().bytes.copyInto(abi, destinationOffset = 0)//ab[i].a
                tmp3 = hash_to_ec(pubs[i], this).toP3(true)
                tmp2 = tmp3.doubleScalarMultiplyVariableTime(image_unp, sigs[i].r, sigs[i].c)
                tmp2.compress().bytes.copyInto(abi, destinationOffset = 32)//ab[i].b
                sum += sigs[i].c
                ab.add(abi.toBytes())

            }
            val h = hash_to_scalar(prefix_hash, *ab.toTypedArray())
            return sc_iszero(h - sum)
        }
    }

}




