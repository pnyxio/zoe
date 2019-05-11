package io.pnyx.monero.rct

import io.pnyx.monero.MoneroCryptoOps
import io.pnyx.zoe.bytes.ubytes
import io.pnyx.zoe.ed25519.*
import io.pnyx.zoe.hash.keccak256
import io.pnyx.zoe.util.AutoMemory
import io.pnyx.zoe.util.autoMem

//Various key initialization functions
private val moneroCryptoOps = MoneroCryptoOps()
object Rct {
    val Z = RctKey(arrayOf(0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 ).toByteArray())
    val I = RctKey(arrayOf(0x01, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 ).toByteArray())
    val L = RctKey(arrayOf(0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10).toByteArray())
    val G = RctKey(arrayOf(0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66).toByteArray())
    val EIGHT = RctKey(arrayOf(0x08, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 ).toByteArray())
    val INV_EIGHT = RctKey(arrayOf( 0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06).toByteArray())
    inline fun zero(): RctKey = Z
    inline fun identity(): RctKey = I
    //Creates a key equal to the curve order
    inline fun curveOrder(): RctKey = L
    //copies a scalar or point
    inline fun copy(A: RctKey): RctKey = RctKey(A.bytes)

    //initializes a key matrix;
    //first parameter is rows,
    //second is columns
    fun keyMInit(rows: UInt, cols: UInt): KeyM =
        KeyM(cols.toInt()) {
            KeyV(rows.toInt()) { copy(zero()) }
        }

    //Various key generation functions

    //null if check failed
    fun AutoMemory?.toPointCheckOrder(data: FeLeUInt): P3? {
        val P = geFromFeFromBytesVartime2(data)
        if(P == null) {
            return null
        } else {
            val R = curveOrder().castEcScalar() * P
            return if(R == P) P else null
        }
    }

    //generates a random scalar which can be used as a secret key or mask
    fun skGen(): RctKey = RctKey(moneroCryptoOps.random32_unbiased().bytes)

    //Generates a vector of secret key
    //Mainly used in testing
    fun skvGen(rows: Int): KeyV {
        require(rows > 0) { "0 or less keys requested" }
        return KeyV(rows) { skGen()}
    }

    //generates a random curve point (for testing)
    fun pkGen(): RctKey {
        autoMem {
            val sk = skGen()
            val pk = sk.castEcScalar() * BPt//G
            return RctKey of pk.bytes
        }
    }

    //generates a random secret and corresponding public key
    fun skpkGen(): Pair<RctKey/*sk*/, RctKey/*pk*/> {
        autoMem {
            val sk = skGen()
            val pk = sk.castEcScalar() * BPt
            return Pair(sk, RctKey of pk.bytes)
        }
    }

    //TODO
    //generates C =aG + bH from b, a is given..
    fun genC(a: RctKey, amount: XmrAmount): RctKey {
        return addKeys2(a, d2h(amount), H);
    }
//    //generates C =aG + bH from b, a is given..
//    void genC(key & C, const key & a, xmr_amount amount) {
//        addKeys2(C, a, d2h(amount), rct::H);
//    }
//
//    //generates a <secret , public> / Pedersen commitment to the amount
//    tuple<ctkey, ctkey> ctskpkGen(xmr_amount amount) {
//        ctkey sk, pk;
//        skpkGen(sk.dest, pk.dest);
//        skpkGen(sk.mask, pk.mask);
//        key am = d2h(amount);
//        key bH = scalarmultH(am);
//        addKeys(pk.mask, pk.mask, bH);
//        return make_tuple(sk, pk);
//    }
//
//
//    //generates a <secret , public> / Pedersen commitment but takes bH as input
//    tuple<ctkey, ctkey> ctskpkGen(const key &bH) {
//        ctkey sk, pk;
//        skpkGen(sk.dest, pk.dest);
//        skpkGen(sk.mask, pk.mask);
//        addKeys(pk.mask, pk.mask, bH);
//        return make_tuple(sk, pk);
//    }
//
//    key zeroCommit(xmr_amount amount) {
//        const zero_commitment *begin = zero_commitments;
//        const zero_commitment *end = zero_commitments + sizeof(zero_commitments) / sizeof(zero_commitments[0]);
//        const zero_commitment value{amount, rct::zero()};
//        const auto it = std::lower_bound(begin, end, value, [](const zero_commitment &e0, const zero_commitment &e1){ return e0.amount < e1.amount; });
//        if (it != end && it->amount == amount)
//        {
//            return it->commitment;
//        }
//        key am = d2h(amount);
//        key bH = scalarmultH(am);
//        return addKeys(G, bH);
//    }
//
//    key commit(xmr_amount amount, const key &mask) {
//        key c;
//        genC(c, mask, amount);
//        return c;
//    }
//
//    //generates a random uint long long (for testing)
//    xmr_amount randXmrAmount(xmr_amount upperlimit) {
//        return h2d(skGen()) % (upperlimit);
//    }
//

    //Scalar multiplications of curve points

    //does a * G where a is a scalar and G is the curve basepoint
    fun scalarmultBase(a: RctKey): RctKey {
        autoMem {
            val aG = EcScalar of sc_reduce32_copy(a.ubytes).asByteArray()
            val point: P3 = aG * BPt
            return RctKey of point.bytes
        }
    }

    //does a * P where a is a scalar and P is an arbitrary point
    //IllegalArgumentException if P not a compressed point
    fun scalarmultKey(P: RctKey, a: RctKey): RctKey {
        autoMem {
            val A: P3 = parsePoint(CompressedPoint(P.bytes))//throws IllegalArgumentException
            val R: P2 = A.scalarMultiplyP2(a.castEcScalar())// * A
            val aP: RctKey = RctKey of R.bytes
            return aP
        }
    }

    //Computes 8P
    //IllegalArgumentException if P not a compressed point
    fun scalarmult8(P: RctKey): RctKey {
        autoMem {
            val p3: P3 = parsePoint(CompressedPoint(P.bytes))//TODO refactor method into RctKey
            return RctKey of p3.mul8().bytes
        }
    }

    //Computes aL where L is the curve order
    fun isInMainSubgroup(a: RctKey): Boolean {
        autoMem {
            return toPointCheckOrder(a.castFeUInt()) != null//TODO correct casting ? ignore exception ?
        }
    }

    //Curve addition / subtractions

    //for curve points: AB = A + B
    fun addKeys(A: RctKey, B: RctKey): RctKey {
        autoMem {
            val A2 = parsePoint(CompressedPoint of A.bytes)
            val B2 = parsePoint(CompressedPoint of B.bytes)
            return RctKey of (A2 + B2).bytes
        }
    }

    fun addKeys(A: KeyV): RctKey {
        autoMem {
            if (A.isEmpty()) {
                return identity()
            }
            val sum = A.map { parsePoint(CompressedPoint of it.bytes) }.reduce { acc, pt -> (acc + pt).toP3() }
            return RctKey of sum.bytes
        }
    }

    //addKeys1
    //aGB = aG + B where a is a scalar, G is the basepoint, and B is a point
    fun addKeys1(a: RctKey, B: RctKey): RctKey {
        autoMem {
            val aG = scalarmultBase(a)
            val aGB = addKeys(aG, B)
            return aGB
        }
    }

    //addKeys2
    //aGbB = aG + bB where a, b are scalars, G is the basepoint and B is a point
    fun addKeys2(a: RctKey, b: RctKey, B: RctKey): RctKey {
        autoMem {
            val B2 = parsePoint(CompressedPoint of B.bytes)
            val rv: P2 = B2.doubleScalarMultiplyVariableTime(BPt, a, b)
            val aGbB = RctKey of rv.bytes
            return aGbB
        }
    }

    //Does some precomputation to make addKeys3 more efficient
    // input B a curve point and output a ge_dsmp which has precomputation applied
    fun AutoMemory?.precomp(B: RctKey): P3/*ge_dsmp*/ {
        return parsePoint(CompressedPoint of B.bytes, true)
    }

    //addKeys3
    //aAbB = a*A + b*B where a, b are scalars, A, B are curve points
    //B must be input after applying "precomp"
    fun addKeys3(a: RctKey, A: RctKey, b: RctKey, B: P3/*ge_dsmp*/): RctKey {
        autoMem {
            val A2 = parsePoint(CompressedPoint of A.bytes, true)
            //TODO !!!! native optimize ge_double_scalarmult_precomp_vartime(&rv, a.bytes, &A2, b.bytes, B);
            val rv = B.doubleScalarMultiplyVariableTime(A2, a, b)
            val aAbB = RctKey of rv.bytes
            return aAbB
        }
    }

    //addKeys3
    //aAbB = a*A + b*B where a, b are scalars, A, B are curve points
    //A and B must be input after applying "precomp"
    fun addKeys3(a: RctKey, A: P3/*ge_dsmp*/, b: RctKey, B: P3/*ge_dsmp*/): RctKey {
        val rv = B.doubleScalarMultiplyVariableTime(A, a, b)
        val aAbB = RctKey of rv.bytes
        return aAbB
    }

    //subtract Keys (subtracts curve points)
    //AB = A - B where A, B are curve points
    fun subKeys(A: RctKey, B: RctKey): RctKey {
        autoMem {
            val A2 = parsePoint(CompressedPoint of A.bytes)
            val B2 = parsePoint(CompressedPoint of B.bytes)
            return RctKey of (A2 - B2).bytes
        }
    }

    //checks if A, B are equal in terms of bytes (may say no if one is a non-reduced scalar)
    //without doing curve operations
    fun equalKeys(a: RctKey, b: RctKey): Boolean {
        //unnecessary cast, just to introduce compilation errors if RctKey changes
        //return a as BytesWrap == b as BytesWrap
        try {
            return a.castEcScalar() == b.castEcScalar()
        } catch (e: Exception) {
            return false
        }
    }

    //Hashing - cn_fast_hash
    //be careful these are also in crypto namespace
    //cn_fast_hash for arbitrary multiples of 32 bytes
    fun cnFastHash(data: ByteArray): RctKey {
        return RctKey of keccak256(data)
    }

    fun hashToScalar(data: ByteArray): RctKey {
        val unreduced = cnFastHash(data)
        val ubuf = unreduced.ubytes
        sc_reduce32(ubuf)
        return RctKey of ubuf.asByteArray()
    }

    //cn_fast_hash for a 32 byte key
    fun cnFastHash(_in: RctKey): RctKey {
        return cnFastHash(_in.bytes)
    }

    fun hashToScalar(_in: RctKey): RctKey {
        return Rct.hashToScalar(_in.bytes)
    }

    //cn_fast_hash for a 128 byte unsigned char
    fun cnFastHash128(_in: ByteArray): RctKey {
        require(_in.size == 128)
        return cnFastHash(_in)
    }

    fun hashToScalar128(_in: ByteArray): RctKey {
        require(_in.size == 128)
        return hashToScalar(_in)
    }

    //cn_fast_hash for multisig purpose
    //This takes the outputs and commitments
    //and hashes them into a 32 byte sized key
    fun cnFastHash(PC: CtKeyV): RctKey {
        if (PC.isEmpty()) return RctKey of keccak256(ByteArray(0))
        val buf = ByteArray(64 * PC.size)
        for(i in 0 until PC.size) {
            //TODO for memory care copy CtKeyV 32 bytes fields separately
            PC[i].bytes.copyInto(buf, destinationOffset = i * 64)
        }
        return cnFastHash(buf)
    }

    fun hashToScalar(PC: CtKeyV): RctKey {
        val unreduced = cnFastHash(PC)
        val ubuf = unreduced.ubytes
        sc_reduce32(ubuf)
        return RctKey of ubuf.asByteArray()
    }

    //cn_fast_hash for a key-vector of arbitrary length
    //this is useful since you take a number of keys
    //put them in the key vector and it concatenates them
    //and then hashes them
    fun cnFastHash(keys: KeyV): RctKey {
        if (keys.isEmpty()) return RctKey of keccak256(ByteArray(0))
        val buf = ByteArray(32 * keys.size)
        for(i in 0 until keys.size) {
            //TODO for memory care copy CtKeyV 32 bytes fields separately
            keys[i].bytes.copyInto(buf, destinationOffset = i * 32)
        }
        return cnFastHash(buf)
    }

    fun hashToScalar(keys: KeyV): RctKey {
        val unreduced = cnFastHash(keys)
        val ubuf = unreduced.ubytes
        sc_reduce32(ubuf)
        return RctKey of ubuf.asByteArray()
    }

    //   key cn_fast_hash(const key64 keys)
    fun cnFastHashKey64(keys: Key64): RctKey = cnFastHash(keys)

    // key hash_to_scalar(const key64 keys)
    fun hashToScalarKey64(keys: Key64): RctKey = hashToScalar(keys)

    //throws
    fun hashToPointSimple(hh: RctKey): RctKey {
        autoMem {
            //throws
            val point = parsePoint(CompressedPoint of hh.bytes)
            return RctKey of point.mul8().bytes
        }
    }

    fun hashToPoint(hh: RctKey): RctKey {
        autoMem {
//            ge_fromfe_frombytes_vartime()
            //TODO what if not an fe ?? shoud we reduce it to fe group order ?
            val point = geFromFeFromBytesVartime2(hh.castFeUInt())
            //throws npe
            return RctKey of point!!.mul8().bytes
        }
    }

    //sums a vector of curve points (for scalars use sc_add)
    fun sumKeys(Cis: KeyV): RctKey {
        var Csum = identity()
        for (i in 0 until Cis.size) {
            Csum = Rct.addKeys(Csum, Cis[i])
        }
        return Csum
    }

    //Elliptic Curve Diffie Helman: encodes and decodes the amount b and mask a
    // where C= aG + bH
    fun ecdhEncode(unmasked: EcdhTuple, sharedSec: RctKey): EcdhTuple {
        val sharedSec1 = hashToScalar(sharedSec)
        val sharedSec2 = hashToScalar(sharedSec1)
        return EcdhTuple(
            //sc_add(unmasked.mask.bytes, unmasked.mask.bytes, sharedSec1.bytes);
            mask = RctKey of ( unmasked.mask.castEcScalar() + sharedSec1.castEcScalar() ).bytes,
            //sc_add(unmasked.amount.bytes, unmasked.amount.bytes, sharedSec2.bytes);
            amount = RctKey of ( unmasked.amount.castEcScalar() + sharedSec2.castEcScalar() ).bytes,
            senderPk = unmasked.senderPk
        )
    }

    fun ecdhDecode(masked: EcdhTuple, sharedSec: RctKey): EcdhTuple {
        val sharedSec1 = hashToScalar(sharedSec)
        val sharedSec2 = hashToScalar(sharedSec1)
        return EcdhTuple(
            //sc_sub(masked.mask.bytes, masked.mask.bytes, sharedSec1.bytes);
            mask = RctKey of ( masked.mask.castEcScalar() - sharedSec1.castEcScalar() ).bytes,
            //sc_sub(masked.amount.bytes, masked.amount.bytes, sharedSec2.bytes);
            amount = RctKey of ( masked.amount.castEcScalar() - sharedSec2.castEcScalar() ).bytes,
            senderPk = masked.senderPk
        )
    }


}



