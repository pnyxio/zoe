package io.pnyx.zoe.ed25519


class DiffieHellmanTest {
//
//    //@Test
//    fun test1() {
//        val G = ed25519.b
//        val (KA, kA) = CryptoOps.generate_keys()
//        val (KB, kB) = CryptoOps.generate_keys()
//        println("Alice pri:${Hex.toHexString(kA)} pub:${Hex.toHexString(KA)}")
//        println("Bob   pri:${Hex.toHexString(kB)} pub:${Hex.toHexString(KB)}")
//        // S = kA * KB = kA kB G = kB kA G = kB KA
//        //Alice computes S
//        val KB_p3 = GroupElement(Ed25519.curve, KB, true)
//        println("KB_p3i:${Hex.toHexString(KB_p3.toByteArray())}")
//        val KB_ = G.scalarMultiply(kB)
//        println("KB_:${Hex.toHexString(KB_.toByteArray())}")
//
//
//        val SA = KB_p3.scalarMultiply(kA)
//        //val SA = (kA * P3(KB, true)).toP3()
//
//        //Bob computes S
//        //val SB = (kB * P3(KA, true)).toP3()
//        val KA_p3 = GroupElement(Ed25519.curve, KA, true)
//        val SB = KA_p3.scalarMultiply(kB)
//
//        //Assert.assertEquals(SA.ge, SB.ge)
//
//        Assert.assertArrayEquals(SA.toByteArray(), SB.toByteArray())
//
//
//        Assert.assertTrue(true)
//    }
//
//    @Test
//    fun test2() {
//        val G = P3(ed25519.b)
//        val (KA, kA) = CryptoOps.generate_keys()
//        val (KB, kB) = CryptoOps.generate_keys()
//        println("Alice pri:${Hex.toHexString(kA)} pub:${Hex.toHexString(KA)}")
//        println("Bob   pri:${Hex.toHexString(kB)} pub:${Hex.toHexString(KB)}")
//        // S = kA * KB = kA kB G = kB kA G = kB KA
//        //Alice computes S
//        val SA = (kA * P3(KB, true)).toP3()//TODO why precomp needed ??
//
//        //Bob computes S
//        val SB = (kB * P3(KA, true)).toP3()
//
//        val SC = (kA * kB) * G
//        Assert.assertEquals(SA.ge, SB.ge)
////TODO        Assert.assertArrayEquals(SA.compress(), SC.compress())
//
//        //digest.update(SA.compress(), 0, 32)
//        val HSA = Keccak256(SA.compress())//digest.digest()
//        val hA = HSA.reduceToScalar()
//
//        val HSB = Keccak256(SB.compress())
//        val hB = HSA.reduceToScalar()
//        Assert.assertArrayEquals(HSA, HSB)
//        Assert.assertArrayEquals(hA, hB)
//
//        val mA = random_scalar()
//        val x = mA + hA
//        //send x to Bob
//        val mB = x - hB
//
//        Assert.assertArrayEquals(mA, mB)
//
//    }
//

}