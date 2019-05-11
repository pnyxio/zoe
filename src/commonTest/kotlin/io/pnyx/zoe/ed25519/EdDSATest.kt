package io.pnyx.zoe.ed25519

import io.pnyx.zoe.bytes.hexDec
import kotlin.test.Test
import kotlin.test.assertTrue

class EdDSATest {

    @Test
    fun testSignVerifyKnownData() {
        val kp = EdDSA.generateKeyPairFromSeed(Seed(seed))
        assertTrue {
            pk contentEquals kp.pk.bytes
        }
        assertTrue {
            sig contentEquals EdDSA.sign(kp, msg)
        }
        assertTrue {
            EdDSA.verify(kp.pk, sig, msg)
        }
    }
}

val seed = "6b83d7da8908c3e7205b39864b56e5f3e17196a3fc9c2f5805aad0f5554c142dd0c846f97fe28585c0ee159015d64c56311c886eddcc185d296dbb165d2625d6".substring(0, 64).hexDec()
val pk = "d0c846f97fe28585c0ee159015d64c56311c886eddcc185d296dbb165d2625d6".hexDec()
val msg = "6ada80b6fa84f7034920789e8536b82d5e4678059aed27f71c".hexDec()
val sig = "16e462a29a6dd498685a3718b3eed00cc1598601ee47820486032d6b9acc9bf89f57684e08d8c0f05589cda2882a05dc4c63f9d0431d6552710812433003bc086ada80b6fa84f7034920789e8536b82d5e4678059aed27f71c".substring(0, 128).hexDec()


//internal val TEST_SEED =
//    Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")
//internal val TEST_PK =
//    Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")
//internal val TEST_MSG = "This is a secret message"
//internal val TEST_MSG_SIG =
//    Utils.hexToBytes("94825896c7075c31bcb81f06dba2bdcd9dcf16e79288d4b9f87c248215c8468d475f429f3de3b4a2cf67fe17077ae19686020364d6d4fa7a0174bab4a123ba0f")
