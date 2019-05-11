package io.pnyx.zoe.ed25519

/*
void sc_0(unsigned char *);
void sc_reduce32(unsigned char *);
void sc_add(unsigned char *, const unsigned char *, const unsigned char *);
void sc_sub(unsigned char *, const unsigned char *, const unsigned char *);
void sc_mulsub(unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *);
void sc_mul(unsigned char *, const unsigned char *, const unsigned char *);
void sc_muladd(unsigned char *s, const unsigned char *a, const unsigned char *b, const unsigned char *c);
int sc_check(const unsigned char *);
int sc_isnonzero(const unsigned char *); /* Doesn't normalize */

// internal
uint64_t load_3(const unsigned char *in);
uint64_t load_4(const unsigned char *in);
*/

internal fun load_3(buf: UByteArray, start: Int = 0): Long =
    buf[0 + start].toLong() or
    (buf[1 + start].toLong() shl 8) or
    (buf[2 + start].toLong() shl 16)

internal fun load_4(buf: UByteArray, start: Int = 0): Long =
    buf[0 + start].toLong() or
    (buf[1 + start].toLong() shl 8) or
    (buf[2 + start].toLong() shl 16) or
    (buf[3 + start].toLong() shl 24)

//internal fun load_33(buf: UByteArray, start: Int = 0): ULong =
//    buf[0 + start].toULong() or (buf[1 + start].toULong() shl 8) or (buf[2 + start].toULong() shl 16)
//
//internal fun load_44(buf: UByteArray, start: Int = 0): ULong =
//    buf[0 + start].toULong() or (buf[1 + start].toULong() shl 8) or (buf[2 + start].toULong() shl 16) or (buf[3 + start].toULong() shl 24)


//internal fun load_3(`in`: UByteArray, offset: Int = 0): Long {
//    var offset1 = offset
//    var result = `in`[offset1++].toInt() and 0xff
//    result = result or (`in`[offset1++].toInt() and 0xff shl 8)
//    result = result or (`in`[offset1].toInt() and 0xff shl 16)
//    return result.toLong()
//}
//
//internal fun load_4(`in`: UByteArray, offset: Int = 0): Long {
//    var offset1 = offset
//    var result = `in`[offset1++].toInt() and 0xff
//    result = result or (`in`[offset1++].toInt() and 0xff shl 8)
//    result = result or (`in`[offset1++].toInt() and 0xff shl 16)
//    result = result or (`in`[offset1].toInt() shl 24)
//    return result.toLong() and 0xffffffffL
//}




fun sc_0(buf: UByteArray) {
    for (i in 0 until 32) {
        buf[i] = 0u
    }
}

//rewrites buf in place
fun sc_reduce32(buf: UByteArray) {
    require(buf.size == 32) { "sc_reduce32 buf.size == ${buf.size}" }
    var s0: Long = 2097151L and load_3(buf)
    var s1: Long = 2097151L and (load_4(buf, 2) shr 5)
    var s2: Long = 2097151L and (load_3(buf, 5) shr 2)
    var s3: Long = 2097151L and (load_4(buf, 7) shr 7)
    var s4: Long = 2097151L and (load_4(buf, 10) shr 4)
    var s5: Long = 2097151L and (load_3(buf, 13) shr 1)
    var s6: Long = 2097151L and (load_4(buf, 15) shr 6)
    var s7: Long = 2097151L and (load_3(buf, 18) shr 3)
    var s8: Long = 2097151L and load_3(buf, 21)
    var s9: Long = 2097151L and (load_4(buf, 23) shr 5)
    var s10: Long = 2097151L and (load_3(buf, 26) shr 2)
    var s11: Long = (load_4(buf, 28) shr 7)
    var s12: Long = 0L
    var carry0: Long
    var carry1: Long
    var carry2: Long
    var carry3: Long
    var carry4: Long
    var carry5: Long
    var carry6: Long
    var carry7: Long
    var carry8: Long
    var carry9: Long
    var carry10: Long
    var carry11: Long

    carry0 = (s0 + (1 shl 20)) shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry2 = (s2 + (1 shl 20)) shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry4 = (s4 + (1 shl 20)) shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry6 = (s6 + (1 shl 20)) shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry8 = (s8 + (1 shl 20)) shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry10 = (s10 + (1 shl 20)) shr 21; s11 += carry10; s10 -= carry10  shl  21;

    carry1 = (s1 + (1 shl 20)) shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry3 = (s3 + (1 shl 20)) shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry5 = (s5 + (1 shl 20)) shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry7 = (s7 + (1 shl 20)) shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry9 = (s9 + (1 shl 20)) shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry11 = (s11 + (1 shl 20)) shr 21; s12 += carry11; s11 -= carry11  shl  21;

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901
    s12 = 0

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10  shl  21;
    carry11 = s11 shr 21; s12 += carry11; s11 -= carry11  shl  21;

    s0 += s12 * 666643L
    s1 += s12 * 470296L
    s2 += s12 * 654183L
    s3 -= s12 * 997805L
    s4 += s12 * 136657L
    s5 -= s12 * 683901L

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10  shl  21;

    buf[0] = (s0 shr 0).toUByte()
    buf[1] = (s0 shr 8).toUByte()
    buf[2] = ((s0 shr 16) or (s1  shl  5)).toUByte()
    buf[3] = (s1 shr 3).toUByte()
    buf[4] = (s1 shr 11).toUByte()
    buf[5] = ((s1 shr 19) or (s2  shl  2)).toUByte()
    buf[6] = (s2 shr 6).toUByte()
    buf[7] = ((s2 shr 14) or (s3  shl  7)).toUByte()
    buf[8] = (s3 shr 1).toUByte()
    buf[9] = (s3 shr 9).toUByte()
    buf[10] = ((s3 shr 17) or (s4  shl  4)).toUByte()
    buf[11] = (s4 shr 4).toUByte()
    buf[12] = (s4 shr 12).toUByte()
    buf[13] = ((s4 shr 20) or (s5  shl  1)).toUByte()
    buf[14] = (s5 shr 7).toUByte()
    buf[15] = ((s5 shr 15) or (s6  shl  6)).toUByte()
    buf[16] = (s6 shr 2).toUByte()
    buf[17] = (s6 shr 10).toUByte()
    buf[18] = ((s6 shr 18) or (s7  shl  3)).toUByte()
    buf[19] = (s7 shr 5).toUByte()
    buf[20] = (s7 shr 13).toUByte()
    buf[21] = (s8 shr 0).toUByte()
    buf[22] = (s8 shr 8).toUByte()
    buf[23] = ((s8 shr 16) or (s9  shl  5)).toUByte()
    buf[24] = (s9 shr 3).toUByte()
    buf[25] = (s9 shr 11).toUByte()
    buf[26] = ((s9 shr 19) or (s10  shl  2)).toUByte()
    buf[27] = (s10 shr 6).toUByte()
    buf[28] = ((s10 shr 14) or (s11  shl  7)).toUByte()
    buf[29] = (s11 shr 1).toUByte()
    buf[30] = (s11 shr 9).toUByte()
    buf[31] = (s11 shr 17).toUByte()
}

fun sc_reduce32_copy(buf: UByteArray): UByteArray {
    require(buf.size == 32) { "sc_reduce32 buf.size == ${buf.size}" }
    var s0: Long = 2097151L and load_3(buf)
    var s1: Long = 2097151L and (load_4(buf, 2) shr 5)
    var s2: Long = 2097151L and (load_3(buf, 5) shr 2)
    var s3: Long = 2097151L and (load_4(buf, 7) shr 7)
    var s4: Long = 2097151L and (load_4(buf, 10) shr 4)
    var s5: Long = 2097151L and (load_3(buf, 13) shr 1)
    var s6: Long = 2097151L and (load_4(buf, 15) shr 6)
    var s7: Long = 2097151L and (load_3(buf, 18) shr 3)
    var s8: Long = 2097151L and load_3(buf, 21)
    var s9: Long = 2097151L and (load_4(buf, 23) shr 5)
    var s10: Long = 2097151L and (load_3(buf, 26) shr 2)
    var s11: Long = (load_4(buf, 28) shr 7)
    var s12: Long = 0L
    var carry0: Long
    var carry1: Long
    var carry2: Long
    var carry3: Long
    var carry4: Long
    var carry5: Long
    var carry6: Long
    var carry7: Long
    var carry8: Long
    var carry9: Long
    var carry10: Long
    var carry11: Long

    carry0 = (s0 + (1 shl 20)) shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry2 = (s2 + (1 shl 20)) shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry4 = (s4 + (1 shl 20)) shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry6 = (s6 + (1 shl 20)) shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry8 = (s8 + (1 shl 20)) shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry10 = (s10 + (1 shl 20)) shr 21; s11 += carry10; s10 -= carry10  shl  21;

    carry1 = (s1 + (1 shl 20)) shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry3 = (s3 + (1 shl 20)) shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry5 = (s5 + (1 shl 20)) shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry7 = (s7 + (1 shl 20)) shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry9 = (s9 + (1 shl 20)) shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry11 = (s11 + (1 shl 20)) shr 21; s12 += carry11; s11 -= carry11  shl  21;

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901
    s12 = 0

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10  shl  21;
    carry11 = s11 shr 21; s12 += carry11; s11 -= carry11  shl  21;

    s0 += s12 * 666643L
    s1 += s12 * 470296L
    s2 += s12 * 654183L
    s3 -= s12 * 997805L
    s4 += s12 * 136657L
    s5 -= s12 * 683901L

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10  shl  21;

    val copy = UByteArray(32)
    copy[0] = (s0 shr 0).toUByte()
    copy[1] = (s0 shr 8).toUByte()
    copy[2] = ((s0 shr 16) or (s1  shl  5)).toUByte()
    copy[3] = (s1 shr 3).toUByte()
    copy[4] = (s1 shr 11).toUByte()
    copy[5] = ((s1 shr 19) or (s2  shl  2)).toUByte()
    copy[6] = (s2 shr 6).toUByte()
    copy[7] = ((s2 shr 14) or (s3  shl  7)).toUByte()
    copy[8] = (s3 shr 1).toUByte()
    copy[9] = (s3 shr 9).toUByte()
    copy[10] = ((s3 shr 17) or (s4  shl  4)).toUByte()
    copy[11] = (s4 shr 4).toUByte()
    copy[12] = (s4 shr 12).toUByte()
    copy[13] = ((s4 shr 20) or (s5  shl  1)).toUByte()
    copy[14] = (s5 shr 7).toUByte()
    copy[15] = ((s5 shr 15) or (s6  shl  6)).toUByte()
    copy[16] = (s6 shr 2).toUByte()
    copy[17] = (s6 shr 10).toUByte()
    copy[18] = ((s6 shr 18) or (s7  shl  3)).toUByte()
    copy[19] = (s7 shr 5).toUByte()
    copy[20] = (s7 shr 13).toUByte()
    copy[21] = (s8 shr 0).toUByte()
    copy[22] = (s8 shr 8).toUByte()
    copy[23] = ((s8 shr 16) or (s9  shl  5)).toUByte()
    copy[24] = (s9 shr 3).toUByte()
    copy[25] = (s9 shr 11).toUByte()
    copy[26] = ((s9 shr 19) or (s10  shl  2)).toUByte()
    copy[27] = (s10 shr 6).toUByte()
    copy[28] = ((s10 shr 14) or (s11  shl  7)).toUByte()
    copy[29] = (s11 shr 1).toUByte()
    copy[30] = (s11 shr 9).toUByte()
    copy[31] = (s11 shr 17).toUByte()
    return copy
}

fun sc_add(a: UByteArray, b: UByteArray): UByteArray {
    val s = UByteArray(32)
    var a0: Long = 2097151L and load_3(a)
    var a1: Long = 2097151L and (load_4(a, 2) shr 5)
    var a2: Long = 2097151L and (load_3(a, 5) shr 2)
    var a3: Long = 2097151L and (load_4(a, 7) shr 7)
    var a4: Long = 2097151L and (load_4(a, 10) shr 4)
    var a5: Long = 2097151L and (load_3(a, 13) shr 1)
    var a6: Long = 2097151L and (load_4(a, 15) shr 6)
    var a7: Long = 2097151L and (load_3(a, 18) shr 3)
    var a8: Long = 2097151L and load_3(a, 21)
    var a9: Long = 2097151L and (load_4(a, 23) shr 5)
    var a10: Long = 2097151L and (load_3(a, 26) shr 2)
    var a11: Long = (load_4(a, 28) shr 7)
    var b0: Long = 2097151L and load_3(b)
    var b1: Long = 2097151L and (load_4(b, 2) shr 5)
    var b2: Long = 2097151L and (load_3(b, 5) shr 2)
    var b3: Long = 2097151L and (load_4(b, 7) shr 7)
    var b4: Long = 2097151L and (load_4(b, 10) shr 4)
    var b5: Long = 2097151L and (load_3(b, 13) shr 1)
    var b6: Long = 2097151L and (load_4(b, 15) shr 6)
    var b7: Long = 2097151L and (load_3(b, 18) shr 3)
    var b8: Long = 2097151L and load_3(b, 21)
    var b9: Long = 2097151L and (load_4(b, 23) shr 5)
    var b10: Long = 2097151L and (load_3(b, 26) shr 2)
    var b11: Long = (load_4(b, 28) shr 7)
    var s0: Long = a0 + b0
    var s1: Long = a1 + b1
    var s2: Long = a2 + b2
    var s3: Long = a3 + b3
    var s4: Long = a4 + b4
    var s5: Long = a5 + b5
    var s6: Long = a6 + b6
    var s7: Long = a7 + b7
    var s8: Long = a8 + b8
    var s9: Long = a9 + b9
    var s10: Long = a10 + b10
    var s11: Long = a11 + b11
    var s12: Long = 0
    var carry0: Long
    var carry1: Long
    var carry2: Long
    var carry3: Long
    var carry4: Long
    var carry5: Long
    var carry6: Long
    var carry7: Long
    var carry8: Long
    var carry9: Long
    var carry10: Long
    var carry11: Long

    carry0 = (s0 + (1 shl 20)) shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry2 = (s2 + (1 shl 20)) shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry4 = (s4 + (1 shl 20)) shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry6 = (s6 + (1 shl 20)) shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry8 = (s8 + (1 shl 20)) shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry10 = (s10 + (1 shl 20)) shr 21; s11 += carry10; s10 -= carry10  shl  21;

    carry1 = (s1 + (1 shl 20)) shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry3 = (s3 + (1 shl 20)) shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry5 = (s5 + (1 shl 20)) shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry7 = (s7 + (1 shl 20)) shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry9 = (s9 + (1 shl 20)) shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry11 = (s11 + (1 shl 20)) shr 21; s12 += carry11; s11 -= carry11  shl  21;

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901
    s12 = 0

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10  shl  21;
    carry11 = s11 shr 21; s12 += carry11; s11 -= carry11  shl  21;

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10  shl  21;

    s[0] = (s0 shr 0).toUByte()
    s[1] = (s0 shr 8).toUByte()
    s[2] = ((s0 shr 16) or (s1  shl  5)).toUByte()
    s[3] = (s1 shr 3).toUByte()
    s[4] = (s1 shr 11).toUByte()
    s[5] = ((s1 shr 19) or (s2  shl  2)).toUByte()
    s[6] = (s2 shr 6).toUByte()
    s[7] = ((s2 shr 14) or (s3  shl  7)).toUByte()
    s[8] = (s3 shr 1).toUByte()
    s[9] = (s3 shr 9).toUByte()
    s[10] = ((s3 shr 17) or (s4  shl  4)).toUByte()
    s[11] = (s4 shr 4).toUByte()
    s[12] = (s4 shr 12).toUByte()
    s[13] = ((s4 shr 20) or (s5  shl  1)).toUByte()
    s[14] = (s5 shr 7).toUByte()
    s[15] = ((s5 shr 15) or (s6  shl  6)).toUByte()
    s[16] = (s6 shr 2).toUByte()
    s[17] = (s6 shr 10).toUByte()
    s[18] = ((s6 shr 18) or (s7  shl  3)).toUByte()
    s[19] = (s7 shr 5).toUByte()
    s[20] = (s7 shr 13).toUByte()
    s[21] = (s8 shr 0).toUByte()
    s[22] = (s8 shr 8).toUByte()
    s[23] = ((s8 shr 16) or (s9  shl  5)).toUByte()
    s[24] = (s9 shr 3).toUByte()
    s[25] = (s9 shr 11).toUByte()
    s[26] = ((s9 shr 19) or (s10  shl  2)).toUByte()
    s[27] = (s10 shr 6).toUByte()
    s[28] = ((s10 shr 14) or (s11  shl  7)).toUByte()
    s[29] = (s11 shr 1).toUByte()
    s[30] = (s11 shr 9).toUByte()
    s[31] = (s11 shr 17).toUByte()

    return s
}

fun sc_sub(a: UByteArray, b: UByteArray): UByteArray {
    val s = UByteArray(32)
    var a0: Long = 2097151L and load_3(a)
    var a1: Long = 2097151L and (load_4(a, 2) shr 5)
    var a2: Long = 2097151L and (load_3(a, 5) shr 2)
    var a3: Long = 2097151L and (load_4(a, 7) shr 7)
    var a4: Long = 2097151L and (load_4(a, 10) shr 4)
    var a5: Long = 2097151L and (load_3(a, 13) shr 1)
    var a6: Long = 2097151L and (load_4(a, 15) shr 6)
    var a7: Long = 2097151L and (load_3(a, 18) shr 3)
    var a8: Long = 2097151L and load_3(a, 21)
    var a9: Long = 2097151L and (load_4(a, 23) shr 5)
    var a10: Long = 2097151L and (load_3(a, 26) shr 2)
    var a11: Long = (load_4(a, 28) shr 7)
    var b0: Long = 2097151L and load_3(b)
    var b1: Long = 2097151L and (load_4(b, 2) shr 5)
    var b2: Long = 2097151L and (load_3(b, 5) shr 2)
    var b3: Long = 2097151L and (load_4(b, 7) shr 7)
    var b4: Long = 2097151L and (load_4(b, 10) shr 4)
    var b5: Long = 2097151L and (load_3(b, 13) shr 1)
    var b6: Long = 2097151L and (load_4(b, 15) shr 6)
    var b7: Long = 2097151L and (load_3(b, 18) shr 3)
    var b8: Long = 2097151L and load_3(b, 21)
    var b9: Long = 2097151L and (load_4(b, 23) shr 5)
    var b10: Long = 2097151L and (load_3(b, 26) shr 2)
    var b11: Long = (load_4(b, 28) shr 7)
    var s0: Long = a0 - b0
    var s1: Long = a1 - b1
    var s2: Long = a2 - b2
    var s3: Long = a3 - b3
    var s4: Long = a4 - b4
    var s5: Long = a5 - b5
    var s6: Long = a6 - b6
    var s7: Long = a7 - b7
    var s8: Long = a8 - b8
    var s9: Long = a9 - b9
    var s10: Long = a10 - b10
    var s11: Long = a11 - b11
    var s12: Long = 0
    var carry0: Long
    var carry1: Long
    var carry2: Long
    var carry3: Long
    var carry4: Long
    var carry5: Long
    var carry6: Long
    var carry7: Long
    var carry8: Long
    var carry9: Long
    var carry10: Long
    var carry11: Long

    carry0 = (s0 + (1 shl 20)) shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry2 = (s2 + (1 shl 20)) shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry4 = (s4 + (1 shl 20)) shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry6 = (s6 + (1 shl 20)) shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry8 = (s8 + (1 shl 20)) shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry10 = (s10 + (1 shl 20)) shr 21; s11 += carry10; s10 -= carry10  shl  21;

    carry1 = (s1 + (1 shl 20)) shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry3 = (s3 + (1 shl 20)) shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry5 = (s5 + (1 shl 20)) shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry7 = (s7 + (1 shl 20)) shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry9 = (s9 + (1 shl 20)) shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry11 = (s11 + (1 shl 20)) shr 21; s12 += carry11; s11 -= carry11  shl  21;

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901
    s12 = 0

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10  shl  21;
    carry11 = s11 shr 21; s12 += carry11; s11 -= carry11  shl  21;

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10  shl  21;

    s[0] = (s0 shr 0).toUByte()
    s[1] = (s0 shr 8).toUByte()
    s[2] = ((s0 shr 16) or (s1  shl  5)).toUByte()
    s[3] = (s1 shr 3).toUByte()
    s[4] = (s1 shr 11).toUByte()
    s[5] = ((s1 shr 19) or (s2  shl  2)).toUByte()
    s[6] = (s2 shr 6).toUByte()
    s[7] = ((s2 shr 14) or (s3  shl  7)).toUByte()
    s[8] = (s3 shr 1).toUByte()
    s[9] = (s3 shr 9).toUByte()
    s[10] = ((s3 shr 17) or (s4  shl  4)).toUByte()
    s[11] = (s4 shr 4).toUByte()
    s[12] = (s4 shr 12).toUByte()
    s[13] = ((s4 shr 20) or (s5  shl  1)).toUByte()
    s[14] = (s5 shr 7).toUByte()
    s[15] = ((s5 shr 15) or (s6  shl  6)).toUByte()
    s[16] = (s6 shr 2).toUByte()
    s[17] = (s6 shr 10).toUByte()
    s[18] = ((s6 shr 18) or (s7  shl  3)).toUByte()
    s[19] = (s7 shr 5).toUByte()
    s[20] = (s7 shr 13).toUByte()
    s[21] = (s8 shr 0).toUByte()
    s[22] = (s8 shr 8).toUByte()
    s[23] = ((s8 shr 16) or (s9  shl  5)).toUByte()
    s[24] = (s9 shr 3).toUByte()
    s[25] = (s9 shr 11).toUByte()
    s[26] = ((s9 shr 19) or (s10  shl  2)).toUByte()
    s[27] = (s10 shr 6).toUByte()
    s[28] = ((s10 shr 14) or (s11  shl  7)).toUByte()
    s[29] = (s11 shr 1).toUByte()
    s[30] = (s11 shr 9).toUByte()
    s[31] = (s11 shr 17).toUByte()

    return s
}

//((c-ab) mod l)
fun sc_mulsub(a: UByteArray, b: UByteArray, c: UByteArray): UByteArray {
    val s = UByteArray(32)
    var a0: Long = 2097151L and load_3(a)
    var a1: Long = 2097151L and (load_4(a, 2) shr 5)
    var a2: Long = 2097151L and (load_3(a, 5) shr 2)
    var a3: Long = 2097151L and (load_4(a, 7) shr 7)
    var a4: Long = 2097151L and (load_4(a, 10) shr 4)
    var a5: Long = 2097151L and (load_3(a, 13) shr 1)
    var a6: Long = 2097151L and (load_4(a, 15) shr 6)
    var a7: Long = 2097151L and (load_3(a, 18) shr 3)
    var a8: Long = 2097151L and load_3(a, 21)
    var a9: Long = 2097151L and (load_4(a, 23) shr 5)
    var a10: Long = 2097151L and (load_3(a, 26) shr 2)
    var a11: Long = (load_4(a, 28) shr 7)
    var b0: Long = 2097151L and load_3(b)
    var b1: Long = 2097151L and (load_4(b, 2) shr 5)
    var b2: Long = 2097151L and (load_3(b, 5) shr 2)
    var b3: Long = 2097151L and (load_4(b, 7) shr 7)
    var b4: Long = 2097151L and (load_4(b, 10) shr 4)
    var b5: Long = 2097151L and (load_3(b, 13) shr 1)
    var b6: Long = 2097151L and (load_4(b, 15) shr 6)
    var b7: Long = 2097151L and (load_3(b, 18) shr 3)
    var b8: Long = 2097151L and load_3(b, 21)
    var b9: Long = 2097151L and (load_4(b, 23) shr 5)
    var b10: Long = 2097151L and (load_3(b, 26) shr 2)
    var b11: Long = (load_4(b, 28) shr 7)
    var c0: Long = 2097151L and load_3(c)
    var c1: Long = 2097151L and (load_4(c, 2) shr 5)
    var c2: Long = 2097151L and (load_3(c, 5) shr 2)
    var c3: Long = 2097151L and (load_4(c, 7) shr 7)
    var c4: Long = 2097151L and (load_4(c, 10) shr 4)
    var c5: Long = 2097151L and (load_3(c, 13) shr 1)
    var c6: Long = 2097151L and (load_4(c, 15) shr 6)
    var c7: Long = 2097151L and (load_3(c, 18) shr 3)
    var c8: Long = 2097151L and load_3(c, 21)
    var c9: Long = 2097151L and (load_4(c, 23) shr 5)
    var c10: Long = 2097151L and (load_3(c, 26) shr 2)
    var c11: Long = (load_4(c, 28) shr 7)
    var s0: Long
    var s1: Long
    var s2: Long
    var s3: Long
    var s4: Long
    var s5: Long
    var s6: Long
    var s7: Long
    var s8: Long
    var s9: Long
    var s10: Long
    var s11: Long
    var s12: Long
    var s13: Long
    var s14: Long
    var s15: Long
    var s16: Long
    var s17: Long
    var s18: Long
    var s19: Long
    var s20: Long
    var s21: Long
    var s22: Long
    var s23: Long
    var carry0: Long
    var carry1: Long
    var carry2: Long
    var carry3: Long
    var carry4: Long
    var carry5: Long
    var carry6: Long
    var carry7: Long
    var carry8: Long
    var carry9: Long
    var carry10: Long
    var carry11: Long
    var carry12: Long
    var carry13: Long
    var carry14: Long
    var carry15: Long
    var carry16: Long
    var carry17: Long
    var carry18: Long
    var carry19: Long
    var carry20: Long
    var carry21: Long
    var carry22: Long

    s0 = c0 - a0*b0
    s1 = c1 - (a0*b1 + a1*b0)
    s2 = c2 - (a0*b2 + a1*b1 + a2*b0)
    s3 = c3 - (a0*b3 + a1*b2 + a2*b1 + a3*b0)
    s4 = c4 - (a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0)
    s5 = c5 - (a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0)
    s6 = c6 - (a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0)
    s7 = c7 - (a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0)
    s8 = c8 - (a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 + a7*b1 + a8*b0)
    s9 = c9 - (a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2 + a8*b1 + a9*b0)
    s10 = c10 - (a0*b10 + a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 + a7*b3 + a8*b2 + a9*b1 + a10*b0)
    s11 = c11 - (a0*b11 + a1*b10 + a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 + a7*b4 + a8*b3 + a9*b2 + a10*b1 + a11*b0)
    s12 = -(a1*b11 + a2*b10 + a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 + a8*b4 + a9*b3 + a10*b2 + a11*b1)
    s13 = -(a2*b11 + a3*b10 + a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 + a9*b4 + a10*b3 + a11*b2)
    s14 = -(a3*b11 + a4*b10 + a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5 + a10*b4 + a11*b3)
    s15 = -(a4*b11 + a5*b10 + a6*b9 + a7*b8 + a8*b7 + a9*b6 + a10*b5 + a11*b4)
    s16 = -(a5*b11 + a6*b10 + a7*b9 + a8*b8 + a9*b7 + a10*b6 + a11*b5)
    s17 = -(a6*b11 + a7*b10 + a8*b9 + a9*b8 + a10*b7 + a11*b6)
    s18 = -(a7*b11 + a8*b10 + a9*b9 + a10*b8 + a11*b7)
    s19 = -(a8*b11 + a9*b10 + a10*b9 + a11*b8)
    s20 = -(a9*b11 + a10*b10 + a11*b9)
    s21 = -(a10*b11 + a11*b10)
    s22 = -a11*b11
    s23 = 0

    carry0 = (s0 + (1 shl 20)) shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry2 = (s2 + (1 shl 20)) shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry4 = (s4 + (1 shl 20)) shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry6 = (s6 + (1 shl 20)) shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry8 = (s8 + (1 shl 20)) shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry10 = (s10 + (1 shl 20)) shr 21; s11 += carry10; s10 -= carry10  shl  21;
    carry12 = (s12 + (1 shl 20)) shr 21; s13 += carry12; s12 -= carry12  shl  21;
    carry14 = (s14 + (1 shl 20)) shr 21; s15 += carry14; s14 -= carry14  shl  21;
    carry16 = (s16 + (1 shl 20)) shr 21; s17 += carry16; s16 -= carry16  shl  21;
    carry18 = (s18 + (1 shl 20)) shr 21; s19 += carry18; s18 -= carry18  shl  21;
    carry20 = (s20 + (1 shl 20)) shr 21; s21 += carry20; s20 -= carry20  shl  21;
    carry22 = (s22 + (1 shl 20)) shr 21; s23 += carry22; s22 -= carry22  shl  21;

    carry1 = (s1 + (1 shl 20)) shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry3 = (s3 + (1 shl 20)) shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry5 = (s5 + (1 shl 20)) shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry7 = (s7 + (1 shl 20)) shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry9 = (s9 + (1 shl 20)) shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry11 = (s11 + (1 shl 20)) shr 21; s12 += carry11; s11 -= carry11  shl  21;
    carry13 = (s13 + (1 shl 20)) shr 21; s14 += carry13; s13 -= carry13  shl  21;
    carry15 = (s15 + (1 shl 20)) shr 21; s16 += carry15; s15 -= carry15  shl  21;
    carry17 = (s17 + (1 shl 20)) shr 21; s18 += carry17; s17 -= carry17  shl  21;
    carry19 = (s19 + (1 shl 20)) shr 21; s20 += carry19; s19 -= carry19  shl  21;
    carry21 = (s21 + (1 shl 20)) shr 21; s22 += carry21; s21 -= carry21  shl  21;

    s11 += s23 * 666643
    s12 += s23 * 470296
    s13 += s23 * 654183
    s14 -= s23 * 997805
    s15 += s23 * 136657
    s16 -= s23 * 683901

    s10 += s22 * 666643
    s11 += s22 * 470296
    s12 += s22 * 654183
    s13 -= s22 * 997805
    s14 += s22 * 136657
    s15 -= s22 * 683901

    s9 += s21 * 666643
    s10 += s21 * 470296
    s11 += s21 * 654183
    s12 -= s21 * 997805
    s13 += s21 * 136657
    s14 -= s21 * 683901

    s8 += s20 * 666643
    s9 += s20 * 470296
    s10 += s20 * 654183
    s11 -= s20 * 997805
    s12 += s20 * 136657
    s13 -= s20 * 683901

    s7 += s19 * 666643
    s8 += s19 * 470296
    s9 += s19 * 654183
    s10 -= s19 * 997805
    s11 += s19 * 136657
    s12 -= s19 * 683901

    s6 += s18 * 666643
    s7 += s18 * 470296
    s8 += s18 * 654183
    s9 -= s18 * 997805
    s10 += s18 * 136657
    s11 -= s18 * 683901

    carry6 = (s6 + (1 shl 20)) shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry8 = (s8 + (1 shl 20)) shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry10 = (s10 + (1 shl 20)) shr 21; s11 += carry10; s10 -= carry10  shl  21;
    carry12 = (s12 + (1 shl 20)) shr 21; s13 += carry12; s12 -= carry12  shl  21;
    carry14 = (s14 + (1 shl 20)) shr 21; s15 += carry14; s14 -= carry14  shl  21;
    carry16 = (s16 + (1 shl 20)) shr 21; s17 += carry16; s16 -= carry16  shl  21;

    carry7 = (s7 + (1 shl 20)) shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry9 = (s9 + (1 shl 20)) shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry11 = (s11 + (1 shl 20)) shr 21; s12 += carry11; s11 -= carry11  shl  21;
    carry13 = (s13 + (1 shl 20)) shr 21; s14 += carry13; s13 -= carry13  shl  21;
    carry15 = (s15 + (1 shl 20)) shr 21; s16 += carry15; s15 -= carry15  shl  21;

    s5 += s17 * 666643
    s6 += s17 * 470296
    s7 += s17 * 654183
    s8 -= s17 * 997805
    s9 += s17 * 136657
    s10 -= s17 * 683901

    s4 += s16 * 666643
    s5 += s16 * 470296
    s6 += s16 * 654183
    s7 -= s16 * 997805
    s8 += s16 * 136657
    s9 -= s16 * 683901

    s3 += s15 * 666643
    s4 += s15 * 470296
    s5 += s15 * 654183
    s6 -= s15 * 997805
    s7 += s15 * 136657
    s8 -= s15 * 683901

    s2 += s14 * 666643
    s3 += s14 * 470296
    s4 += s14 * 654183
    s5 -= s14 * 997805
    s6 += s14 * 136657
    s7 -= s14 * 683901

    s1 += s13 * 666643
    s2 += s13 * 470296
    s3 += s13 * 654183
    s4 -= s13 * 997805
    s5 += s13 * 136657
    s6 -= s13 * 683901

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901
    s12 = 0

    carry0 = (s0 + (1 shl 20)) shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry2 = (s2 + (1 shl 20)) shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry4 = (s4 + (1 shl 20)) shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry6 = (s6 + (1 shl 20)) shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry8 = (s8 + (1 shl 20)) shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry10 = (s10 + (1 shl 20)) shr 21; s11 += carry10; s10 -= carry10  shl  21;

    carry1 = (s1 + (1 shl 20)) shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry3 = (s3 + (1 shl 20)) shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry5 = (s5 + (1 shl 20)) shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry7 = (s7 + (1 shl 20)) shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry9 = (s9 + (1 shl 20)) shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry11 = (s11 + (1 shl 20)) shr 21; s12 += carry11; s11 -= carry11  shl  21;

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901
    s12 = 0

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10  shl  21;
    carry11 = s11 shr 21; s12 += carry11; s11 -= carry11  shl  21;

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10  shl  21;

    s[0] = (s0 shr 0).toUByte()
    s[1] = (s0 shr 8).toUByte()
    s[2] = ((s0 shr 16) or (s1  shl  5)).toUByte()
    s[3] = (s1 shr 3).toUByte()
    s[4] = (s1 shr 11).toUByte()
    s[5] = ((s1 shr 19) or (s2  shl  2)).toUByte()
    s[6] = (s2 shr 6).toUByte()
    s[7] = ((s2 shr 14) or (s3  shl  7)).toUByte()
    s[8] = (s3 shr 1).toUByte()
    s[9] = (s3 shr 9).toUByte()
    s[10] = ((s3 shr 17) or (s4  shl  4)).toUByte()
    s[11] = (s4 shr 4).toUByte()
    s[12] = (s4 shr 12).toUByte()
    s[13] = ((s4 shr 20) or (s5  shl  1)).toUByte()
    s[14] = (s5 shr 7).toUByte()
    s[15] = ((s5 shr 15) or (s6  shl  6)).toUByte()
    s[16] = (s6 shr 2).toUByte()
    s[17] = (s6 shr 10).toUByte()
    s[18] = ((s6 shr 18) or (s7  shl  3)).toUByte()
    s[19] = (s7 shr 5).toUByte()
    s[20] = (s7 shr 13).toUByte()
    s[21] = (s8 shr 0).toUByte()
    s[22] = (s8 shr 8).toUByte()
    s[23] = ((s8 shr 16) or (s9  shl  5)).toUByte()
    s[24] = (s9 shr 3).toUByte()
    s[25] = (s9 shr 11).toUByte()
    s[26] = ((s9 shr 19) or (s10  shl  2)).toUByte()
    s[27] = (s10 shr 6).toUByte()
    s[28] = ((s10 shr 14) or (s11  shl  7)).toUByte()
    s[29] = (s11 shr 1).toUByte()
    s[30] = (s11 shr 9).toUByte()
    s[31] = (s11 shr 17).toUByte()

    return s
}

//ab mod l
fun sc_mul(a: UByteArray, b: UByteArray): UByteArray {
    val s = UByteArray(32)

    var a0: Long = 2097151L and load_3(a)
    var a1: Long = 2097151L and (load_4(a, 2) shr 5)
    var a2: Long = 2097151L and (load_3(a, 5) shr 2)
    var a3: Long = 2097151L and (load_4(a, 7) shr 7)
    var a4: Long = 2097151L and (load_4(a, 10) shr 4)
    var a5: Long = 2097151L and (load_3(a, 13) shr 1)
    var a6: Long = 2097151L and (load_4(a, 15) shr 6)
    var a7: Long = 2097151L and (load_3(a, 18) shr 3)
    var a8: Long = 2097151L and load_3(a, 21)
    var a9: Long = 2097151L and (load_4(a, 23) shr 5)
    var a10: Long = 2097151L and (load_3(a, 26) shr 2)
    var a11: Long = (load_4(a, 28) shr 7)
    var b0: Long = 2097151L and load_3(b)
    var b1: Long = 2097151L and (load_4(b, 2) shr 5)
    var b2: Long = 2097151L and (load_3(b, 5) shr 2)
    var b3: Long = 2097151L and (load_4(b, 7) shr 7)
    var b4: Long = 2097151L and (load_4(b, 10) shr 4)
    var b5: Long = 2097151L and (load_3(b, 13) shr 1)
    var b6: Long = 2097151L and (load_4(b, 15) shr 6)
    var b7: Long = 2097151L and (load_3(b, 18) shr 3)
    var b8: Long = 2097151L and load_3(b, 21)
    var b9: Long = 2097151L and (load_4(b, 23) shr 5)
    var b10: Long = 2097151L and (load_3(b, 26) shr 2)
    var b11: Long = (load_4(b, 28) shr 7)
    var s0: Long
    var s1: Long
    var s2: Long
    var s3: Long
    var s4: Long
    var s5: Long
    var s6: Long
    var s7: Long
    var s8: Long
    var s9: Long
    var s10: Long
    var s11: Long
    var s12: Long
    var s13: Long
    var s14: Long
    var s15: Long
    var s16: Long
    var s17: Long
    var s18: Long
    var s19: Long
    var s20: Long
    var s21: Long
    var s22: Long
    var s23: Long
    var carry0: Long
    var carry1: Long
    var carry2: Long
    var carry3: Long
    var carry4: Long
    var carry5: Long
    var carry6: Long
    var carry7: Long
    var carry8: Long
    var carry9: Long
    var carry10: Long
    var carry11: Long
    var carry12: Long
    var carry13: Long
    var carry14: Long
    var carry15: Long
    var carry16: Long
    var carry17: Long
    var carry18: Long
    var carry19: Long
    var carry20: Long
    var carry21: Long
    var carry22: Long

    s0 = a0*b0
    s1 = (a0*b1 + a1*b0)
    s2 = (a0*b2 + a1*b1 + a2*b0)
    s3 = (a0*b3 + a1*b2 + a2*b1 + a3*b0)
    s4 = (a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0)
    s5 = (a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0)
    s6 = (a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0)
    s7 = (a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0)
    s8 = (a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 + a7*b1 + a8*b0)
    s9 = (a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2 + a8*b1 + a9*b0)
    s10 = (a0*b10 + a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 + a7*b3 + a8*b2 + a9*b1 + a10*b0)
    s11 = (a0*b11 + a1*b10 + a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 + a7*b4 + a8*b3 + a9*b2 + a10*b1 + a11*b0)
    s12 = (a1*b11 + a2*b10 + a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 + a8*b4 + a9*b3 + a10*b2 + a11*b1)
    s13 = (a2*b11 + a3*b10 + a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 + a9*b4 + a10*b3 + a11*b2)
    s14 = (a3*b11 + a4*b10 + a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5 + a10*b4 + a11*b3)
    s15 = (a4*b11 + a5*b10 + a6*b9 + a7*b8 + a8*b7 + a9*b6 + a10*b5 + a11*b4)
    s16 = (a5*b11 + a6*b10 + a7*b9 + a8*b8 + a9*b7 + a10*b6 + a11*b5)
    s17 = (a6*b11 + a7*b10 + a8*b9 + a9*b8 + a10*b7 + a11*b6)
    s18 = (a7*b11 + a8*b10 + a9*b9 + a10*b8 + a11*b7)
    s19 = (a8*b11 + a9*b10 + a10*b9 + a11*b8)
    s20 = (a9*b11 + a10*b10 + a11*b9)
    s21 = (a10*b11 + a11*b10)
    s22 = a11*b11
    s23 = 0

    carry0 = (s0 + (1 shl 20)) shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry2 = (s2 + (1 shl 20)) shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry4 = (s4 + (1 shl 20)) shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry6 = (s6 + (1 shl 20)) shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry8 = (s8 + (1 shl 20)) shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry10 = (s10 + (1 shl 20)) shr 21; s11 += carry10; s10 -= carry10  shl  21;
    carry12 = (s12 + (1 shl 20)) shr 21; s13 += carry12; s12 -= carry12  shl  21;
    carry14 = (s14 + (1 shl 20)) shr 21; s15 += carry14; s14 -= carry14  shl  21;
    carry16 = (s16 + (1 shl 20)) shr 21; s17 += carry16; s16 -= carry16  shl  21;
    carry18 = (s18 + (1 shl 20)) shr 21; s19 += carry18; s18 -= carry18  shl  21;
    carry20 = (s20 + (1 shl 20)) shr 21; s21 += carry20; s20 -= carry20  shl  21;
    carry22 = (s22 + (1 shl 20)) shr 21; s23 += carry22; s22 -= carry22  shl  21;

    carry1 = (s1 + (1 shl 20)) shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry3 = (s3 + (1 shl 20)) shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry5 = (s5 + (1 shl 20)) shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry7 = (s7 + (1 shl 20)) shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry9 = (s9 + (1 shl 20)) shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry11 = (s11 + (1 shl 20)) shr 21; s12 += carry11; s11 -= carry11  shl  21;
    carry13 = (s13 + (1 shl 20)) shr 21; s14 += carry13; s13 -= carry13  shl  21;
    carry15 = (s15 + (1 shl 20)) shr 21; s16 += carry15; s15 -= carry15  shl  21;
    carry17 = (s17 + (1 shl 20)) shr 21; s18 += carry17; s17 -= carry17  shl  21;
    carry19 = (s19 + (1 shl 20)) shr 21; s20 += carry19; s19 -= carry19  shl  21;
    carry21 = (s21 + (1 shl 20)) shr 21; s22 += carry21; s21 -= carry21  shl  21;

    s11 += s23 * 666643
    s12 += s23 * 470296
    s13 += s23 * 654183
    s14 -= s23 * 997805
    s15 += s23 * 136657
    s16 -= s23 * 683901

    s10 += s22 * 666643
    s11 += s22 * 470296
    s12 += s22 * 654183
    s13 -= s22 * 997805
    s14 += s22 * 136657
    s15 -= s22 * 683901

    s9 += s21 * 666643
    s10 += s21 * 470296
    s11 += s21 * 654183
    s12 -= s21 * 997805
    s13 += s21 * 136657
    s14 -= s21 * 683901

    s8 += s20 * 666643
    s9 += s20 * 470296
    s10 += s20 * 654183
    s11 -= s20 * 997805
    s12 += s20 * 136657
    s13 -= s20 * 683901

    s7 += s19 * 666643
    s8 += s19 * 470296
    s9 += s19 * 654183
    s10 -= s19 * 997805
    s11 += s19 * 136657
    s12 -= s19 * 683901

    s6 += s18 * 666643
    s7 += s18 * 470296
    s8 += s18 * 654183
    s9 -= s18 * 997805
    s10 += s18 * 136657
    s11 -= s18 * 683901

    carry6 = (s6 + (1 shl 20)) shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry8 = (s8 + (1 shl 20)) shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry10 = (s10 + (1 shl 20)) shr 21; s11 += carry10; s10 -= carry10  shl  21;
    carry12 = (s12 + (1 shl 20)) shr 21; s13 += carry12; s12 -= carry12  shl  21;
    carry14 = (s14 + (1 shl 20)) shr 21; s15 += carry14; s14 -= carry14  shl  21;
    carry16 = (s16 + (1 shl 20)) shr 21; s17 += carry16; s16 -= carry16  shl  21;

    carry7 = (s7 + (1 shl 20)) shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry9 = (s9 + (1 shl 20)) shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry11 = (s11 + (1 shl 20)) shr 21; s12 += carry11; s11 -= carry11  shl  21;
    carry13 = (s13 + (1 shl 20)) shr 21; s14 += carry13; s13 -= carry13  shl  21;
    carry15 = (s15 + (1 shl 20)) shr 21; s16 += carry15; s15 -= carry15  shl  21;

    s5 += s17 * 666643
    s6 += s17 * 470296
    s7 += s17 * 654183
    s8 -= s17 * 997805
    s9 += s17 * 136657
    s10 -= s17 * 683901

    s4 += s16 * 666643
    s5 += s16 * 470296
    s6 += s16 * 654183
    s7 -= s16 * 997805
    s8 += s16 * 136657
    s9 -= s16 * 683901

    s3 += s15 * 666643
    s4 += s15 * 470296
    s5 += s15 * 654183
    s6 -= s15 * 997805
    s7 += s15 * 136657
    s8 -= s15 * 683901

    s2 += s14 * 666643
    s3 += s14 * 470296
    s4 += s14 * 654183
    s5 -= s14 * 997805
    s6 += s14 * 136657
    s7 -= s14 * 683901

    s1 += s13 * 666643
    s2 += s13 * 470296
    s3 += s13 * 654183
    s4 -= s13 * 997805
    s5 += s13 * 136657
    s6 -= s13 * 683901

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901
    s12 = 0

    carry0 = (s0 + (1 shl 20)) shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry2 = (s2 + (1 shl 20)) shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry4 = (s4 + (1 shl 20)) shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry6 = (s6 + (1 shl 20)) shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry8 = (s8 + (1 shl 20)) shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry10 = (s10 + (1 shl 20)) shr 21; s11 += carry10; s10 -= carry10  shl  21;

    carry1 = (s1 + (1 shl 20)) shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry3 = (s3 + (1 shl 20)) shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry5 = (s5 + (1 shl 20)) shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry7 = (s7 + (1 shl 20)) shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry9 = (s9 + (1 shl 20)) shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry11 = (s11 + (1 shl 20)) shr 21; s12 += carry11; s11 -= carry11  shl  21;

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901
    s12 = 0

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10  shl  21;
    carry11 = s11 shr 21; s12 += carry11; s11 -= carry11  shl  21;

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10  shl  21;

    s[0] = (s0 shr 0).toUByte()
    s[1] = (s0 shr 8).toUByte()
    s[2] = ((s0 shr 16) or (s1  shl  5)).toUByte()
    s[3] = (s1 shr 3).toUByte()
    s[4] = (s1 shr 11).toUByte()
    s[5] = ((s1 shr 19) or (s2  shl  2)).toUByte()
    s[6] = (s2 shr 6).toUByte()
    s[7] = ((s2 shr 14) or (s3  shl  7)).toUByte()
    s[8] = (s3 shr 1).toUByte()
    s[9] = (s3 shr 9).toUByte()
    s[10] = ((s3 shr 17) or (s4  shl  4)).toUByte()
    s[11] = (s4 shr 4).toUByte()
    s[12] = (s4 shr 12).toUByte()
    s[13] = ((s4 shr 20) or (s5  shl  1)).toUByte()
    s[14] = (s5 shr 7).toUByte()
    s[15] = ((s5 shr 15) or (s6  shl  6)).toUByte()
    s[16] = (s6 shr 2).toUByte()
    s[17] = (s6 shr 10).toUByte()
    s[18] = ((s6 shr 18) or (s7  shl  3)).toUByte()
    s[19] = (s7 shr 5).toUByte()
    s[20] = (s7 shr 13).toUByte()
    s[21] = (s8 shr 0).toUByte()
    s[22] = (s8 shr 8).toUByte()
    s[23] = ((s8 shr 16) or (s9  shl  5)).toUByte()
    s[24] = (s9 shr 3).toUByte()
    s[25] = (s9 shr 11).toUByte()
    s[26] = ((s9 shr 19) or (s10  shl  2)).toUByte()
    s[27] = (s10 shr 6).toUByte()
    s[28] = ((s10 shr 14) or (s11  shl  7)).toUByte()
    s[29] = (s11 shr 1).toUByte()
    s[30] = (s11 shr 9).toUByte()
    s[31] = (s11 shr 17).toUByte()

    return s
}

//((c+ab) mod l)
fun sc_muladd(a: UByteArray, b: UByteArray, c: UByteArray): UByteArray {
    val s = UByteArray(32)

    var a0: Long = 2097151L and load_3(a)
    var a1: Long = 2097151L and (load_4(a, 2) shr 5)
    var a2: Long = 2097151L and (load_3(a, 5) shr 2)
    var a3: Long = 2097151L and (load_4(a, 7) shr 7)
    var a4: Long = 2097151L and (load_4(a, 10) shr 4)
    var a5: Long = 2097151L and (load_3(a, 13) shr 1)
    var a6: Long = 2097151L and (load_4(a, 15) shr 6)
    var a7: Long = 2097151L and (load_3(a, 18) shr 3)
    var a8: Long = 2097151L and load_3(a, 21)
    var a9: Long = 2097151L and (load_4(a, 23) shr 5)
    var a10: Long = 2097151L and (load_3(a, 26) shr 2)
    var a11: Long = (load_4(a, 28) shr 7)
    var b0: Long = 2097151L and load_3(b)
    var b1: Long = 2097151L and (load_4(b, 2) shr 5)
    var b2: Long = 2097151L and (load_3(b, 5) shr 2)
    var b3: Long = 2097151L and (load_4(b, 7) shr 7)
    var b4: Long = 2097151L and (load_4(b, 10) shr 4)
    var b5: Long = 2097151L and (load_3(b, 13) shr 1)
    var b6: Long = 2097151L and (load_4(b, 15) shr 6)
    var b7: Long = 2097151L and (load_3(b, 18) shr 3)
    var b8: Long = 2097151L and load_3(b, 21)
    var b9: Long = 2097151L and (load_4(b, 23) shr 5)
    var b10: Long = 2097151L and (load_3(b, 26) shr 2)
    var b11: Long = (load_4(b, 28) shr 7)
    var c0: Long = 2097151L and load_3(c)
    var c1: Long = 2097151L and (load_4(c, 2) shr 5)
    var c2: Long = 2097151L and (load_3(c, 5) shr 2)
    var c3: Long = 2097151L and (load_4(c, 7) shr 7)
    var c4: Long = 2097151L and (load_4(c, 10) shr 4)
    var c5: Long = 2097151L and (load_3(c, 13) shr 1)
    var c6: Long = 2097151L and (load_4(c, 15) shr 6)
    var c7: Long = 2097151L and (load_3(c, 18) shr 3)
    var c8: Long = 2097151L and load_3(c, 21)
    var c9: Long = 2097151L and (load_4(c, 23) shr 5)
    var c10: Long = 2097151L and (load_3(c, 26) shr 2)
    var c11: Long = (load_4(c, 28) shr 7)
    var s0: Long
    var s1: Long
    var s2: Long
    var s3: Long
    var s4: Long
    var s5: Long
    var s6: Long
    var s7: Long
    var s8: Long
    var s9: Long
    var s10: Long
    var s11: Long
    var s12: Long
    var s13: Long
    var s14: Long
    var s15: Long
    var s16: Long
    var s17: Long
    var s18: Long
    var s19: Long
    var s20: Long
    var s21: Long
    var s22: Long
    var s23: Long
    var carry0: Long
    var carry1: Long
    var carry2: Long
    var carry3: Long
    var carry4: Long
    var carry5: Long
    var carry6: Long
    var carry7: Long
    var carry8: Long
    var carry9: Long
    var carry10: Long
    var carry11: Long
    var carry12: Long
    var carry13: Long
    var carry14: Long
    var carry15: Long
    var carry16: Long
    var carry17: Long
    var carry18: Long
    var carry19: Long
    var carry20: Long
    var carry21: Long
    var carry22: Long

    s0 = c0 + a0*b0
    s1 = c1 + (a0*b1 + a1*b0)
    s2 = c2 + (a0*b2 + a1*b1 + a2*b0)
    s3 = c3 + (a0*b3 + a1*b2 + a2*b1 + a3*b0)
    s4 = c4 + (a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0)
    s5 = c5 + (a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0)
    s6 = c6 + (a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0)
    s7 = c7 + (a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0)
    s8 = c8 + (a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 + a7*b1 + a8*b0)
    s9 = c9 + (a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2 + a8*b1 + a9*b0)
    s10 = c10 + (a0*b10 + a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 + a7*b3 + a8*b2 + a9*b1 + a10*b0)
    s11 = c11 + (a0*b11 + a1*b10 + a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 + a7*b4 + a8*b3 + a9*b2 + a10*b1 + a11*b0)
    s12 = (a1*b11 + a2*b10 + a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 + a8*b4 + a9*b3 + a10*b2 + a11*b1)
    s13 = (a2*b11 + a3*b10 + a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 + a9*b4 + a10*b3 + a11*b2)
    s14 = (a3*b11 + a4*b10 + a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5 + a10*b4 + a11*b3)
    s15 = (a4*b11 + a5*b10 + a6*b9 + a7*b8 + a8*b7 + a9*b6 + a10*b5 + a11*b4)
    s16 = (a5*b11 + a6*b10 + a7*b9 + a8*b8 + a9*b7 + a10*b6 + a11*b5)
    s17 = (a6*b11 + a7*b10 + a8*b9 + a9*b8 + a10*b7 + a11*b6)
    s18 = (a7*b11 + a8*b10 + a9*b9 + a10*b8 + a11*b7)
    s19 = (a8*b11 + a9*b10 + a10*b9 + a11*b8)
    s20 = (a9*b11 + a10*b10 + a11*b9)
    s21 = (a10*b11 + a11*b10)
    s22 = a11*b11
    s23 = 0

    carry0 = (s0 + (1 shl 20)) shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry2 = (s2 + (1 shl 20)) shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry4 = (s4 + (1 shl 20)) shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry6 = (s6 + (1 shl 20)) shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry8 = (s8 + (1 shl 20)) shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry10 = (s10 + (1 shl 20)) shr 21; s11 += carry10; s10 -= carry10  shl  21;
    carry12 = (s12 + (1 shl 20)) shr 21; s13 += carry12; s12 -= carry12  shl  21;
    carry14 = (s14 + (1 shl 20)) shr 21; s15 += carry14; s14 -= carry14  shl  21;
    carry16 = (s16 + (1 shl 20)) shr 21; s17 += carry16; s16 -= carry16  shl  21;
    carry18 = (s18 + (1 shl 20)) shr 21; s19 += carry18; s18 -= carry18  shl  21;
    carry20 = (s20 + (1 shl 20)) shr 21; s21 += carry20; s20 -= carry20  shl  21;
    carry22 = (s22 + (1 shl 20)) shr 21; s23 += carry22; s22 -= carry22  shl  21;

    carry1 = (s1 + (1 shl 20)) shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry3 = (s3 + (1 shl 20)) shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry5 = (s5 + (1 shl 20)) shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry7 = (s7 + (1 shl 20)) shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry9 = (s9 + (1 shl 20)) shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry11 = (s11 + (1 shl 20)) shr 21; s12 += carry11; s11 -= carry11  shl  21;
    carry13 = (s13 + (1 shl 20)) shr 21; s14 += carry13; s13 -= carry13  shl  21;
    carry15 = (s15 + (1 shl 20)) shr 21; s16 += carry15; s15 -= carry15  shl  21;
    carry17 = (s17 + (1 shl 20)) shr 21; s18 += carry17; s17 -= carry17  shl  21;
    carry19 = (s19 + (1 shl 20)) shr 21; s20 += carry19; s19 -= carry19  shl  21;
    carry21 = (s21 + (1 shl 20)) shr 21; s22 += carry21; s21 -= carry21  shl  21;

    s11 += s23 * 666643
    s12 += s23 * 470296
    s13 += s23 * 654183
    s14 -= s23 * 997805
    s15 += s23 * 136657
    s16 -= s23 * 683901

    s10 += s22 * 666643
    s11 += s22 * 470296
    s12 += s22 * 654183
    s13 -= s22 * 997805
    s14 += s22 * 136657
    s15 -= s22 * 683901

    s9 += s21 * 666643
    s10 += s21 * 470296
    s11 += s21 * 654183
    s12 -= s21 * 997805
    s13 += s21 * 136657
    s14 -= s21 * 683901

    s8 += s20 * 666643
    s9 += s20 * 470296
    s10 += s20 * 654183
    s11 -= s20 * 997805
    s12 += s20 * 136657
    s13 -= s20 * 683901

    s7 += s19 * 666643
    s8 += s19 * 470296
    s9 += s19 * 654183
    s10 -= s19 * 997805
    s11 += s19 * 136657
    s12 -= s19 * 683901

    s6 += s18 * 666643
    s7 += s18 * 470296
    s8 += s18 * 654183
    s9 -= s18 * 997805
    s10 += s18 * 136657
    s11 -= s18 * 683901

    carry6 = (s6 + (1 shl 20)) shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry8 = (s8 + (1 shl 20)) shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry10 = (s10 + (1 shl 20)) shr 21; s11 += carry10; s10 -= carry10  shl  21;
    carry12 = (s12 + (1 shl 20)) shr 21; s13 += carry12; s12 -= carry12  shl  21;
    carry14 = (s14 + (1 shl 20)) shr 21; s15 += carry14; s14 -= carry14  shl  21;
    carry16 = (s16 + (1 shl 20)) shr 21; s17 += carry16; s16 -= carry16  shl  21;

    carry7 = (s7 + (1 shl 20)) shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry9 = (s9 + (1 shl 20)) shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry11 = (s11 + (1 shl 20)) shr 21; s12 += carry11; s11 -= carry11  shl  21;
    carry13 = (s13 + (1 shl 20)) shr 21; s14 += carry13; s13 -= carry13  shl  21;
    carry15 = (s15 + (1 shl 20)) shr 21; s16 += carry15; s15 -= carry15  shl  21;

    s5 += s17 * 666643
    s6 += s17 * 470296
    s7 += s17 * 654183
    s8 -= s17 * 997805
    s9 += s17 * 136657
    s10 -= s17 * 683901

    s4 += s16 * 666643
    s5 += s16 * 470296
    s6 += s16 * 654183
    s7 -= s16 * 997805
    s8 += s16 * 136657
    s9 -= s16 * 683901

    s3 += s15 * 666643
    s4 += s15 * 470296
    s5 += s15 * 654183
    s6 -= s15 * 997805
    s7 += s15 * 136657
    s8 -= s15 * 683901

    s2 += s14 * 666643
    s3 += s14 * 470296
    s4 += s14 * 654183
    s5 -= s14 * 997805
    s6 += s14 * 136657
    s7 -= s14 * 683901

    s1 += s13 * 666643
    s2 += s13 * 470296
    s3 += s13 * 654183
    s4 -= s13 * 997805
    s5 += s13 * 136657
    s6 -= s13 * 683901

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901
    s12 = 0

    carry0 = (s0 + (1 shl 20)) shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry2 = (s2 + (1 shl 20)) shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry4 = (s4 + (1 shl 20)) shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry6 = (s6 + (1 shl 20)) shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry8 = (s8 + (1 shl 20)) shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry10 = (s10 + (1 shl 20)) shr 21; s11 += carry10; s10 -= carry10  shl  21;

    carry1 = (s1 + (1 shl 20)) shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry3 = (s3 + (1 shl 20)) shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry5 = (s5 + (1 shl 20)) shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry7 = (s7 + (1 shl 20)) shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry9 = (s9 + (1 shl 20)) shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry11 = (s11 + (1 shl 20)) shr 21; s12 += carry11; s11 -= carry11  shl  21;

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901
    s12 = 0

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10  shl  21;
    carry11 = s11 shr 21; s12 += carry11; s11 -= carry11  shl  21;

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0  shl  21;
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1  shl  21;
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2  shl  21;
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3  shl  21;
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4  shl  21;
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5  shl  21;
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6  shl  21;
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7  shl  21;
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8  shl  21;
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9  shl  21;
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10  shl  21;

    s[0] = (s0 shr 0).toUByte()
    s[1] = (s0 shr 8).toUByte()
    s[2] = ((s0 shr 16) or (s1  shl  5)).toUByte()
    s[3] = (s1 shr 3).toUByte()
    s[4] = (s1 shr 11).toUByte()
    s[5] = ((s1 shr 19) or (s2  shl  2)).toUByte()
    s[6] = (s2 shr 6).toUByte()
    s[7] = ((s2 shr 14) or (s3  shl  7)).toUByte()
    s[8] = (s3 shr 1).toUByte()
    s[9] = (s3 shr 9).toUByte()
    s[10] = ((s3 shr 17) or (s4  shl  4)).toUByte()
    s[11] = (s4 shr 4).toUByte()
    s[12] = (s4 shr 12).toUByte()
    s[13] = ((s4 shr 20) or (s5  shl  1)).toUByte()
    s[14] = (s5 shr 7).toUByte()
    s[15] = ((s5 shr 15) or (s6  shl  6)).toUByte()
    s[16] = (s6 shr 2).toUByte()
    s[17] = (s6 shr 10).toUByte()
    s[18] = ((s6 shr 18) or (s7  shl  3)).toUByte()
    s[19] = (s7 shr 5).toUByte()
    s[20] = (s7 shr 13).toUByte()
    s[21] = (s8 shr 0).toUByte()
    s[22] = (s8 shr 8).toUByte()
    s[23] = ((s8 shr 16) or (s9  shl  5)).toUByte()
    s[24] = (s9 shr 3).toUByte()
    s[25] = (s9 shr 11).toUByte()
    s[26] = ((s9 shr 19) or (s10  shl  2)).toUByte()
    s[27] = (s10 shr 6).toUByte()
    s[28] = ((s10 shr 14) or (s11  shl  7)).toUByte()
    s[29] = (s11 shr 1).toUByte()
    s[30] = (s11 shr 9).toUByte()
    s[31] = (s11 shr 17).toUByte()

    return s
}

fun signum(a: Long) = when {
        a > 0 -> 1L
        a < 0 -> -1L
        else -> 0L
}


/*

4
down vote
accepted
Elliptic curve encryption uses numbers called scalars (which are used as private keys). Valid scalars should be less than the group size of Monero's base point, i.e. the maximum allowable value of a scalar is 2^252 + 27742317777372353535851937790883648492

The sc_check method therefore verifies that the number is not too big. It does so in a strange way so that it runs in constant time. This prevents timing attacks that could leak information about the size of the scalar.

Math.pow(2,252) + 27742317777372353535851937790883648492 ==
1559614444 * Math.pow(2,8*4*0) +
1477600026 * Math.pow(2,8*4*1) +
2734136534 * Math.pow(2,8*4*2)  +
350157278 * Math.pow(2,8*4*3)  +
0 * Math.pow(2,8*4*4)  +
0 * Math.pow(2,8*4*5)  +
0 * Math.pow(2,8*4*6)  +
268435456 * Math.pow(2,8*4*7)
 */
fun sc_check(s: UByteArray): Boolean {
    val s0 = load_4(s).toLong();
    val s1 = load_4(s, 4).toLong();
    val s2 = load_4(s, 8).toLong();
    val s3 = load_4(s, 12).toLong();
    val s4 = load_4(s, 16).toLong();
    val s5 = load_4(s, 20).toLong();
    val s6 = load_4(s, 24).toLong();
    val s7 = load_4(s, 28).toLong();
    return ((signum(1559614444 - s0)
            + (signum(1477600026 - s1) shl 1)
            + (signum(2734136534 - s2) shl 2)
            + (signum(350157278 - s3) shl 3)
            + (signum(-s4) shl 4)
            + (signum(-s5) shl 5)
            + (signum(-s6) shl 6)
            + (signum(268435456 - s7) shl 7))) shr 8 == 0L
}

fun sc_iszero(s: UByteArray) = !sc_isnonzero(s)

fun sc_isnonzero(s: UByteArray): Boolean {
    return ((( (s[0] or s[1] or s[2] or s[3] or s[4] or s[5] or s[6] or s[7] or s[8] or
    s[9] or s[10] or s[11] or s[12] or s[13] or s[14] or s[15] or s[16] or s[17] or
    s[18] or s[19] or s[20] or s[21] or s[22] or s[23] or s[24] or s[25] or s[26] or
    s[27] or s[28] or s[29] or s[30] or s[31]).toInt() - 1) shr 8) + 1) != 0
}


