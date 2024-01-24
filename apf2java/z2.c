/* VSR15+ really should only require APF to be running/filtering when AP CPU is asleep,
   and only on packets that would normally be delivered to the AP.
   Basically APF needs to run only on packets that could/would wake the cpu.
   This also eliminates all throughput requirements. */

/* https://sourceforge.net/p/predef/wiki/Endianness/
 * Big endian     __BIG_ENDIAN__ __ARMEB__ __THUMBEB__ __AARCH64EB__ _MIPSEB __MIPSEB __MIPSEB__
 * __BYTE_ORDER__ __ORDER_BIG_ENDIAN__
 * Little endian  __LITTLE_ENDIAN__ __ARMEL__ __THUMBEL__ __AARCH64EL__ _MIPSEL __MIPSEL __MIPSEL__
 * __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
 */

static u32 read_be16(const u8* buf) {
#if 1
    return buf[0] * 256u + buf[1];
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return *(u16*)buf;  // require unaligned memory access
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return buf[0] * 256u + buf[1];
#else
#error "Unknown Endianness"
    static const union { u16 v; u8 w; } a = { 1 };
    return (a.w == 1) ? buf[0] * 256u + buf[1] : *(u16*)buf;
#endif
}
