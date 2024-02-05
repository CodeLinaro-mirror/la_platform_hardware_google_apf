/*
 * Copyright 2023, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apf_interpreter.h"

/* TODO: Remove the dependency of the standard library and make the interpreter self-contained. */
#include <string.h>/* For memcmp */

typedef enum { false, true } bool;

/* Begin include of apf_defs.h */
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

typedef enum {
  error_program = -2,
  error_packet = -1,
  nomatch = false,
  match = true,
} match_result_type;

#define ETH_P_IP	0x0800
#define ETH_P_IPV6	0x86DD

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP	1
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP	6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP	17
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6	58
#endif

#define ETH_HLEN	14
#define IPV4_HLEN	20
#define IPV6_HLEN	40
#define TCP_HLEN	20
#define UDP_HLEN	8
/* End include of apf_defs.h */
/* Begin include of apf.h */
/*
 * Copyright 2023, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_APF_APF_H
#define ANDROID_APF_APF_H

/* A brief overview of APF:
 *
 * APF machine is composed of:
 *  1. A read-only program consisting of bytecodes as described below.
 *  2. Two 32-bit registers, called R0 and R1.
 *  3. Sixteen 32-bit temporary memory slots (cleared between packets).
 *  4. A read-only packet.
 * The program is executed by the interpreter below and parses the packet
 * to determine if the application processor (AP) should be woken up to
 * handle the packet or if can be dropped.
 *
 * APF bytecode description:
 *
 * The APF interpreter uses big-endian byte order for loads from the packet
 * and for storing immediates in instructions.
 *
 * Each instruction starts with a byte composed of:
 *  Top 5 bits form "opcode" field, see *_OPCODE defines below.
 *  Next 2 bits form "size field", which indicate the length of an immediate
 *  value which follows the first byte.  Values in this field:
 *                 0 => immediate value is 0 and no bytes follow.
 *                 1 => immediate value is 1 byte big.
 *                 2 => immediate value is 2 bytes big.
 *                 3 => immediate value is 4 bytes big.
 *  Bottom bit forms "register" field, which indicates which register this
 *  instruction operates on.
 *
 *  There are three main categories of instructions:
 *  Load instructions
 *    These instructions load byte(s) of the packet into a register.
 *    They load either 1, 2 or 4 bytes, as determined by the "opcode" field.
 *    They load into the register specified by the "register" field.
 *    The immediate value that follows the first byte of the instruction is
 *    the byte offset from the beginning of the packet to load from.
 *    There are "indexing" loads which add the value in R1 to the byte offset
 *    to load from. The "opcode" field determines which loads are "indexing".
 *  Arithmetic instructions
 *    These instructions perform simple operations, like addition, on register
 *    values. The result of these instructions is always written into R0. One
 *    argument of the arithmetic operation is R0's value. The other argument
 *    of the arithmetic operation is determined by the "register" field:
 *            If the "register" field is 0 then the immediate value following
 *            the first byte of the instruction is used as the other argument
 *            to the arithmetic operation.
 *            If the "register" field is 1 then R1's value is used as the other
 *            argument to the arithmetic operation.
 *  Conditional jump instructions
 *    These instructions compare register R0's value with another value, and if
 *    the comparison succeeds, jump (i.e. adjust the program counter). The
 *    immediate value that follows the first byte of the instruction
 *    represents the jump target offset, i.e. the value added to the program
 *    counter if the comparison succeeds. The other value compared is
 *    determined by the "register" field:
 *            If the "register" field is 0 then another immediate value
 *            follows the jump target offset. This immediate value is of the
 *            same size as the jump target offset, and represents the value
 *            to compare against.
 *            If the "register" field is 1 then register R1's value is
 *            compared against.
 *    The type of comparison (e.g. equal to, greater than etc) is determined
 *    by the "opcode" field. The comparison interprets both values being
 *    compared as unsigned values.
 *
 *  Miscellaneous details:
 *
 *  Pre-filled temporary memory slot values
 *    When the APF program begins execution, three of the sixteen memory slots
 *    are pre-filled by the interpreter with values that may be useful for
 *    programs:
 *      Slot #11 contains the size (in bytes) of the APF program.
 *      Slot #12 contains the total size of the APF buffer (program + data).
 *      Slot #13 is filled with the IPv4 header length. This value is calculated
 *               by loading the first byte of the IPv4 header and taking the
 *               bottom 4 bits and multiplying their value by 4. This value is
 *               set to zero if the first 4 bits after the link layer header are
 *               not 4, indicating not IPv4.
 *      Slot #14 is filled with size of the packet in bytes, including the
 *               link-layer header if any.
 *      Slot #15 is filled with the filter age in seconds. This is the number of
 *               seconds since the AP sent the program to the chipset. This may
 *               be used by filters that should have a particular lifetime. For
 *               example, it can be used to rate-limit particular packets to one
 *               every N seconds.
 *  Special jump targets:
 *    When an APF program executes a jump to the byte immediately after the last
 *      byte of the progam (i.e., one byte past the end of the program), this
 *      signals the program has completed and determined the packet should be
 *      passed to the AP.
 *    When an APF program executes a jump two bytes past the end of the program,
 *      this signals the program has completed and determined the packet should
 *      be dropped.
 *  Jump if byte sequence doesn't match:
 *    This is a special instruction to facilitate matching long sequences of
 *    bytes in the packet. Initially it is encoded like a conditional jump
 *    instruction with two exceptions:
 *      The first byte of the instruction is always followed by two immediate
 *        fields: The first immediate field is the jump target offset like other
 *        conditional jump instructions. The second immediate field specifies the
 *        number of bytes to compare.
 *      These two immediate fields are followed by a sequence of bytes. These
 *        bytes are compared with the bytes in the packet starting from the
 *        position specified by the value of the register specified by the
 *        "register" field of the instruction.
 */

/* Number of temporary memory slots, see ldm/stm instructions. */
#define MEMORY_ITEMS 16
/* Upon program execution, some temporary memory slots are prefilled: */

/* Offset inside the output buffer where the next byte of output packet should be written to. */
#define MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET 10
#define MEMORY_OFFSET_PROGRAM_SIZE 11     /* Size of program (in bytes) */
#define MEMORY_OFFSET_DATA_SIZE 12        /* Total size of program + data */
#define MEMORY_OFFSET_IPV4_HEADER_SIZE 13 /* 4*([APF_FRAME_HEADER_SIZE]&15) */
#define MEMORY_OFFSET_PACKET_SIZE 14      /* Size of packet in bytes. */
#define MEMORY_OFFSET_FILTER_AGE 15       /* Age since filter installed in seconds. */


/* Unconditionally pass (if R=0) or drop (if R=1) packet.
 * An optional unsigned immediate value can be provided to encode the counter number.
 * the value is non-zero, the instruction increments the counter.
 * The counter is located (-4 * counter number) bytes from the end of the data region.
 * It is a U32 big-endian value and is always incremented by 1.
 * This is more or less equivalent to: lddw R0, -N4; add R0,1; stdw R0, -N4; {pass,drop}
 * e.g. "pass", "pass 1", "drop", "drop 1".
 */
#define PASSDROP_OPCODE 0
#define LDB_OPCODE 1    /* Load 1 byte from immediate offset, e.g. "ldb R0, [5]" */
#define LDH_OPCODE 2    /* Load 2 bytes from immediate offset, e.g. "ldh R0, [5]" */
#define LDW_OPCODE 3    /* Load 4 bytes from immediate offset, e.g. "ldw R0, [5]" */
#define LDBX_OPCODE 4   /* Load 1 byte from immediate offset plus register, e.g. "ldbx R0, [5+R0]" */
#define LDHX_OPCODE 5   /* Load 2 byte from immediate offset plus register, e.g. "ldhx R0, [5+R0]" */
#define LDWX_OPCODE 6   /* Load 4 byte from immediate offset plus register, e.g. "ldwx R0, [5+R0]" */
#define ADD_OPCODE 7    /* Add, e.g. "add R0,5" */
#define MUL_OPCODE 8    /* Multiply, e.g. "mul R0,5" */
#define DIV_OPCODE 9    /* Divide, e.g. "div R0,5" */
#define AND_OPCODE 10   /* And, e.g. "and R0,5" */
#define OR_OPCODE 11    /* Or, e.g. "or R0,5" */
#define SH_OPCODE 12    /* Left shift, e.g. "sh R0, 5" or "sh R0, -5" (shifts right) */
#define LI_OPCODE 13    /* Load signed immediate, e.g. "li R0,5" */
#define JMP_OPCODE 14   /* Unconditional jump, e.g. "jmp label" */
#define JEQ_OPCODE 15   /* Compare equal and branch, e.g. "jeq R0,5,label" */
#define JNE_OPCODE 16   /* Compare not equal and branch, e.g. "jne R0,5,label" */
#define JGT_OPCODE 17   /* Compare greater than and branch, e.g. "jgt R0,5,label" */
#define JLT_OPCODE 18   /* Compare less than and branch, e.g. "jlt R0,5,label" */
#define JSET_OPCODE 19  /* Compare any bits set and branch, e.g. "jset R0,5,label" */
#define JNEBS_OPCODE 20 /* Compare not equal byte sequence, e.g. "jnebs R0,5,label,0x1122334455" */
#define EXT_OPCODE 21   /* Immediate value is one of *_EXT_OPCODE */
#define LDDW_OPCODE 22  /* Load 4 bytes from data address (register + simm): "lddw R0, [5+R1]" */
#define STDW_OPCODE 23  /* Store 4 bytes to data address (register + simm): "stdw R0, [5+R1]" */
/* Write 1, 2 or 4 bytes immediate to the output buffer and auto-increment the pointer to
 * write. e.g. "write 5"
 */
#define WRITE_OPCODE 24
/* Copy bytes from input packet/APF program/data region to output buffer and
 * auto-increment the output buffer pointer.
 * Register bit is used to specify the source of data copy.
 * R=0 means copy from packet.
 * R=1 means copy from APF program/data region.
 * The copy length is stored in (u8)imm2.
 * e.g. "pktcopy 5, 5" "datacopy 5, 5"
 */
#define PKTDATACOPY_OPCODE 25

/* Extended opcodes. These all have an opcode of EXT_OPCODE */
/* and specify the actual opcode in the immediate field. */
#define LDM_EXT_OPCODE 0   /* Load from temporary memory, e.g. "ldm R0,5" */
  /* Values 0-15 represent loading the different temporary memory slots. */
#define STM_EXT_OPCODE 16  /* Store to temporary memory, e.g. "stm R0,5" */
  /* Values 16-31 represent storing to the different temporary memory slots. */
#define NOT_EXT_OPCODE 32  /* Not, e.g. "not R0" */
#define NEG_EXT_OPCODE 33  /* Negate, e.g. "neg R0" */
#define SWAP_EXT_OPCODE 34 /* Swap, e.g. "swap R0,R1" */
#define MOV_EXT_OPCODE 35  /* Move, e.g. "move R0,R1" */


/* Allocate writable output buffer.
 * R=0, use register R0 to store the length. R=1, encode the length in the u16 int imm2.
 * "e.g. allocate R0"
 * "e.g. allocate 123"
 */
#define ALLOCATE_EXT_OPCODE 36
/* Transmit and deallocate the buffer (transmission can be delayed until the program
 * terminates). R=0 means discard the buffer, R=1 means transmit the buffer.
 * "e.g. trans"
 * "e.g. discard"
 */
#define TRANSMITDISCARD_EXT_OPCODE 37
/* Write 1, 2 or 4 byte value from register to the output buffer and auto-increment the
 * output buffer pointer.
 * e.g. "ewrite1 r0"
 */
#define EWRITE1_EXT_OPCODE 38
#define EWRITE2_EXT_OPCODE 39
#define EWRITE4_EXT_OPCODE 40
/* Copy bytes from input packet/APF program/data region to output buffer and
 * auto-increment the output buffer pointer.
 * The copy src offset is stored in R0.
 * when R=0, the copy length is stored in (u8)imm2.
 * when R=1, the copy length is stored in R1.
 * e.g. "pktcopy r0, 5", "pktcopy r0, r1", "datacopy r0, 5", "datacopy r0, r1"
 */
#define EPKTCOPY_EXT_OPCODE 41
#define EDATACOPY_EXT_OPCODE 42
/* Jumps if the UDP payload content (starting at R0) does not contain the specified QNAME,
 * applying MDNS case insensitivity.
 * R0: Offset to UDP payload content
 * imm1: Opcode
 * imm2: Label offset
 * imm3(u8): Question type (PTR/SRV/TXT/A/AAAA)
 * imm4(bytes): TLV-encoded QNAME list (null-terminated)
 * e.g.: "jdnsqmatch R0,label,0x0c,\002aa\005local\0\0"
 */
#define JDNSQMATCH_EXT_OPCODE 43
/* Jumps if the UDP payload content (starting at R0) does not contain one
 * of the specified NAMEs in answers/authority/additional records, applying
 * case insensitivity.
 * R=0/1 meaning 'does not match'/'matches'
 * R0: Offset to UDP payload content
 * imm1: Opcode
 * imm2: Label offset
 * imm3(bytes): TLV-encoded QNAME list (null-terminated)
 * e.g.: "jdnsamatch R0,label,0x0c,\002aa\005local\0\0"
 */
#define JDNSAMATCH_EXT_OPCODE 44

#define EXTRACT_OPCODE(i) (((i) >> 3) & 31)
#define EXTRACT_REGISTER(i) ((i) & 1)
#define EXTRACT_IMM_LENGTH(i) (((i) >> 1) & 3)

#endif  /* ANDROID_APF_APF_H */
/* End include of apf.h */
/* Begin include of apf_utils.h */
static u32 read_be16(const u8* buf) {
    return buf[0] * 256u + buf[1];
}

static void store_be16(u8* const buf, const u16 v) {
    buf[0] = (u8)(v >> 8);
    buf[1] = (u8)v;
}

static u8 uppercase(u8 c) {
    return (c >= 'a') && (c <= 'z') ? c - ('a' - 'A') : c;
}
/* End include of apf_utils.h */
/* Begin include of apf_dns.h */
/**
 * Compares a (Q)NAME starting at udp[*ofs] with the target name.
 *
 * @param needle - non-NULL - pointer to DNS encoded target name to match against.
 *   example: [11]_googlecast[4]_tcp[5]local[0]  (where [11] is a byte with value 11)
 * @param needle_bound - non-NULL - points at first invalid byte past needle.
 * @param udp - non-NULL - pointer to the start of the UDP payload (DNS header).
 * @param udp_len - length of the UDP payload.
 * @param ofs - non-NULL - pointer to the offset of the beginning of the (Q)NAME.
 *   On non-error return will be updated to point to the first unread offset,
 *   ie. the next position after the (Q)NAME.
 *
 * @return 1 if matched, 0 if not matched, -1 if error in packet, -2 if error in program.
 */
match_result_type match_single_name(const u8* needle,
                                    const u8* const needle_bound,
                                    const u8* const udp,
                                    const u32 udp_len,
                                    u32* const ofs) {
    u32 first_unread_offset = *ofs;
    bool is_qname_match = true;
    int lvl;

    /* DNS names are <= 255 characters including terminating 0, since >= 1 char + '.' per level => max. 127 levels */
    for (lvl = 1; lvl <= 127; ++lvl) {
        if (*ofs >= udp_len) return error_packet;
        u8 v = udp[(*ofs)++];
        if (v >= 0xC0) { /* RFC 1035 4.1.4 - handle message compression */
            if (*ofs >= udp_len) return error_packet;
            u8 w = udp[(*ofs)++];
            if (*ofs > first_unread_offset) first_unread_offset = *ofs;
            u32 new_ofs = (v - 0xC0) * 256 + w;
            if (new_ofs >= *ofs) return error_packet;  /* RFC 1035 4.1.4 allows only backward pointers */
            *ofs = new_ofs;
        } else if (v > 63) {
            return error_packet;  /* RFC 1035 2.3.4 - label size is 1..63. */
        } else if (v) {
            u8 label_size = v;
            if (*ofs + label_size > udp_len) return error_packet;
            if (needle >= needle_bound) return error_program;
            if (is_qname_match && label_size == *needle++) {
                if (needle + label_size > needle_bound) return error_program;
                while (label_size--) {
                    u8 w = udp[(*ofs)++];
                    is_qname_match &= (uppercase(w) == *needle++);
                }
            } else {
                *ofs += label_size;
                is_qname_match = false;
            }
        } else { /* reached the end of the name */
            if (first_unread_offset > *ofs) *ofs = first_unread_offset;
            return (is_qname_match && *needle == 0) ? match : nomatch;
        }
    }
    return error_packet;  /* too many dns domain name levels */
}

/**
 * Check if DNS packet contains any of the target names with the provided
 * question_type.
 *
 * @param needles - non-NULL - pointer to DNS encoded target nameS to match against.
 *   example: [3]foo[3]com[0][3]bar[3]net[0][0]  -- note ends with an extra NULL byte.
 * @param needle_bound - non-NULL - points at first invalid byte past needles.
 * @param udp - non-NULL - pointer to the start of the UDP payload (DNS header).
 * @param udp_len - length of the UDP payload.
 * @param question_type - question type to match against or -1 to match answers.
 *
 * @return 1 if matched, 0 if not matched, -1 if error in packet, -2 if error in program.
 */
match_result_type match_names(const u8* needles,
                              const u8* const needle_bound,
                              const u8* const udp,
                              const u32 udp_len,
                              const int question_type) {
    if (udp_len < 12) return error_packet;  /* lack of dns header */

    /* dns header: be16 tid, flags, num_{questions,answers,authority,additional} */
    u32 num_questions = read_be16(udp + 4);
    u32 num_answers = read_be16(udp + 6) + read_be16(udp + 8) + read_be16(udp + 10);

    /* loop until we hit final needle, which is a null byte */
    while (true) {
        if (needles >= needle_bound) return error_program;
        if (!*needles) return nomatch;  /* we've run out of needles without finding a match */
        u32 ofs = 12;  /* dns header is 12 bytes */
        u32 i;
        /* match questions */
        for (i = 0; i < num_questions; ++i) {
            match_result_type m = match_single_name(needles, needle_bound, udp, udp_len, &ofs);
            if (m < nomatch) return m;
            if (ofs + 2 > udp_len) return error_packet;
            int qtype = (int)read_be16(udp + ofs);
            ofs += 4; /* skip be16 qtype & qclass */
            if (question_type == -1) continue;
            if (m == nomatch) continue;
            if (qtype == 0xFF /* QTYPE_ANY */ || qtype == question_type) return match;
        }
        /* match answers */
        if (question_type == -1) for (i = 0; i < num_answers; ++i) {
            match_result_type m = match_single_name(needles, needle_bound, udp, udp_len, &ofs);
            if (m < nomatch) return m;
            ofs += 8; /* skip be16 type, class & be32 ttl */
            if (ofs + 2 > udp_len) return error_packet;
            ofs += 2 + read_be16(udp + ofs);  /* skip be16 rdata length field, plus length bytes */
            if (m == match) return match;
        }
        /* move needles pointer to the next needle. */
        do {
            u8 len = *needles++;
            if (len > 63) return error_program;
            needles += len;
            if (needles >= needle_bound) return error_program;
        } while (*needles);
        needles++;  /* skip the NULL byte at the end of *a* DNS name */
    }
}
/* End include of apf_dns.h */
/* Begin include of apf_checksum.h */
/**
 * Calculate big endian 16-bit sum of a buffer (max 128kB),
 * then fold and negate it, producing a 16-bit result in [0..FFFE].
 */
u16 calc_csum(u32 sum, const u8* const buf, const s32 len) {
    s32 i;
    for (i = 0; i < len; ++i) sum += buf[i] * ((i & 1) ? 1 : 256);

    sum = (sum & 0xFFFF) + (sum >> 16);  /* max after this is 1FFFE */
    u16 csum = sum + (sum >> 16);
    return ~csum;  /* assuming sum > 0 on input, this is in [0..FFFE] */
}

static u16 fix_udp_csum(u16 csum) {
    return csum ? csum : 0xFFFF;
}

/**
 * Calculate the ipv4 header and tcp/udp layer 4 checksums.
 * (assumes IPv4 checksum field is set to partial sum of ipv4 options [likely 0])
 * (assumes L4 checksum field is set to L4 payload length on input)
 * Warning: TCP/UDP L4 checksum corrupts packet iff ipv4 options are present.
 * Warning: first IPV4_HLEN + TCP_HLEN == 40 bytes of ip4_pkt must be writable!
 * Returns 6-bit DSCP value [0..63], garbage on parse error.
 */
static int calc_ipv4_csum(u8* const ip4_pkt, const s32 len) {
    store_be16(ip4_pkt + 10, calc_csum(0xFFFF, ip4_pkt, IPV4_HLEN));

    u8 proto = ip4_pkt[9];
    u16 csum = calc_csum(proto, ip4_pkt + 12, len - 12);
    switch (proto) {
      case IPPROTO_ICMP:
        /* Note: for this to work, the icmpv4 checksum field must be prefilled
         * with non-zero negative sum of proto (1) and src/dst ips, ie:
         * 5 * 0xFFFF - 1 - (src >> 16) - (src & 0xFFFF) - (dst >> 16) - (dst & 0xFFFF)
         */
        store_be16(ip4_pkt + IPV4_HLEN + 2, csum);
        break;
      case IPPROTO_TCP:
        store_be16(ip4_pkt + IPV4_HLEN + 16, csum);
        break;
      case IPPROTO_UDP:
        store_be16(ip4_pkt + IPV4_HLEN + 6, fix_udp_csum(csum));
        break;
    }
    return ip4_pkt[1] >> 2;  /* DSCP */
}

/**
 * Calculate the ipv6 icmp6/tcp/udp layer 4 checksums.
 * (assumes L4 checksum field is set to L4 payload length on input)
 * Warning: first IPV6_HLEN + TCP_HLEN == 60 bytes of ip6_pkt must be writable!
 * Returns 6-bit DSCP value [0..63], garbage on parse error.
 */
static int calc_ipv6_csum(u8* const ip6_pkt, const s32 len) {
    u8 proto = ip6_pkt[6];
    u16 csum = calc_csum(proto, ip6_pkt + 8, len - 8);
    switch (proto) {
      case IPPROTO_ICMPV6:
        store_be16(ip6_pkt + IPV6_HLEN + 2, csum);
        break;
      case IPPROTO_TCP:
        store_be16(ip6_pkt + IPV6_HLEN + 16, csum);
        break;
      case IPPROTO_UDP:
        store_be16(ip6_pkt + IPV6_HLEN + 6, fix_udp_csum(csum));
        break;
    }
    return (read_be16(ip6_pkt) >> 6) & 0x3F;  /* DSCP */
}

/**
 * Calculate and store packet checksums and return dscp.
 *
 * @param pkt - pointer to the start of the ethernet header of the packet.
 *     WARNING: first ETHER_HLEN + max(IPV{4,6}_HLEN) + TCP_HLEN = 74 bytes
 *              of buffer pointed to my 'pkt' pointer *MUST* be writable.
 * @param len - length of the packet.
 *
 * @return 6-bit DSCP value [0..63], garbage on parse error.
 */
int calculate_checksum_and_return_dscp(u8* const pkt, const s32 len) {
    switch (read_be16(pkt + 12)) {  /* ethertype */
      case ETH_P_IP:   return calc_ipv4_csum(pkt + ETH_HLEN, len - ETH_HLEN);
      case ETH_P_IPV6: return calc_ipv6_csum(pkt + ETH_HLEN, len - ETH_HLEN);
      default: return 0;
    }
}
/* End include of apf_checksum.h */

/* User hook for interpreter debug tracing. */
#ifdef APF_TRACE_HOOK
extern void APF_TRACE_HOOK(u32 pc, const u32* regs, const u8* program,
                           u32 program_len, const u8 *packet, u32 packet_len,
                           const u32* memory, u32 ram_len);
#else
#define APF_TRACE_HOOK(pc, regs, program, program_len, packet, packet_len, memory, memory_len) \
    do { /* nop*/                                                                              \
    } while (0)
#endif

/* Frame header size should be 14 */
#define APF_FRAME_HEADER_SIZE 14
/* Return code indicating "packet" should accepted. */
#define PASS_PACKET 1
/* Return code indicating "packet" should be dropped. */
#define DROP_PACKET 0
/* Verify an internal condition and accept packet if it fails. */
#define ASSERT_RETURN(c) if (!(c)) return PASS_PACKET
/* If "c" is of an unsigned type, generate a compile warning that gets promoted to an error. */
/* This makes bounds checking simpler because ">= 0" can be avoided. Otherwise adding */
/* superfluous ">= 0" with unsigned expressions generates compile warnings. */
#define ENFORCE_UNSIGNED(c) ((c)==(u32)(c))

u32 apf_version(void) {
    return 20240124;
}

int apf_run(void* ctx, u8* const program, const u32 program_len,
            const u32 ram_len, const u8* const packet,
            const u32 packet_len, const u32 filter_age_16384ths) {
/* Is offset within program bounds? */
#define IN_PROGRAM_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < program_len)
/* Is offset within ram bounds? */
#define IN_RAM_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < ram_len)
/* Is offset within packet bounds? */
#define IN_PACKET_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < packet_len)
/* Is access to offset |p| length |size| within data bounds? */
#define IN_DATA_BOUNDS(p, size) (ENFORCE_UNSIGNED(p) && \
                                 ENFORCE_UNSIGNED(size) && \
                                 (p) + (size) <= ram_len && \
                                 (p) >= program_len && \
                                 (p) + (size) >= (p))  /* catch wraparounds */
/* Accept packet if not within program bounds */
#define ASSERT_IN_PROGRAM_BOUNDS(p) ASSERT_RETURN(IN_PROGRAM_BOUNDS(p))
/* Accept packet if not within ram bounds */
#define ASSERT_IN_RAM_BOUNDS(p) ASSERT_RETURN(IN_RAM_BOUNDS(p))
/* Accept packet if not within packet bounds */
#define ASSERT_IN_PACKET_BOUNDS(p) ASSERT_RETURN(IN_PACKET_BOUNDS(p))
/* Accept packet if not within data bounds */
#define ASSERT_IN_DATA_BOUNDS(p, size) ASSERT_RETURN(IN_DATA_BOUNDS(p, size))

  /* Program counter. */
  u32 pc = 0;
/* Accept packet if not within program or not ahead of program counter */
#define ASSERT_FORWARD_IN_PROGRAM(p) ASSERT_RETURN(IN_PROGRAM_BOUNDS(p) && (p) >= pc)
  /* Memory slot values. */
  u32 memory[MEMORY_ITEMS] = {};
  /* Fill in pre-filled memory slot values. */
  memory[MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET] = 0;
  memory[MEMORY_OFFSET_PROGRAM_SIZE] = program_len;
  memory[MEMORY_OFFSET_DATA_SIZE] = ram_len;
  memory[MEMORY_OFFSET_PACKET_SIZE] = packet_len;
  memory[MEMORY_OFFSET_FILTER_AGE] = filter_age_16384ths >> 14;
  ASSERT_IN_PACKET_BOUNDS(APF_FRAME_HEADER_SIZE);
  /* Only populate if IP version is IPv4. */
  if ((packet[APF_FRAME_HEADER_SIZE] & 0xf0) == 0x40) {
      memory[MEMORY_OFFSET_IPV4_HEADER_SIZE] = (packet[APF_FRAME_HEADER_SIZE] & 15) * 4;
  }
  /* Register values. */
  u32 registers[2] = {};
  /* Count of instructions remaining to execute. This is done to ensure an */
  /* upper bound on execution time. It should never be hit and is only for */
  /* safety. Initialize to the number of bytes in the program which is an */
  /* upper bound on the number of instructions in the program. */
  u32 instructions_remaining = program_len;

  /* The output buffer pointer */
  u8* allocated_buffer = NULL;
  /* The length of the output buffer */
  u32 allocated_buffer_len = 0;
/* Is access to offset |p| length |size| within output buffer bounds? */
#define IN_OUTPUT_BOUNDS(p, size) (ENFORCE_UNSIGNED(p) && \
                                 ENFORCE_UNSIGNED(size) && \
                                 (p) + (size) <= allocated_buffer_len && \
                                 (p) + (size) >= (p))
/* Accept packet if not write within allocated output buffer */
#define ASSERT_IN_OUTPUT_BOUNDS(p, size) ASSERT_RETURN(IN_OUTPUT_BOUNDS(p, size))

/* Decode the imm length. */
#define DECODE_IMM(value, length)                                              \
    do {                                                                       \
        ASSERT_FORWARD_IN_PROGRAM(pc + length - 1);                            \
        value = 0;                                                             \
        u32 i;                                                            \
        for (i = 0; i < (length) && pc < program_len; i++)                     \
            value = (value << 8) | program[pc++];                              \
    } while (0)

  do {
      APF_TRACE_HOOK(pc, registers, program, program_len, packet, packet_len, memory, ram_len);
      if (pc == program_len) {
          return PASS_PACKET;
      } else if (pc == (program_len + 1)) {
          return DROP_PACKET;
      }
      ASSERT_IN_PROGRAM_BOUNDS(pc);
      const u8 bytecode = program[pc++];
      const u32 opcode = EXTRACT_OPCODE(bytecode);
      const u32 reg_num = EXTRACT_REGISTER(bytecode);
#define REG (registers[reg_num])
#define OTHER_REG (registers[reg_num ^ 1])
      /* All instructions have immediate fields, so load them now. */
      const u32 len_field = EXTRACT_IMM_LENGTH(bytecode);
      u32 imm = 0;
      s32 signed_imm = 0;
      if (len_field != 0) {
          const u32 imm_len = 1 << (len_field - 1);
          ASSERT_FORWARD_IN_PROGRAM(pc + imm_len - 1);
          DECODE_IMM(imm, imm_len);
          /* Sign extend imm into signed_imm. */
          signed_imm = (s32) (imm << ((4 - imm_len) * 8));
          signed_imm >>= (4 - imm_len) * 8;
      }

      switch (opcode) {
          case LDB_OPCODE:
          case LDH_OPCODE:
          case LDW_OPCODE:
          case LDBX_OPCODE:
          case LDHX_OPCODE:
          case LDWX_OPCODE: {
              u32 offs = imm;
              if (opcode >= LDBX_OPCODE) {
                  /* Note: this can overflow and actually decrease offs. */
                  offs += registers[1];
              }
              ASSERT_IN_PACKET_BOUNDS(offs);
              u32 load_size = 0;
              switch (opcode) {
                  case LDB_OPCODE:
                  case LDBX_OPCODE:
                    load_size = 1;
                    break;
                  case LDH_OPCODE:
                  case LDHX_OPCODE:
                    load_size = 2;
                    break;
                  case LDW_OPCODE:
                  case LDWX_OPCODE:
                    load_size = 4;
                    break;
                  /* Immediately enclosing switch statement guarantees */
                  /* opcode cannot be any other value. */
              }
              const u32 end_offs = offs + (load_size - 1);
              /* Catch overflow/wrap-around. */
              ASSERT_RETURN(end_offs >= offs);
              ASSERT_IN_PACKET_BOUNDS(end_offs);
              u32 val = 0;
              while (load_size--)
                  val = (val << 8) | packet[offs++];
              REG = val;
              break;
          }
          case JMP_OPCODE:
              /* This can jump backwards. Infinite looping prevented by instructions_remaining. */
              pc += imm;
              break;
          case JEQ_OPCODE:
          case JNE_OPCODE:
          case JGT_OPCODE:
          case JLT_OPCODE:
          case JSET_OPCODE:
          case JNEBS_OPCODE: {
              /* Load second immediate field. */
              u32 cmp_imm = 0;
              if (reg_num == 1) {
                  cmp_imm = registers[1];
              } else if (len_field != 0) {
                  u32 cmp_imm_len = 1 << (len_field - 1);
                  ASSERT_FORWARD_IN_PROGRAM(pc + cmp_imm_len - 1);
                  DECODE_IMM(cmp_imm, cmp_imm_len);
              }
              switch (opcode) {
                  case JEQ_OPCODE:  if (registers[0] == cmp_imm) pc += imm; break;
                  case JNE_OPCODE:  if (registers[0] != cmp_imm) pc += imm; break;
                  case JGT_OPCODE:  if (registers[0] >  cmp_imm) pc += imm; break;
                  case JLT_OPCODE:  if (registers[0] <  cmp_imm) pc += imm; break;
                  case JSET_OPCODE: if (registers[0] &  cmp_imm) pc += imm; break;
                  case JNEBS_OPCODE: {
                      /* cmp_imm is size in bytes of data to compare. */
                      /* pc is offset of program bytes to compare. */
                      /* imm is jump target offset. */
                      /* REG is offset of packet bytes to compare. */
                      ASSERT_FORWARD_IN_PROGRAM(pc + cmp_imm - 1);
                      ASSERT_IN_PACKET_BOUNDS(REG);
                      const u32 last_packet_offs = REG + cmp_imm - 1;
                      ASSERT_RETURN(last_packet_offs >= REG);
                      ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
                      if (memcmp(program + pc, packet + REG, cmp_imm))
                          pc += imm;
                      /* skip past comparison bytes */
                      pc += cmp_imm;
                      break;
                  }
              }
              break;
          }
          case ADD_OPCODE: registers[0] += reg_num ? registers[1] : imm; break;
          case MUL_OPCODE: registers[0] *= reg_num ? registers[1] : imm; break;
          case AND_OPCODE: registers[0] &= reg_num ? registers[1] : imm; break;
          case OR_OPCODE:  registers[0] |= reg_num ? registers[1] : imm; break;
          case DIV_OPCODE: {
              const u32 div_operand = reg_num ? registers[1] : imm;
              ASSERT_RETURN(div_operand);
              registers[0] /= div_operand;
              break;
          }
          case SH_OPCODE: {
              const s32 shift_val = reg_num ? (s32)registers[1] : signed_imm;
              if (shift_val > 0)
                  registers[0] <<= shift_val;
              else
                  registers[0] >>= -shift_val;
              break;
          }
          case LI_OPCODE:
              REG = (u32) signed_imm;
              break;
          case EXT_OPCODE:
              if (
/* If LDM_EXT_OPCODE is 0 and imm is compared with it, a compiler error will result, */
/* instead just enforce that imm is unsigned (so it's always greater or equal to 0). */
#if LDM_EXT_OPCODE == 0
                  ENFORCE_UNSIGNED(imm) &&
#else
                  imm >= LDM_EXT_OPCODE &&
#endif
                  imm < (LDM_EXT_OPCODE + MEMORY_ITEMS)) {
                REG = memory[imm - LDM_EXT_OPCODE];
              } else if (imm >= STM_EXT_OPCODE && imm < (STM_EXT_OPCODE + MEMORY_ITEMS)) {
                memory[imm - STM_EXT_OPCODE] = REG;
              } else switch (imm) {
                  case NOT_EXT_OPCODE: REG = ~REG;      break;
                  case NEG_EXT_OPCODE: REG = -REG;      break;
                  case MOV_EXT_OPCODE: REG = OTHER_REG; break;
                  case SWAP_EXT_OPCODE: {
                    u32 tmp = REG;
                    REG = OTHER_REG;
                    OTHER_REG = tmp;
                    break;
                  }
                  case ALLOCATE_EXT_OPCODE:
                    ASSERT_RETURN(allocated_buffer == NULL);
                    if (reg_num == 0) {
                        allocated_buffer_len = REG;
                    } else {
                        DECODE_IMM(allocated_buffer_len, 2);
                    }
                    /* checksumming functions requires minimum 74 byte buffer for correctness */
                    if (allocated_buffer_len < 74) allocated_buffer_len = 74;
                    allocated_buffer = apf_allocate_buffer(ctx, allocated_buffer_len);
                    ASSERT_RETURN(allocated_buffer != NULL);
                    memset(allocated_buffer, 0, allocated_buffer_len);
                    memory[MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET] = 0;
                    break;
                  case TRANSMITDISCARD_EXT_OPCODE:
                    ASSERT_RETURN(allocated_buffer != NULL);
                    u32 pkt_len = memory[MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET];
                    /* If pkt_len > allocate_buffer_len, it means sth. wrong */
                    /* happened and the allocated_buffer should be deallocated. */
                    if (pkt_len > allocated_buffer_len) {
                        apf_transmit_buffer(ctx, allocated_buffer, 0 /* len */, 0 /* dscp */);
                        allocated_buffer = NULL;
                        allocated_buffer_len = 0;
                        return PASS_PACKET;
                    }
                    /* allocated_buffer_len cannot be large because we'd run out of RAM, */
                    /* so the above unsigned comparison effectively guarantees casting pkt_len */
                    /* to a signed value does not result in it going negative. */
                    int dscp = calculate_checksum_and_return_dscp(allocated_buffer, (s32)pkt_len);
                    int ret = apf_transmit_buffer(ctx, allocated_buffer, pkt_len, dscp);
                    allocated_buffer = NULL;
                    allocated_buffer_len = 0;
                    if (ret) {
                      return PASS_PACKET;
                    }
                    break;
                  case JDNSQMATCH_EXT_OPCODE: {
                    const u32 imm_len = 1 << (len_field - 1);
                    u32 jump_offs;
                    DECODE_IMM(jump_offs, imm_len);
                    int qtype;
                    DECODE_IMM(qtype, 1);
                    u32 udp_payload_offset = registers[0];
                    int match_rst = match_names(program + pc,
                                                program + program_len,
                                                packet + udp_payload_offset,
                                                packet_len - udp_payload_offset,
                                                qtype);
                    if (match_rst == -1) return PASS_PACKET;
                    while (!(program[pc] == 0 && program[pc + 1] == 0)) {
                        pc++;
                    }
                    pc += 2;
                    if (reg_num == 0 && match_rst == 0) {
                        pc += jump_offs;
                    } else if (reg_num == 1 && match_rst == 1) {
                        pc += jump_offs;
                    }
                    break;
                  }
                  default:  /* Unknown extended opcode */
                    return PASS_PACKET;  /* Bail out */
              }
              break;
          case LDDW_OPCODE: {
              u32 offs = OTHER_REG + (u32)signed_imm;
              u32 size = 4;
              u32 val = 0;
              /* Negative offsets wrap around the end of the address space. */
              /* This allows us to efficiently access the end of the */
              /* address space with one-byte immediates without using %=. */
              if (offs & 0x80000000) {
                  offs = ram_len + offs;  /* unsigned overflow intended */
              }
              ASSERT_IN_DATA_BOUNDS(offs, size);
              while (size--)
                  val = (val << 8) | program[offs++];
              REG = val;
              break;
          }
          case STDW_OPCODE: {
              u32 offs = OTHER_REG + (u32)signed_imm;
              u32 size = 4;
              u32 val = REG;
              /* Negative offsets wrap around the end of the address space. */
              /* This allows us to efficiently access the end of the */
              /* address space with one-byte immediates without using %=. */
              if (offs & 0x80000000) {
                  offs = ram_len + offs;  /* unsigned overflow intended */
              }
              ASSERT_IN_DATA_BOUNDS(offs, size);
              while (size--) {
                  program[offs++] = (val >> 24);
                  val <<= 8;
              }
              break;
          }
          case WRITE_OPCODE: {
              ASSERT_RETURN(allocated_buffer != NULL);
              ASSERT_RETURN(len_field > 0);
              u32 offs = memory[MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET];
              const u32 write_len = 1 << (len_field - 1);
              ASSERT_RETURN(write_len > 0);
              ASSERT_IN_OUTPUT_BOUNDS(offs, write_len);
              u32 i;
              for (i = 0; i < write_len; ++i) {
                  *(allocated_buffer + offs) =
                      (u8) ((imm >> (write_len - 1 - i) * 8) & 0xff);
                  offs++;
              }
              memory[MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET] = offs;
              break;
          }
          case PKTDATACOPY_OPCODE: {
              ASSERT_RETURN(allocated_buffer != NULL);
              u32 src_offs = imm;
              u32 copy_len;
              DECODE_IMM(copy_len, 1);
              u32 dst_offs = memory[MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET];
              ASSERT_IN_OUTPUT_BOUNDS(dst_offs, copy_len);
              /* reg_num == 0 copy from packet, reg_num == 1 copy from data. */
              if (reg_num == 0) {
                  ASSERT_IN_PACKET_BOUNDS(src_offs);
                  const u32 last_packet_offs = src_offs + copy_len - 1;
                  ASSERT_RETURN(last_packet_offs >= src_offs);
                  ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
                  memmove(allocated_buffer + dst_offs, packet + src_offs, copy_len);
              } else {
                  ASSERT_IN_RAM_BOUNDS(src_offs + copy_len - 1);
                  memmove(allocated_buffer + dst_offs, program + src_offs, copy_len);
              }
              dst_offs += copy_len;
              memory[MEMORY_OFFSET_OUTPUT_BUFFER_OFFSET] = dst_offs;
              break;
          }
          default:  /* Unknown opcode */
              return PASS_PACKET;  /* Bail out */
      }
  } while (instructions_remaining--);
  return PASS_PACKET;
}
