/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef APF_GENERATOR_H
#define APF_GENERATOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define APF_VERSION_61  6100

/* Bitmask flags for slot #7 (APF_MEM_INTERNAL_STATE): */
#define APF_INTERNAL_STATE_SUSPENDED 1

enum apf_mem_slot {
    APF_MEM_INTERNAL_STATE = 7,
    APF_MEM_APF_VERSION = 8,
    APF_MEM_FILTER_AGE_16384THS = 9,
    APF_MEM_TX_BUF_OFFSET = 10,
    APF_MEM_PROGRAM_SIZE = 11,
    APF_MEM_DATA_SIZE = 12,
    APF_MEM_IPV4_HEADER_SIZE = 13,
    APF_MEM_PACKET_SIZE = 14,
    APF_MEM_FILTER_AGE = 15,
};

enum apf_register {
    APF_REG_R0 = 0,
    APF_REG_R1 = 1,
};

enum apf_gen_err {
    APF_GEN_OK = 0,
    APF_GEN_ERR_INVALID_ARGUMENT,
    APF_GEN_ERR_OUT_OF_MEMORY,
    APF_GEN_ERR_LABEL_LIMIT,
    APF_GEN_ERR_DUPLICATE_LABEL,
    APF_GEN_ERR_UNDEFINED_LABEL,
    APF_GEN_ERR_DATA_OVERFLOW,
    APF_GEN_ERR_RAM_OVERFLOW,
    APF_GEN_ERR_BUFFER_TOO_SMALL,
    APF_GEN_ERR_ALREADY_GENERATED,
};

typedef struct {
    int16_t id;
} apf_label;

static const apf_label APF_LABEL_INVALID = { -1 };
static const apf_label APF_LABEL_PASS    = { 0 };
static const apf_label APF_LABEL_DROP    = { 1 };

enum {
    APF_COUNTER_ENDIANNESS = 1,
    APF_COUNTER_TOTAL_PACKETS = 2,
    APF_COUNTER_PASSED_ALLOCATE_FAILURE = 3,
    APF_COUNTER_PASSED_TRANSMIT_FAILURE = 4,
    APF_COUNTER_CORRUPT_DNS_PACKET = 5,
    APF_COUNTER_EXCEPTIONS = 6,
    APF_COUNTER_MIN_USER = 7,
    APF_COUNTER_MAX = 16383,
};

/*
 * Opaque handle for an APF bytecode generator instance.
 *
 * Builder functions return 0 on success (or a non-negative data offset for
 * apf_gen_find_or_append_data) and -1 on error. Errors are sticky and can be
 * queried with apf_gen_get_error(). Adding instructions or labels after
 * apf_gen_generate() has been called is forbidden.
 */
struct apf_generator;

struct apf_generator *apf_generator_alloc(uint32_t apf_version, uint32_t ram_len);
void apf_generator_free(struct apf_generator *gen);

/* Packet Load Instructions */
int apf_gen_add_ldb(struct apf_generator *gen, enum apf_register reg, uint32_t offset);
int apf_gen_add_ldh(struct apf_generator *gen, enum apf_register reg, uint32_t offset);
int apf_gen_add_ldw(struct apf_generator *gen, enum apf_register reg, uint32_t offset);
int apf_gen_add_ldbx(struct apf_generator *gen, enum apf_register reg, uint32_t offset);
int apf_gen_add_ldhx(struct apf_generator *gen, enum apf_register reg, uint32_t offset);
int apf_gen_add_ldwx(struct apf_generator *gen, enum apf_register reg, uint32_t offset);

/* Jump, Data, and Conditional Branch Instructions */
apf_label apf_gen_alloc_label(struct apf_generator *gen);
int apf_gen_define_label(struct apf_generator *gen, apf_label label);
apf_label apf_gen_cnt_pass_label(uint16_t cnt);
apf_label apf_gen_cnt_drop_label(uint16_t cnt);

int apf_gen_add_jmp(struct apf_generator *gen, apf_label tgt_label);
int apf_gen_set_data(struct apf_generator *gen, const uint8_t *data, uint16_t len);
int apf_gen_add_jeq(struct apf_generator *gen, uint32_t val, apf_label tgt_label);
int apf_gen_add_jeq_r1(struct apf_generator *gen, apf_label tgt_label);
int apf_gen_add_jne(struct apf_generator *gen, uint32_t val, apf_label tgt_label);
int apf_gen_add_jne_r1(struct apf_generator *gen, apf_label tgt_label);
int apf_gen_add_jgt(struct apf_generator *gen, uint32_t val, apf_label tgt_label);
int apf_gen_add_jgt_r1(struct apf_generator *gen, apf_label tgt_label);
int apf_gen_add_jlt(struct apf_generator *gen, uint32_t val, apf_label tgt_label);
int apf_gen_add_jlt_r1(struct apf_generator *gen, apf_label tgt_label);
int apf_gen_add_jset(struct apf_generator *gen, uint32_t val, apf_label tgt_label);
int apf_gen_add_jset_r1(struct apf_generator *gen, apf_label tgt_label);
int apf_gen_add_jnset(struct apf_generator *gen, uint32_t val, apf_label tgt_label);
int apf_gen_add_jnset_r1(struct apf_generator *gen, apf_label tgt_label);
/*
 * Byte-sequence matching starting at the packet offset in R0.
 */
int apf_gen_add_jbsne(struct apf_generator *gen, apf_label tgt_label, const uint8_t *bytes,
                      uint16_t len);
int apf_gen_add_jbseq(struct apf_generator *gen, apf_label tgt_label, const uint8_t *bytes,
                      uint16_t len);
int apf_gen_add_jbsne_multi(struct apf_generator *gen, apf_label tgt_label, const uint8_t *bytes,
                            uint8_t cnt, uint16_t len);
int apf_gen_add_jbseq_multi(struct apf_generator *gen, apf_label tgt_label, const uint8_t *bytes,
                            uint8_t cnt, uint16_t len);
/*
 * Byte-sequence matching at a fixed packet offset. Emits compact JBSPTRMATCH
 * when pkt_offset <= 255, cnt <= 16, len <= 16, and all patterns fit at even
 * offsets <= 510 in the JMPDATA region; otherwise falls back to
 * `li r0, pkt_offset` + JBSMATCH. Callers must assume R0 may be overwritten.
 */
int apf_gen_add_jbsne_at_offset(struct apf_generator *gen, uint32_t pkt_offset, apf_label tgt_label,
                                const uint8_t *bytes, uint16_t len);
int apf_gen_add_jbseq_at_offset(struct apf_generator *gen, uint32_t pkt_offset, apf_label tgt_label,
                                const uint8_t *bytes, uint16_t len);
int apf_gen_add_jbsne_at_offset_multi(struct apf_generator *gen, uint32_t pkt_offset,
                                      apf_label tgt_label, const uint8_t *bytes, uint8_t cnt,
                                      uint16_t len);
int apf_gen_add_jbseq_at_offset_multi(struct apf_generator *gen, uint32_t pkt_offset,
                                      apf_label tgt_label, const uint8_t *bytes, uint8_t cnt,
                                      uint16_t len);
int apf_gen_add_joneof(struct apf_generator *gen, enum apf_register reg, apf_label tgt_label,
                       const uint32_t *values, uint8_t cnt);
int apf_gen_add_jnoneof(struct apf_generator *gen, enum apf_register reg, apf_label tgt_label,
                        const uint32_t *values, uint8_t cnt);

/*
 * DNS Matching Instructions (all read the UDP payload start offset from R0).
 */
int apf_gen_add_jdnsqne(struct apf_generator *gen, apf_label tgt_label, uint8_t qtype,
                        const uint8_t *qnames, uint16_t qnames_len);
int apf_gen_add_jdnsqeq(struct apf_generator *gen, apf_label tgt_label, uint8_t qtype,
                        const uint8_t *qnames, uint16_t qnames_len);
int apf_gen_add_jdnsqnesafe(struct apf_generator *gen, apf_label tgt_label, uint8_t qtype,
                            const uint8_t *qnames, uint16_t qnames_len);
int apf_gen_add_jdnsqeqsafe(struct apf_generator *gen, apf_label tgt_label, uint8_t qtype,
                            const uint8_t *qnames, uint16_t qnames_len);

int apf_gen_add_jdnsane(struct apf_generator *gen, apf_label tgt_label, const uint8_t *names,
                        uint16_t names_len);
int apf_gen_add_jdnsaeq(struct apf_generator *gen, apf_label tgt_label, const uint8_t *names,
                        uint16_t names_len);
int apf_gen_add_jdnsanesafe(struct apf_generator *gen, apf_label tgt_label, const uint8_t *names,
                            uint16_t names_len);
int apf_gen_add_jdnsaeqsafe(struct apf_generator *gen, apf_label tgt_label, const uint8_t *names,
                            uint16_t names_len);

int apf_gen_add_jdnsqne1(struct apf_generator *gen, apf_label tgt_label, uint16_t qtype,
                         const uint8_t *qnames, uint16_t qnames_len);
int apf_gen_add_jdnsqeq1(struct apf_generator *gen, apf_label tgt_label, uint16_t qtype,
                         const uint8_t *qnames, uint16_t qnames_len);
int apf_gen_add_jdnsqnesafe1(struct apf_generator *gen, apf_label tgt_label, uint16_t qtype,
                             const uint8_t *qnames, uint16_t qnames_len);
int apf_gen_add_jdnsqeqsafe1(struct apf_generator *gen, apf_label tgt_label, uint16_t qtype,
                             const uint8_t *qnames, uint16_t qnames_len);

int apf_gen_add_jdnsqne2(struct apf_generator *gen, apf_label tgt_label, uint8_t qtype1,
                         uint8_t qtype2, const uint8_t *qnames, uint16_t qnames_len);
int apf_gen_add_jdnsqeq2(struct apf_generator *gen, apf_label tgt_label, uint8_t qtype1,
                         uint8_t qtype2, const uint8_t *qnames, uint16_t qnames_len);
int apf_gen_add_jdnsqnesafe2(struct apf_generator *gen, apf_label tgt_label, uint8_t qtype1,
                             uint8_t qtype2, const uint8_t *qnames, uint16_t qnames_len);
int apf_gen_add_jdnsqeqsafe2(struct apf_generator *gen, apf_label tgt_label, uint8_t qtype1,
                             uint8_t qtype2, const uint8_t *qnames, uint16_t qnames_len);

/* Arithmetic and Immediate Instructions */
int apf_gen_add_add(struct apf_generator *gen, enum apf_register reg, int32_t val);
int apf_gen_add_mul(struct apf_generator *gen, enum apf_register reg, uint32_t val);
int apf_gen_add_div(struct apf_generator *gen, enum apf_register reg, uint32_t val);
int apf_gen_add_and(struct apf_generator *gen, enum apf_register reg, int32_t val);
int apf_gen_add_or(struct apf_generator *gen, enum apf_register reg, uint32_t val);
int apf_gen_add_sh(struct apf_generator *gen, enum apf_register reg, int32_t val);
int apf_gen_add_li(struct apf_generator *gen, enum apf_register reg, int32_t val);

int apf_gen_add_add_reg(struct apf_generator *gen, enum apf_register dst_reg);
int apf_gen_add_mul_reg(struct apf_generator *gen, enum apf_register dst_reg);
int apf_gen_add_div_reg(struct apf_generator *gen, enum apf_register dst_reg);
int apf_gen_add_and_reg(struct apf_generator *gen, enum apf_register dst_reg);
int apf_gen_add_or_reg(struct apf_generator *gen, enum apf_register dst_reg);
int apf_gen_add_sh_reg(struct apf_generator *gen, enum apf_register dst_reg);

/* Extended Register, Scratch Memory, and Counter Instructions */
int apf_gen_add_ldm(struct apf_generator *gen, enum apf_register reg, uint8_t slot);
int apf_gen_add_stm(struct apf_generator *gen, enum apf_register reg, uint8_t slot);
int apf_gen_add_not(struct apf_generator *gen, enum apf_register reg);
int apf_gen_add_neg(struct apf_generator *gen, enum apf_register reg);
int apf_gen_add_swap(struct apf_generator *gen);
int apf_gen_add_mov(struct apf_generator *gen, enum apf_register dst_reg);

int apf_gen_add_lddw(struct apf_generator *gen, enum apf_register reg, uint16_t cnt);
int apf_gen_add_stdw(struct apf_generator *gen, enum apf_register reg, uint16_t cnt);

/* Packet Construction and Transmission Instructions */
/* Allocates a transmit buffer of size R0 bytes. */
int apf_gen_add_allocate_r0(struct apf_generator *gen);
int apf_gen_add_allocate(struct apf_generator *gen, uint16_t size);
int apf_gen_add_allocate_ext(struct apf_generator *gen, uint16_t size);
int apf_gen_add_transmit_without_csum(struct apf_generator *gen);
int apf_gen_add_transmit(struct apf_generator *gen, uint8_t ip_ofs);
int apf_gen_add_transmit_l4(struct apf_generator *gen, uint8_t ip_ofs, uint8_t csum_ofs,
                            uint8_t csum_start, uint16_t partial_csum, bool is_udp);
int apf_gen_add_write_u8(struct apf_generator *gen, uint8_t val);
int apf_gen_add_write_u16(struct apf_generator *gen, uint16_t val);
int apf_gen_add_write_u32(struct apf_generator *gen, uint32_t val);
int apf_gen_add_ewrite1(struct apf_generator *gen, enum apf_register reg);
int apf_gen_add_ewrite2(struct apf_generator *gen, enum apf_register reg);
int apf_gen_add_ewrite4(struct apf_generator *gen, enum apf_register reg);
int apf_gen_find_or_append_data(struct apf_generator *gen, const uint8_t *data, size_t len);
int apf_gen_add_data_copy(struct apf_generator *gen, const uint8_t *data, size_t len);
int apf_gen_add_pktcopy(struct apf_generator *gen, uint32_t src_offset, uint16_t len);
int apf_gen_add_datacopy(struct apf_generator *gen, uint32_t src_offset, uint16_t len);
/*
 * Extended packet/data copy instructions: read the source offset from R0
 * (packet offset for epktcopy*, JMPDATA offset for edatacopy*); the *_r1
 * variants also read the copy length in bytes from R1.
 */
int apf_gen_add_epktcopy(struct apf_generator *gen, uint16_t len);
int apf_gen_add_edatacopy(struct apf_generator *gen, uint16_t len);
int apf_gen_add_epktcopy_r1(struct apf_generator *gen);
int apf_gen_add_edatacopy_r1(struct apf_generator *gen);

/* Terminal Verdict Instructions */
int apf_gen_add_pass(struct apf_generator *gen);
int apf_gen_add_drop(struct apf_generator *gen);
int apf_gen_add_cnt_and_pass(struct apf_generator *gen, uint16_t cnt);
int apf_gen_add_cnt_and_drop(struct apf_generator *gen, uint16_t cnt);

/*
 * Generator Inspection, Error Reporting, and Bytecode Generation
 *
 * apf_gen_get_insn_count returns the number of user instructions added to @gen
 * (excluding the hidden prologue instructions).
 *
 * apf_gen_generate writes the assembled bytecode into @buf (of capacity
 * @buf_len) and stores the bytecode size in *@out_len. When @buf is NULL, it
 * validates the program, populates *@out_len with the required size, and
 * returns 0 without writing bytecode.
 */
size_t apf_gen_get_insn_count(const struct apf_generator *gen);
size_t apf_gen_get_program_len(struct apf_generator *gen);
enum apf_gen_err apf_gen_get_error(const struct apf_generator *gen, size_t *insn_index);

int apf_gen_generate(struct apf_generator *gen, uint8_t *buf, size_t buf_len, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* APF_GENERATOR_H */
