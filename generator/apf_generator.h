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
 * Builder functions return 0 on success and -1 on error. Errors are sticky and
 * can be queried with apf_gen_get_error(). Adding instructions or labels after
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
int apf_gen_add_jbsne(struct apf_generator *gen, apf_label tgt_label, const uint8_t *bytes,
                      uint16_t len);
int apf_gen_add_jbseq(struct apf_generator *gen, apf_label tgt_label, const uint8_t *bytes,
                      uint16_t len);

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
