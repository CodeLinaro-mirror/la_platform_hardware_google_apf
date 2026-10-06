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

#include "apf_generator.h"

#include <stdlib.h>
#include <string.h>

#include "apf_opcode_defs.h"

#define INITIAL_INSN_CAPACITY 64
#define INITIAL_LABEL_CAPACITY 32
#define PROLOGUE_INSN_COUNT 2
#define MIN_APF_RAM_LEN 1024u
#define SYSTEM_COUNTER_COUNT 6u

/*
 * Internal representation of a single APF instruction prior to bytecode
 * assembly. The generator performs a two-pass assembly in apf_gen_generate()
 * to resolve branch labels, determine minimal immediate/offset encodings,
 * and emit final big-endian bytecode.
 */
struct apf_instruction {
    uint8_t opcode;
    uint8_t reg;
    bool has_imm;
    /*
     * Stores both unsigned and signed immediates as a 32-bit two's-complement
     * bit pattern. Signedness is determined by opcode_has_signed_imm(opcode)
     * during operand sizing in get_insn_operand_sizes().
     */
    uint32_t imm;

    bool has_target;
    int16_t target_label;
    uint32_t target_offset;

    uint8_t *extra_bytes;
    uint32_t extra_len;

    uint32_t offset;
};

/*
 * Label table entry for intra-program user labels (label.id <= -2, mapped to
 * index = -label.id - 2). insn_index == SIZE_MAX indicates that the label has
 * been allocated via apf_gen_alloc_label() but not yet bound via
 * apf_gen_define_label(). Non-negative target_label values (>= 0) encode
 * end-of-program targets (APF_LABEL_PASS, APF_LABEL_DROP, and counter-verdict
 * targets from apf_gen_cnt_pass_label() / apf_gen_cnt_drop_label()) without
 * table entries.
 */
struct apf_label_entry {
    size_t insn_index;
    uint32_t offset;
};

struct apf_generator {
    uint32_t version;
    uint32_t ram_len;
    uint32_t max_cnt;
    bool generated;
    enum apf_gen_err err;
    size_t err_insn_index;

    struct apf_instruction *insns;
    size_t count;
    size_t capacity;

    struct apf_label_entry *labels;
    size_t label_count;
    size_t label_capacity;
};

static int apf_gen_fail_with(struct apf_generator *gen, enum apf_gen_err err) {
    if (gen && gen->err == APF_GEN_OK) {
        gen->err = err;
        gen->err_insn_index =
            (gen->count >= PROLOGUE_INSN_COUNT) ? (gen->count - PROLOGUE_INSN_COUNT) : 0;
    }
    return -1;
}

static int apf_gen_fail_at(struct apf_generator *gen, enum apf_gen_err err, size_t insn_idx) {
    if (gen && gen->err == APF_GEN_OK) {
        gen->err = err;
        gen->err_insn_index =
            (insn_idx >= PROLOGUE_INSN_COUNT) ? (insn_idx - PROLOGUE_INSN_COUNT) : 0;
    }
    return -1;
}

static int apf_gen_fail(struct apf_generator *gen) {
    return apf_gen_fail_with(gen, APF_GEN_ERR_INVALID_ARGUMENT);
}

static bool is_valid_reg(enum apf_register reg) {
    return reg == APF_REG_R0 || reg == APF_REG_R1;
}

static void track_counter(struct apf_generator *gen, uint16_t cnt) {
    if (gen && cnt > gen->max_cnt) {
        gen->max_cnt = cnt;
    }
}

static int ensure_label_capacity(struct apf_generator *gen, size_t min_cap) {
    if (min_cap <= gen->label_capacity) {
        return 0;
    }
    size_t new_cap =
        (gen->label_capacity == 0) ? INITIAL_LABEL_CAPACITY : gen->label_capacity;
    while (new_cap < min_cap) {
        new_cap *= 2;
    }
    struct apf_label_entry *new_labels =
        realloc(gen->labels, new_cap * sizeof(struct apf_label_entry));
    if (!new_labels) {
        return apf_gen_fail_with(gen, APF_GEN_ERR_OUT_OF_MEMORY);
    }
    for (size_t i = gen->label_capacity; i < new_cap; i++) {
        new_labels[i].insn_index = SIZE_MAX;
        new_labels[i].offset = 0;
    }
    gen->labels = new_labels;
    gen->label_capacity = new_cap;
    return 0;
}

static bool is_valid_user_counter(uint16_t cnt) {
    return cnt >= APF_COUNTER_MIN_USER && cnt <= APF_COUNTER_MAX;
}

static bool validate_and_track_target_label(struct apf_generator *gen, apf_label tgt_label) {
    if (!gen || tgt_label.id == APF_LABEL_INVALID.id) {
        return false;
    }
    if (tgt_label.id >= 0) {
        if (tgt_label.id == APF_LABEL_PASS.id || tgt_label.id == APF_LABEL_DROP.id) {
            return true;
        }
        uint16_t cnt = (uint16_t)(tgt_label.id / 2);
        if (!is_valid_user_counter(cnt)) {
            return false;
        }
        track_counter(gen, cnt);
        return true;
    }
    size_t idx = (size_t)(-(int32_t)tgt_label.id - 2);
    return idx < gen->label_count;
}

struct apf_generator *apf_generator_alloc(uint32_t apf_version, uint32_t ram_len) {
    if (apf_version < APF_VERSION_61 || ram_len < MIN_APF_RAM_LEN ||
        (ram_len % 4) != 0 || (ram_len >> 31) != 0) {
        return NULL;
    }

    struct apf_generator *gen = calloc(1, sizeof(*gen));
    if (!gen) {
        return NULL;
    }

    gen->version = apf_version;
    gen->ram_len = ram_len;
    gen->capacity = INITIAL_INSN_CAPACITY;
    gen->insns = calloc(gen->capacity, sizeof(struct apf_instruction));
    if (!gen->insns) {
        free(gen);
        return NULL;
    }

    if (ensure_label_capacity(gen, INITIAL_LABEL_CAPACITY) != 0) {
        free(gen->insns);
        free(gen);
        return NULL;
    }

    /*
     * Automatically emit the APFv6+ prologue matching ApfV6GeneratorBase.java:
     *   insn[0]: JMPDATA (3-byte header + optional constant data region)
     *   insn[1]: EXCEPTIONBUFFER (4-byte instruction whose u16 size is updated
     *            in apf_gen_generate() once program_len and max_cnt are known)
     */
    struct apf_instruction *jmpdata = &gen->insns[gen->count++];
    jmpdata->opcode = JMP_OPCODE;
    jmpdata->reg = APF_REG_R1;
    jmpdata->has_imm = true;
    jmpdata->imm = 0;
    jmpdata->target_label = APF_LABEL_INVALID.id;

    uint8_t *except_extra = calloc(2, sizeof(uint8_t));
    if (!except_extra) {
        free(gen->labels);
        free(gen->insns);
        free(gen);
        return NULL;
    }
    struct apf_instruction *except_insn = &gen->insns[gen->count++];
    except_insn->opcode = EXT_OPCODE;
    except_insn->reg = APF_REG_R0;
    except_insn->has_imm = true;
    except_insn->imm = EXCEPTIONBUFFER_EXT_OPCODE;
    except_insn->extra_bytes = except_extra;
    except_insn->extra_len = 2;
    except_insn->target_label = APF_LABEL_INVALID.id;

    return gen;
}

void apf_generator_free(struct apf_generator *gen) {
    if (!gen) {
        return;
    }
    for (size_t i = 0; i < gen->count; i++) {
        free(gen->insns[i].extra_bytes);
    }
    free(gen->labels);
    free(gen->insns);
    free(gen);
}

apf_label apf_gen_alloc_label(struct apf_generator *gen) {
    if (!gen) {
        return APF_LABEL_INVALID;
    }
    if (gen->generated) {
        apf_gen_fail_with(gen, APF_GEN_ERR_ALREADY_GENERATED);
        return APF_LABEL_INVALID;
    }
    if (gen->label_count > 32766) {
        apf_gen_fail_with(gen, APF_GEN_ERR_LABEL_LIMIT);
        return APF_LABEL_INVALID;
    }
    if (ensure_label_capacity(gen, gen->label_count + 1) != 0) {
        return APF_LABEL_INVALID;
    }
    size_t idx = gen->label_count++;
    gen->labels[idx].insn_index = SIZE_MAX;
    gen->labels[idx].offset = 0;
    return (apf_label){ (int16_t)-(2 + (int32_t)idx) };
}

int apf_gen_define_label(struct apf_generator *gen, apf_label label) {
    if (!gen) {
        return -1;
    }
    if (gen->generated) {
        return apf_gen_fail_with(gen, APF_GEN_ERR_ALREADY_GENERATED);
    }
    if (label.id > -2) {
        return apf_gen_fail(gen);
    }
    size_t idx = (size_t)(-(int32_t)label.id - 2);
    if (idx >= gen->label_count) {
        return apf_gen_fail(gen);
    }
    if (gen->labels[idx].insn_index != SIZE_MAX) {
        return apf_gen_fail_with(gen, APF_GEN_ERR_DUPLICATE_LABEL);
    }
    gen->labels[idx].insn_index = gen->count;
    return 0;
}

apf_label apf_gen_cnt_pass_label(uint16_t cnt) {
    return is_valid_user_counter(cnt) ? (apf_label){ (int16_t)(cnt * 2) } : APF_LABEL_INVALID;
}

apf_label apf_gen_cnt_drop_label(uint16_t cnt) {
    return is_valid_user_counter(cnt) ? (apf_label){ (int16_t)(cnt * 2 + 1) } : APF_LABEL_INVALID;
}

static struct apf_instruction *apf_gen_add_insn(struct apf_generator *gen,
                                                uint8_t opcode, uint8_t reg) {
    if (!gen) {
        return NULL;
    }
    if (gen->generated) {
        apf_gen_fail_with(gen, APF_GEN_ERR_ALREADY_GENERATED);
        return NULL;
    }
    if (!is_valid_reg((enum apf_register)reg)) {
        apf_gen_fail(gen);
        return NULL;
    }

    if (gen->count >= gen->capacity) {
        size_t new_cap = gen->capacity * 2;
        struct apf_instruction *new_insns =
            realloc(gen->insns, new_cap * sizeof(struct apf_instruction));
        if (!new_insns) {
            apf_gen_fail_with(gen, APF_GEN_ERR_OUT_OF_MEMORY);
            return NULL;
        }
        memset(new_insns + gen->capacity, 0,
               (new_cap - gen->capacity) * sizeof(struct apf_instruction));
        gen->insns = new_insns;
        gen->capacity = new_cap;
    }

    struct apf_instruction *insn = &gen->insns[gen->count++];
    memset(insn, 0, sizeof(*insn));
    insn->opcode = opcode;
    insn->reg = reg & 1;
    insn->target_label = APF_LABEL_INVALID.id;
    return insn;
}

static int apf_gen_add_imm_insn(struct apf_generator *gen, uint8_t opcode,
                                enum apf_register reg, uint32_t imm) {
    struct apf_instruction *insn = apf_gen_add_insn(gen, opcode, (uint8_t)reg);
    if (!insn) return -1;
    insn->has_imm = true;
    insn->imm = imm;
    return 0;
}

static int apf_gen_add_reg_insn(struct apf_generator *gen, uint8_t opcode,
                                enum apf_register reg) {
    struct apf_instruction *insn = apf_gen_add_insn(gen, opcode, (uint8_t)reg);
    return insn ? 0 : -1;
}

static int apf_gen_add_ext_insn(struct apf_generator *gen, enum apf_register reg,
                                uint32_t ext_opcode) {
    return apf_gen_add_imm_insn(gen, EXT_OPCODE, reg, ext_opcode);
}

static int apf_gen_add_branch_insn(struct apf_generator *gen, uint8_t opcode,
                                   enum apf_register reg, uint32_t val,
                                   apf_label tgt_label) {
    if (!validate_and_track_target_label(gen, tgt_label)) return apf_gen_fail(gen);
    struct apf_instruction *insn = apf_gen_add_insn(gen, opcode, (uint8_t)reg);
    if (!insn) return -1;
    insn->has_target = true;
    insn->target_label = tgt_label.id;
    /*
     * For conditional branches, R=0 compares R0 against an immediate operand,
     * whereas R=1 compares R0 against R1 and omits the immediate field.
     */
    if (reg == APF_REG_R0) {
        insn->has_imm = true;
        insn->imm = val;
    }
    return 0;
}

/*
 * -------------------------------------------------------------------------
 * Packet Load Instructions
 * -------------------------------------------------------------------------
 */
int apf_gen_add_ldb(struct apf_generator *gen, enum apf_register reg, uint32_t offset) {
    return apf_gen_add_imm_insn(gen, LDB_OPCODE, reg, offset);
}

int apf_gen_add_ldh(struct apf_generator *gen, enum apf_register reg, uint32_t offset) {
    return apf_gen_add_imm_insn(gen, LDH_OPCODE, reg, offset);
}

int apf_gen_add_ldw(struct apf_generator *gen, enum apf_register reg, uint32_t offset) {
    return apf_gen_add_imm_insn(gen, LDW_OPCODE, reg, offset);
}

int apf_gen_add_ldbx(struct apf_generator *gen, enum apf_register reg, uint32_t offset) {
    return apf_gen_add_imm_insn(gen, LDBX_OPCODE, reg, offset);
}

int apf_gen_add_ldhx(struct apf_generator *gen, enum apf_register reg, uint32_t offset) {
    return apf_gen_add_imm_insn(gen, LDHX_OPCODE, reg, offset);
}

int apf_gen_add_ldwx(struct apf_generator *gen, enum apf_register reg, uint32_t offset) {
    return apf_gen_add_imm_insn(gen, LDWX_OPCODE, reg, offset);
}

/*
 * -------------------------------------------------------------------------
 * Jump, Data, and Conditional Branch Instructions
 * -------------------------------------------------------------------------
 */
int apf_gen_add_jmp(struct apf_generator *gen, apf_label tgt_label) {
    if (!validate_and_track_target_label(gen, tgt_label)) return apf_gen_fail(gen);
    struct apf_instruction *insn = apf_gen_add_insn(gen, JMP_OPCODE, APF_REG_R0);
    if (!insn) return -1;
    insn->has_target = true;
    insn->target_label = tgt_label.id;
    return 0;
}

int apf_gen_set_data(struct apf_generator *gen, const uint8_t *data, uint16_t len) {
    if (!gen) {
        return -1;
    }
    if (gen->generated) {
        return apf_gen_fail_with(gen, APF_GEN_ERR_ALREADY_GENERATED);
    }
    if (gen->count != PROLOGUE_INSN_COUNT || gen->label_count != 0 ||
        gen->insns[0].opcode != JMP_OPCODE || gen->insns[0].reg != APF_REG_R1 ||
        gen->insns[0].extra_len != 0 || (len > 0 && !data)) {
        return apf_gen_fail(gen);
    }
    if (len > 0) {
        uint8_t *copy = malloc(len);
        if (!copy) {
            return apf_gen_fail_with(gen, APF_GEN_ERR_OUT_OF_MEMORY);
        }
        memcpy(copy, data, len);
        gen->insns[0].extra_bytes = copy;
        gen->insns[0].extra_len = len;
        gen->insns[0].imm = len;
    }
    return 0;
}

int apf_gen_add_jeq(struct apf_generator *gen, uint32_t val, apf_label tgt_label) {
    return apf_gen_add_branch_insn(gen, JEQ_OPCODE, APF_REG_R0, val, tgt_label);
}

int apf_gen_add_jeq_r1(struct apf_generator *gen, apf_label tgt_label) {
    return apf_gen_add_branch_insn(gen, JEQ_OPCODE, APF_REG_R1, 0, tgt_label);
}

int apf_gen_add_jne(struct apf_generator *gen, uint32_t val, apf_label tgt_label) {
    return apf_gen_add_branch_insn(gen, JNE_OPCODE, APF_REG_R0, val, tgt_label);
}

int apf_gen_add_jne_r1(struct apf_generator *gen, apf_label tgt_label) {
    return apf_gen_add_branch_insn(gen, JNE_OPCODE, APF_REG_R1, 0, tgt_label);
}

int apf_gen_add_jgt(struct apf_generator *gen, uint32_t val, apf_label tgt_label) {
    return apf_gen_add_branch_insn(gen, JGT_OPCODE, APF_REG_R0, val, tgt_label);
}

int apf_gen_add_jgt_r1(struct apf_generator *gen, apf_label tgt_label) {
    return apf_gen_add_branch_insn(gen, JGT_OPCODE, APF_REG_R1, 0, tgt_label);
}

int apf_gen_add_jlt(struct apf_generator *gen, uint32_t val, apf_label tgt_label) {
    return apf_gen_add_branch_insn(gen, JLT_OPCODE, APF_REG_R0, val, tgt_label);
}

int apf_gen_add_jlt_r1(struct apf_generator *gen, apf_label tgt_label) {
    return apf_gen_add_branch_insn(gen, JLT_OPCODE, APF_REG_R1, 0, tgt_label);
}

int apf_gen_add_jset(struct apf_generator *gen, uint32_t val, apf_label tgt_label) {
    return apf_gen_add_branch_insn(gen, JSET_OPCODE, APF_REG_R0, val, tgt_label);
}

int apf_gen_add_jset_r1(struct apf_generator *gen, apf_label tgt_label) {
    return apf_gen_add_branch_insn(gen, JSET_OPCODE, APF_REG_R1, 0, tgt_label);
}

static int apf_gen_add_jbsmatch_insn(struct apf_generator *gen, enum apf_register reg,
                                     apf_label tgt_label, const uint8_t *bytes, uint16_t len) {
    if (!bytes || len == 0 || len > 2047 || !validate_and_track_target_label(gen, tgt_label)) {
        return apf_gen_fail(gen);
    }

    uint8_t *copy = malloc(len);
    if (!copy) {
        return apf_gen_fail_with(gen, APF_GEN_ERR_OUT_OF_MEMORY);
    }
    memcpy(copy, bytes, len);

    struct apf_instruction *insn = apf_gen_add_insn(gen, JBSMATCH_OPCODE, (uint8_t)reg);
    if (!insn) {
        free(copy);
        return -1;
    }

    insn->has_target = true;
    insn->target_label = tgt_label.id;
    insn->has_imm = true;
    insn->imm = (uint32_t)len;
    insn->extra_bytes = copy;
    insn->extra_len = len;
    return 0;
}

int apf_gen_add_jbsne(struct apf_generator *gen, apf_label tgt_label,
                      const uint8_t *bytes, uint16_t len) {
    return apf_gen_add_jbsmatch_insn(gen, APF_REG_R0, tgt_label, bytes, len);
}

int apf_gen_add_jbseq(struct apf_generator *gen, apf_label tgt_label,
                      const uint8_t *bytes, uint16_t len) {
    return apf_gen_add_jbsmatch_insn(gen, APF_REG_R1, tgt_label, bytes, len);
}

/*
 * -------------------------------------------------------------------------
 * Arithmetic and Immediate Instructions
 * -------------------------------------------------------------------------
 */
int apf_gen_add_add(struct apf_generator *gen, enum apf_register reg, int32_t val) {
    return apf_gen_add_imm_insn(gen, ADD_OPCODE, reg, (uint32_t)val);
}

int apf_gen_add_mul(struct apf_generator *gen, enum apf_register reg, uint32_t val) {
    return apf_gen_add_imm_insn(gen, MUL_OPCODE, reg, val);
}

int apf_gen_add_div(struct apf_generator *gen, enum apf_register reg, uint32_t val) {
    if (val == 0) return apf_gen_fail(gen);
    return apf_gen_add_imm_insn(gen, DIV_OPCODE, reg, val);
}

int apf_gen_add_and(struct apf_generator *gen, enum apf_register reg, int32_t val) {
    return apf_gen_add_imm_insn(gen, AND_OPCODE, reg, (uint32_t)val);
}

int apf_gen_add_or(struct apf_generator *gen, enum apf_register reg, uint32_t val) {
    return apf_gen_add_imm_insn(gen, OR_OPCODE, reg, val);
}

int apf_gen_add_sh(struct apf_generator *gen, enum apf_register reg, int32_t val) {
    if (val < -31 || val > 31) return apf_gen_fail(gen);
    return apf_gen_add_imm_insn(gen, SH_OPCODE, reg, (uint32_t)val);
}

int apf_gen_add_li(struct apf_generator *gen, enum apf_register reg, int32_t val) {
    return apf_gen_add_imm_insn(gen, LI_OPCODE, reg, (uint32_t)val);
}

int apf_gen_add_add_reg(struct apf_generator *gen, enum apf_register dst_reg) {
    return apf_gen_add_reg_insn(gen, ADD_OPCODE, dst_reg);
}

int apf_gen_add_mul_reg(struct apf_generator *gen, enum apf_register dst_reg) {
    return apf_gen_add_reg_insn(gen, MUL_OPCODE, dst_reg);
}

int apf_gen_add_div_reg(struct apf_generator *gen, enum apf_register dst_reg) {
    return apf_gen_add_reg_insn(gen, DIV_OPCODE, dst_reg);
}

int apf_gen_add_and_reg(struct apf_generator *gen, enum apf_register dst_reg) {
    return apf_gen_add_reg_insn(gen, AND_OPCODE, dst_reg);
}

int apf_gen_add_or_reg(struct apf_generator *gen, enum apf_register dst_reg) {
    return apf_gen_add_reg_insn(gen, OR_OPCODE, dst_reg);
}

int apf_gen_add_sh_reg(struct apf_generator *gen, enum apf_register dst_reg) {
    return apf_gen_add_reg_insn(gen, SH_OPCODE, dst_reg);
}

/*
 * -------------------------------------------------------------------------
 * Extended Register, Scratch Memory, and Counter Instructions
 * -------------------------------------------------------------------------
 */
int apf_gen_add_ldm(struct apf_generator *gen, enum apf_register reg, uint8_t slot) {
    if (slot >= MEMORY_ITEMS) return apf_gen_fail(gen);
    return apf_gen_add_ext_insn(gen, reg, (uint32_t)LDM_EXT_OPCODE + slot);
}

int apf_gen_add_stm(struct apf_generator *gen, enum apf_register reg, uint8_t slot) {
    if (slot >= MEMORY_ITEMS) return apf_gen_fail(gen);
    return apf_gen_add_ext_insn(gen, reg, (uint32_t)STM_EXT_OPCODE + slot);
}

int apf_gen_add_not(struct apf_generator *gen, enum apf_register reg) {
    return apf_gen_add_ext_insn(gen, reg, NOT_EXT_OPCODE);
}

int apf_gen_add_neg(struct apf_generator *gen, enum apf_register reg) {
    return apf_gen_add_ext_insn(gen, reg, NEG_EXT_OPCODE);
}

int apf_gen_add_swap(struct apf_generator *gen) {
    return apf_gen_add_ext_insn(gen, APF_REG_R0, SWAP_EXT_OPCODE);
}

int apf_gen_add_mov(struct apf_generator *gen, enum apf_register dst_reg) {
    return apf_gen_add_ext_insn(gen, dst_reg, MOV_EXT_OPCODE);
}

int apf_gen_add_lddw(struct apf_generator *gen, enum apf_register reg, uint16_t cnt) {
    if (cnt == 0 || cnt > APF_COUNTER_MAX) return apf_gen_fail(gen);
    if (apf_gen_add_imm_insn(gen, LDDW_OPCODE, reg, (uint32_t)cnt) < 0) return -1;
    track_counter(gen, cnt);
    return 0;
}

int apf_gen_add_stdw(struct apf_generator *gen, enum apf_register reg, uint16_t cnt) {
    if (!is_valid_user_counter(cnt)) return apf_gen_fail(gen);
    if (apf_gen_add_imm_insn(gen, STDW_OPCODE, reg, (uint32_t)cnt) < 0) return -1;
    track_counter(gen, cnt);
    return 0;
}

/*
 * -------------------------------------------------------------------------
 * Terminal Verdict Instructions
 * -------------------------------------------------------------------------
 */
int apf_gen_add_pass(struct apf_generator *gen) {
    return apf_gen_add_reg_insn(gen, PASSDROP_OPCODE, APF_REG_R0);
}

int apf_gen_add_drop(struct apf_generator *gen) {
    return apf_gen_add_reg_insn(gen, PASSDROP_OPCODE, APF_REG_R1);
}

int apf_gen_add_cnt_and_pass(struct apf_generator *gen, uint16_t cnt) {
    if (!is_valid_user_counter(cnt)) return apf_gen_fail(gen);
    if (apf_gen_add_imm_insn(gen, PASSDROP_OPCODE, APF_REG_R0, cnt) < 0) return -1;
    track_counter(gen, cnt);
    return 0;
}

int apf_gen_add_cnt_and_drop(struct apf_generator *gen, uint16_t cnt) {
    if (!is_valid_user_counter(cnt)) return apf_gen_fail(gen);
    if (apf_gen_add_imm_insn(gen, PASSDROP_OPCODE, APF_REG_R1, cnt) < 0) return -1;
    track_counter(gen, cnt);
    return 0;
}

/*
 * -------------------------------------------------------------------------
 * Bytecode Size Calculation and Generation
 * -------------------------------------------------------------------------
 */

/*
 * Returns whether an opcode can encode an immediate value of 0 using
 * len_field == 0 (0 immediate bytes). In APFv6+, arithmetic/logic opcodes
 * interpret len_field == 0 as the register-to-register variant (R0 op R1).
 * For EXT_OPCODE, although the interpreter decodes len_field == 0 as imm == 0
 * (LDM_EXT_OPCODE for slot M[0]), the generator always emits at least 1 byte
 * for the extended sub-opcode to keep EXT instruction encoding uniform.
 */
static bool opcode_allows_zero_len_imm(uint8_t opcode) {
    switch (opcode) {
        case ADD_OPCODE:
        case MUL_OPCODE:
        case DIV_OPCODE:
        case AND_OPCODE:
        case OR_OPCODE:
        case SH_OPCODE:
        case EXT_OPCODE:
            return false;
        default:
            return true;
    }
}

/*
 * Returns whether the APFv6+ interpreter sign-extends the immediate operand
 * for the given opcode, allowing negative values in [-128, -1] or
 * [-32768, 32767] to be compressed into 1 or 2 bytes.
 */
static bool opcode_has_signed_imm(uint8_t opcode) {
    switch (opcode) {
        case ADD_OPCODE:
        case AND_OPCODE:
        case SH_OPCODE:
        case LI_OPCODE:
            return true;
        default:
            return false;
    }
}

static uint8_t get_uimm_size(uint32_t val, bool allow_zero_len) {
    if (val == 0 && allow_zero_len) return 0;
    if (val <= 0xFF) return 1;
    if (val <= 0xFFFF) return 2;
    return 4;
}

static uint8_t get_simm_size(int32_t val, bool allow_zero_len) {
    if (val == 0 && allow_zero_len) return 0;
    if (val >= -128 && val <= 127) return 1;
    if (val >= -32768 && val <= 32767) return 2;
    return 4;
}

/*
 * Maps an immediate byte count (0, 1, 2, or 4 bytes) to the 2-bit len_field
 * (0, 1, 2, or 3) packed into bits [2:1] of the 1-byte APF instruction header.
 */
static uint8_t size_to_len_field(uint8_t size) {
    switch (size) {
        case 0: return 0;
        case 1: return 1;
        case 2: return 2;
        case 4: return 3;
        default: return 0;
    }
}

static uint8_t get_insn_operand_sizes(const struct apf_instruction *insn,
                                      uint8_t *out_imm_size,
                                      uint8_t *out_target_size) {
    /*
     * JMPDATA (JMP_OPCODE with R=1) always uses a fixed 2-byte length
     * immediate (len_field = 2) so the instruction prefix is always 3 bytes
     * and the constant data pool always starts at program byte offset 3.
     */
    if (insn->opcode == JMP_OPCODE && insn->reg == APF_REG_R1) {
        *out_imm_size = 2;
        *out_target_size = 0;
        return 2;
    }

    uint8_t imm_size = 0;
    if (insn->has_imm) {
        bool allow_zero_len = opcode_allows_zero_len_imm(insn->opcode);
        imm_size = opcode_has_signed_imm(insn->opcode)
                       ? get_simm_size((int32_t)insn->imm, allow_zero_len)
                       : get_uimm_size(insn->imm, allow_zero_len);
    }
    uint8_t target_size = insn->has_target ? get_uimm_size(insn->target_offset, true) : 0;
    uint8_t size = (imm_size > target_size) ? imm_size : target_size;

    /*
     * Instructions with both a branch target and an immediate (e.g., JEQ with
     * R=0, JBSMATCH, or extended conditional branches) share a single 2-bit
     * len_field in the header, so the interpreter decodes both operands at
     * the same byte width.
     */
    if (insn->has_imm && insn->has_target) {
        imm_size = size;
        target_size = size;
    }
    *out_imm_size = imm_size;
    *out_target_size = target_size;
    return size;
}

static size_t compute_insn_size(const struct apf_instruction *insn) {
    uint8_t imm_size = 0;
    uint8_t target_size = 0;
    get_insn_operand_sizes(insn, &imm_size, &target_size);
    return 1 + (size_t)imm_size + (size_t)target_size + insn->extra_len;
}

static size_t compute_program_size(struct apf_generator *gen) {
    size_t total = 0;
    for (size_t i = 0; i < gen->count; i++) {
        struct apf_instruction *insn = &gen->insns[i];
        insn->offset = (uint32_t)total;
        total += compute_insn_size(insn);
    }
    for (size_t i = 0; i < gen->label_count; i++) {
        size_t idx = gen->labels[i].insn_index;
        if (idx != SIZE_MAX) {
            gen->labels[i].offset = (idx < gen->count) ? gen->insns[idx].offset
                                                       : (uint32_t)total;
        }
    }
    return total;
}

/*
 * Iteratively resolves branch offsets and shrinks forward branch encodings.
 * Because APF branch offsets are relative to the end of the branch instruction
 * and may reference forward labels, all branch offsets start at 0xFFFFFFFF
 * (4-byte worst case) and iteratively shrink to 2, 1, or 0 bytes until instruction
 * offsets stabilize. Backward jumps wrap around modulo 2^32 and remain 4 bytes.
 */
static int resolve_labels(struct apf_generator *gen, bool require_defined,
                          size_t *out_total_len) {
    bool has_labels = false;
    for (size_t i = 0; i < gen->count; i++) {
        struct apf_instruction *insn = &gen->insns[i];
        if (insn->has_target) {
            insn->target_offset = 0xFFFFFFFFu;
            has_labels = true;
        }
    }

    size_t total_size = compute_program_size(gen);
    if (!has_labels) {
        if (out_total_len) *out_total_len = total_size;
        return 0;
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t i = gen->count; i-- > 0;) {
            struct apf_instruction *insn = &gen->insns[i];
            if (!insn->has_target) {
                continue;
            }
            size_t insn_size = compute_insn_size(insn);
            uint32_t insn_end_offset = insn->offset + (uint32_t)insn_size;
            uint32_t target_byte_offset = 0;

            if (insn->target_label >= 0) {
                /*
                 * Non-negative labels encode end-of-program targets:
                 *   0 -> total_size (PASS)
                 *   1 -> total_size + 1 (DROP)
                 *   2 * cnt -> total_size + 2 * cnt (cnt_pass)
                 *   2 * cnt + 1 -> total_size + 2 * cnt + 1 (cnt_drop)
                 */
                target_byte_offset = (uint32_t)total_size + (uint32_t)insn->target_label;
            } else if (insn->target_label <= -2) {
                size_t lbl_idx = (size_t)(-(int32_t)insn->target_label - 2);
                if (lbl_idx >= gen->label_count ||
                    gen->labels[lbl_idx].insn_index == SIZE_MAX) {
                    if (require_defined) {
                        return apf_gen_fail_at(gen, APF_GEN_ERR_UNDEFINED_LABEL, i);
                    }
                    continue;
                }
                target_byte_offset = gen->labels[lbl_idx].offset;
            } else {
                if (require_defined) {
                    return apf_gen_fail_at(gen, APF_GEN_ERR_UNDEFINED_LABEL, i);
                }
                continue;
            }

            uint32_t rel_offset = target_byte_offset - insn_end_offset;
            if (rel_offset != insn->target_offset) {
                insn->target_offset = rel_offset;
                changed = true;
            }
        }
        total_size = compute_program_size(gen);
    }

    if (out_total_len) *out_total_len = total_size;
    return 0;
}

static uint8_t *emit_be_uint(uint8_t *ptr, uint32_t val, uint8_t len) {
    for (int i = (int)len - 1; i >= 0; i--) {
        *ptr++ = (uint8_t)((val >> (i * 8)) & 0xFF);
    }
    return ptr;
}

size_t apf_gen_get_insn_count(const struct apf_generator *gen) {
    if (!gen || gen->count < PROLOGUE_INSN_COUNT) {
        return 0;
    }
    return gen->count - PROLOGUE_INSN_COUNT;
}

size_t apf_gen_get_program_len(struct apf_generator *gen) {
    if (!gen) return 0;
    size_t total_len = 0;
    enum apf_gen_err saved_err = gen->err;
    size_t saved_err_insn_index = gen->err_insn_index;
    resolve_labels(gen, false, &total_len);
    gen->err = saved_err;
    gen->err_insn_index = saved_err_insn_index;
    return total_len;
}

enum apf_gen_err apf_gen_get_error(const struct apf_generator *gen, size_t *insn_index) {
    if (!gen) {
        if (insn_index) *insn_index = 0;
        return APF_GEN_ERR_INVALID_ARGUMENT;
    }
    if (insn_index) {
        *insn_index = (gen->err != APF_GEN_OK) ? gen->err_insn_index : 0;
    }
    return gen->err;
}

int apf_gen_generate(struct apf_generator *gen, uint8_t *buf, size_t buf_len, size_t *out_len) {
    if (out_len) {
        *out_len = 0;
    }
    if (!gen || !out_len) {
        return apf_gen_fail(gen);
    }
    if (gen->err != APF_GEN_OK) {
        return -1;
    }

    size_t total_size = 0;
    if (resolve_labels(gen, true, &total_size) != 0) {
        return -1;
    }

    if (gen->ram_len < MIN_APF_RAM_LEN || (gen->ram_len % 4) != 0) {
        return apf_gen_fail_with(gen, APF_GEN_ERR_RAM_OVERFLOW);
    }

    uint32_t reserved_cnt =
        (gen->max_cnt > SYSTEM_COUNTER_COUNT) ? gen->max_cnt : SYSTEM_COUNTER_COUNT;
    size_t counter_bytes = 4 * (size_t)reserved_cnt;
    if (total_size + counter_bytes > (size_t)gen->ram_len) {
        return apf_gen_fail_with(gen, APF_GEN_ERR_RAM_OVERFLOW);
    }

    /* Update the prologue EXCEPTIONBUFFER instruction (insn[1]) with remaining RAM size. */
    if (gen->count >= PROLOGUE_INSN_COUNT &&
        gen->insns[1].opcode == EXT_OPCODE &&
        gen->insns[1].imm == EXCEPTIONBUFFER_EXT_OPCODE &&
        gen->insns[1].extra_len == 2 && gen->insns[1].extra_bytes) {
        size_t avail = (size_t)gen->ram_len - counter_bytes - total_size;
        uint16_t except_buf_sz = (avail > 0xFFFFu) ? 0xFFFFu : (uint16_t)avail;
        gen->insns[1].extra_bytes[0] = (uint8_t)((except_buf_sz >> 8) & 0xFF);
        gen->insns[1].extra_bytes[1] = (uint8_t)(except_buf_sz & 0xFF);
    }

    *out_len = total_size;

    if (!buf) {
        return 0;
    }
    if (buf_len < total_size) {
        return -1;
    }

    uint8_t *ptr = buf;
    for (size_t i = 0; i < gen->count; i++) {
        struct apf_instruction *insn = &gen->insns[i];
        uint8_t imm_size = 0;
        uint8_t target_size = 0;
        uint8_t size = get_insn_operand_sizes(insn, &imm_size, &target_size);
        size_t insn_size = 1 + (size_t)imm_size + (size_t)target_size + insn->extra_len;
        if ((size_t)(ptr - buf) + insn_size > total_size) {
            return apf_gen_fail_with(gen, APF_GEN_ERR_BUFFER_TOO_SMALL);
        }
        uint8_t len_field = size_to_len_field(size);

        /* 1-byte instruction header: [opcode (5b)][len_field (2b)][reg (1b)]. */
        *ptr++ = (uint8_t)(((insn->opcode & 0x1F) << 3) |
                           ((len_field & 0x03) << 1) |
                           (insn->reg & 0x01));

        /*
         * In the interpreter, EXT_OPCODE decodes its extended sub-opcode (imm)
         * first in the main loop and any branch target offset second inside
         * the EXT_OPCODE handler, whereas standard branch opcodes decode the
         * branch target offset first and the comparison immediate second.
         */
        if (insn->opcode == EXT_OPCODE) {
            ptr = emit_be_uint(ptr, insn->imm, imm_size);
            ptr = emit_be_uint(ptr, insn->target_offset, target_size);
        } else {
            ptr = emit_be_uint(ptr, insn->target_offset, target_size);
            ptr = emit_be_uint(ptr, insn->imm, imm_size);
        }

        if (insn->extra_len > 0 && insn->extra_bytes) {
            memcpy(ptr, insn->extra_bytes, insn->extra_len);
            ptr += insn->extra_len;
        }
    }

    if ((size_t)(ptr - buf) != total_size) {
        return apf_gen_fail_with(gen, APF_GEN_ERR_BUFFER_TOO_SMALL);
    }

    gen->generated = true;
    return 0;
}
