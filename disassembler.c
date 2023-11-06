/*
 * Copyright 2016, The Android Open Source Project
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

#include <stdint.h>
#include <stdio.h>

#include "v5/apf.h"

// If "c" is of a signed type, generate a compile warning that gets promoted to an error.
// This makes bounds checking simpler because ">= 0" can be avoided. Otherwise adding
// superfluous ">= 0" with unsigned expressions generates compile warnings.
#define ENFORCE_UNSIGNED(c) ((c)==(uint32_t)(c))

static int print_opcode(const char* opcode, char* output_buffer,
                        int output_buffer_len, int offset) {
    int ret = snprintf(output_buffer + offset, output_buffer_len - offset,
                      "%-6s", opcode);
    return ret;
}

// Mapping from opcode number to opcode name.
static const char* opcode_names [] = {
    [LDB_OPCODE] = "ldb",
    [LDH_OPCODE] = "ldh",
    [LDW_OPCODE] = "ldw",
    [LDBX_OPCODE] = "ldbx",
    [LDHX_OPCODE] = "ldhx",
    [LDWX_OPCODE] = "ldwx",
    [ADD_OPCODE] = "add",
    [MUL_OPCODE] = "mul",
    [DIV_OPCODE] = "div",
    [AND_OPCODE] = "and",
    [OR_OPCODE] = "or",
    [SH_OPCODE] = "sh",
    [LI_OPCODE] = "li",
    [JMP_OPCODE] = "jmp",
    [JEQ_OPCODE] = "jeq",
    [JNE_OPCODE] = "jne",
    [JGT_OPCODE] = "jgt",
    [JLT_OPCODE] = "jlt",
    [JSET_OPCODE] = "jset",
    [JNEBS_OPCODE] = "jnebs",
    [LDDW_OPCODE] = "lddw",
    [STDW_OPCODE] = "stdw",
};

static int print_jump_target(uint32_t target, uint32_t program_len,
                             char* output_buffer, int output_buffer_len,
                             int offset) {
    int ret;
    if (target == program_len) {
        ret = snprintf(output_buffer + offset, output_buffer_len - offset,
                       "PASS");
    } else if (target == program_len + 1) {
        ret = snprintf(output_buffer + offset, output_buffer_len - offset,
                       "DROP");
    } else {
        ret = snprintf(output_buffer + offset, output_buffer_len - offset,
                       "%u", target);
    }
    return ret;
}

uint32_t apf_disassemble(const uint8_t* program, uint32_t program_len,
                         uint32_t pc, char* output_buffer,
                         int output_buffer_len) {
    if (pc > program_len + 1) {
        fprintf(stderr, "pc is overflow: pc %d, program_len: %d", pc,
                program_len);
        return pc;
    }
#define ASSERT_RET_INBOUND(x)                                               \
    if ((x) < 0 || (x) >= (output_buffer_len - offset)) return pc + 2

    int offset = 0;
    int ret;
    ret = snprintf(output_buffer + offset, output_buffer_len - offset,
                       "%8u: ", pc);
    ASSERT_RET_INBOUND(ret);
    offset += ret;

    if (pc == program_len) {
        ret = snprintf(output_buffer + offset, output_buffer_len - offset,
                       "PASS");
        ASSERT_RET_INBOUND(ret);
        offset += ret;
        return ++pc;
    }

    if (pc == program_len + 1) {
        ret = snprintf(output_buffer + offset, output_buffer_len - offset,
                       "DROP");
        ASSERT_RET_INBOUND(ret);
        offset += ret;
        return ++pc;
    }

    const uint8_t bytecode = program[pc++];
    const uint32_t opcode = EXTRACT_OPCODE(bytecode);
#define PRINT_OPCODE()                                                         \
    print_opcode(opcode_names[opcode], output_buffer, output_buffer_len, offset)
    const uint32_t reg_num = EXTRACT_REGISTER(bytecode);
    // All instructions have immediate fields, so load them now.
    const uint32_t len_field = EXTRACT_IMM_LENGTH(bytecode);
    uint32_t imm = 0;
    int32_t signed_imm = 0;
    if (len_field != 0) {
        const uint32_t imm_len = 1 << (len_field - 1);
        for (uint32_t i = 0; i < imm_len && pc < program_len; i++)
            imm = (imm << 8) | program[pc++];
        // Sign extend imm into signed_imm.
        signed_imm = imm << ((4 - imm_len) * 8);
        signed_imm >>= (4 - imm_len) * 8;
    }
    switch (opcode) {
        case LDB_OPCODE:
        case LDH_OPCODE:
        case LDW_OPCODE:
            ret = PRINT_OPCODE();
            ASSERT_RET_INBOUND(ret);
            offset += ret;
            ret = snprintf(output_buffer + offset, output_buffer_len - offset,
                          "r%d, [%u]", reg_num, imm);
            ASSERT_RET_INBOUND(ret);
            offset += ret;
            break;
        case LDBX_OPCODE:
        case LDHX_OPCODE:
        case LDWX_OPCODE:
            ret = PRINT_OPCODE();
            ASSERT_RET_INBOUND(ret);
            offset += ret;
            if (imm) {
                ret =
                    snprintf(output_buffer + offset, output_buffer_len - offset,
                             "r%d, [r1+%u]", reg_num, imm);
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            } else {
                ret =
                    snprintf(output_buffer + offset, output_buffer_len - offset,
                             "r%d, [r1]", reg_num);
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            }
            break;
        case JMP_OPCODE:
            ret = PRINT_OPCODE();
            ASSERT_RET_INBOUND(ret);
            offset += ret;
            ret = print_jump_target(pc + imm, program_len, output_buffer,
                                    output_buffer_len, offset);
            ASSERT_RET_INBOUND(ret);
            offset += ret;
            break;
        case JEQ_OPCODE:
        case JNE_OPCODE:
        case JGT_OPCODE:
        case JLT_OPCODE:
        case JSET_OPCODE:
        case JNEBS_OPCODE: {
            ret = PRINT_OPCODE();
            ASSERT_RET_INBOUND(ret);
            offset += ret;
            ret = snprintf(output_buffer + offset, output_buffer_len - offset,
                          "r0, ");
            ASSERT_RET_INBOUND(ret);
            offset += ret;
            // Load second immediate field.
            uint32_t cmp_imm = 0;
            if (reg_num == 1) {
                ret = snprintf(output_buffer + offset,
                               output_buffer_len - offset, "r1, ");
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            } else if (len_field == 0) {
                ret = snprintf(output_buffer + offset,
                               output_buffer_len - offset, "0, ");
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            } else {
                uint32_t cmp_imm_len = 1 << (len_field - 1);
                uint32_t i;
                for (i = 0; i < cmp_imm_len && pc < program_len; i++)
                    cmp_imm = (cmp_imm << 8) | program[pc++];
                ret = snprintf(output_buffer + offset,
                              output_buffer_len - offset, "0x%x, ", cmp_imm);
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            }
            if (opcode == JNEBS_OPCODE) {
                ret = print_jump_target(pc + imm + cmp_imm, program_len,
                                  output_buffer, output_buffer_len, offset);
                ASSERT_RET_INBOUND(ret);
                offset += ret;
                ret = snprintf(output_buffer + offset,
                               output_buffer_len - offset, ", ");
                ASSERT_RET_INBOUND(ret);
                offset += ret;
                while (cmp_imm--) {
                    uint8_t byte = program[pc++];
                    ret = snprintf(output_buffer + offset,
                                  output_buffer_len - offset, "%02x", byte);
                    ASSERT_RET_INBOUND(ret);
                    offset += ret;
                }
            } else {
                ret = print_jump_target(pc + imm, program_len, output_buffer,
                                  output_buffer_len, offset);
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            }
            break;
        }
        case SH_OPCODE:
            ret = PRINT_OPCODE();
            ASSERT_RET_INBOUND(ret);
            offset += ret;
            if (reg_num) {
                ret = snprintf(output_buffer + offset,
                               output_buffer_len - offset, "r0, r1");
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            } else {
                ret =
                    snprintf(output_buffer + offset, output_buffer_len - offset,
                             "r0, %d", signed_imm);
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            }
            break;
        case ADD_OPCODE:
        case MUL_OPCODE:
        case DIV_OPCODE:
        case AND_OPCODE:
        case OR_OPCODE:
            ret = PRINT_OPCODE();
            ASSERT_RET_INBOUND(ret);
            offset += ret;
            if (reg_num) {
                ret = snprintf(output_buffer + offset,
                               output_buffer_len - offset, "r0, r1");
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            } else if (!imm && opcode == DIV_OPCODE) {
                ret = snprintf(output_buffer + offset,
                               output_buffer_len - offset, "pass (div 0)");
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            } else {
                ret = snprintf(output_buffer + offset,
                               output_buffer_len - offset, "r0, %u", imm);
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            }
            break;
        case LI_OPCODE:
            ret = PRINT_OPCODE();
            ASSERT_RET_INBOUND(ret);
            offset += ret;
            ret = snprintf(output_buffer + offset, output_buffer_len - offset,
                           "r%d, %d", reg_num, signed_imm);
            ASSERT_RET_INBOUND(ret);
            offset += ret;
            break;
        case EXT_OPCODE:
            if (
// If LDM_EXT_OPCODE is 0 and imm is compared with it, a compiler error will result,
// instead just enforce that imm is unsigned (so it's always greater or equal to 0).
#if LDM_EXT_OPCODE == 0
                ENFORCE_UNSIGNED(imm) &&
#else
                imm >= LDM_EXT_OPCODE &&
#endif
                imm < (LDM_EXT_OPCODE + MEMORY_ITEMS)) {
                ret = print_opcode("ldm", output_buffer, output_buffer_len,
                                   offset);
                ASSERT_RET_INBOUND(ret);
                offset += ret;
                ret =
                    snprintf(output_buffer + offset, output_buffer_len - offset,
                             "r%d, m[%u]", reg_num, imm - LDM_EXT_OPCODE);
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            } else if (imm >= STM_EXT_OPCODE && imm < (STM_EXT_OPCODE + MEMORY_ITEMS)) {
                ret = print_opcode("stm", output_buffer, output_buffer_len,
                                   offset);
                ASSERT_RET_INBOUND(ret);
                offset += ret;
                ret =
                    snprintf(output_buffer + offset, output_buffer_len - offset,
                             "r%d, m[%u]", reg_num, imm - STM_EXT_OPCODE);
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            } else switch (imm) {
                case NOT_EXT_OPCODE:
                    ret = print_opcode("not", output_buffer,
                                       output_buffer_len, offset);
                    ASSERT_RET_INBOUND(ret);
                    offset += ret;
                    ret = snprintf(output_buffer + offset,
                                   output_buffer_len - offset, "r%d",
                                   reg_num);
                    ASSERT_RET_INBOUND(ret);
                    offset += ret;
                    break;
                case NEG_EXT_OPCODE:
                    ret = print_opcode("neg", output_buffer, output_buffer_len,
                                       offset);
                    ASSERT_RET_INBOUND(ret);
                    offset += ret;
                    ret = snprintf(output_buffer + offset,
                                  output_buffer_len - offset, "r%d", reg_num);
                    ASSERT_RET_INBOUND(ret);
                    offset += ret;
                    break;
                case SWAP_EXT_OPCODE:
                    ret = print_opcode("swap", output_buffer, output_buffer_len,
                                       offset);
                    ASSERT_RET_INBOUND(ret);
                    offset += ret;
                    break;
                case MOV_EXT_OPCODE:
                    ret = print_opcode("mov", output_buffer, output_buffer_len,
                                       offset);
                    ASSERT_RET_INBOUND(ret);
                    offset += ret;
                    ret = snprintf(output_buffer + offset,
                                   output_buffer_len - offset, "r%d, r%d",
                                   reg_num, reg_num ^ 1);
                    ASSERT_RET_INBOUND(ret);
                    offset += ret;
                    break;
                case ALLOC_EXT_OPCODE:
                    ret = print_opcode("alloc", output_buffer,
                                       output_buffer_len, offset);
                    ASSERT_RET_INBOUND(ret);
                    offset += ret;
                    ret =
                        snprintf(output_buffer + offset,
                                 output_buffer_len - offset, "r%d", reg_num);
                    ASSERT_RET_INBOUND(ret);
                    offset += ret;
                    break;
                case TRANS_EXT_OPCODE:
                    ret = print_opcode("trans", output_buffer,
                                       output_buffer_len, offset);
                    ASSERT_RET_INBOUND(ret);
                    offset += ret;
                    ret =
                        snprintf(output_buffer + offset,
                                 output_buffer_len - offset, "r%d", reg_num);
                    ASSERT_RET_INBOUND(ret);
                    offset += ret;
                    break;
                default:
                    ret = snprintf(output_buffer + offset,
                                   output_buffer_len - offset, "unknown_ext %u",
                                   imm);
                    ASSERT_RET_INBOUND(ret);
                    offset += ret;
                    break;
            }
            break;
        case LDDW_OPCODE:
        case STDW_OPCODE:
            ret = PRINT_OPCODE();
            ASSERT_RET_INBOUND(ret);
            offset += ret;
            if (signed_imm > 0) {
                ret = snprintf(output_buffer + offset,
                           output_buffer_len - offset, "r%u, [r%u+%d]", reg_num,
                           reg_num ^ 1, signed_imm);
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            } else if (signed_imm < 0) {
                ret = snprintf(output_buffer + offset,
                               output_buffer_len - offset, "r%u, [r%u-%d]",
                               reg_num, reg_num ^ 1, -signed_imm);
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            } else {
                ret = snprintf(output_buffer + offset,
                               output_buffer_len - offset, "r%u, [r%u]", reg_num,
                               reg_num ^ 1);
                ASSERT_RET_INBOUND(ret);
                offset += ret;
            }
            break;

        // Unknown opcode
        default:
            ret = snprintf(output_buffer + offset, output_buffer_len - offset,
                           "unknown %u", opcode);
            ASSERT_RET_INBOUND(ret);
            offset += ret;
            break;
    }
    return pc;
}
