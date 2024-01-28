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
#include <stdarg.h>

typedef enum { false, true } bool;

#include "v5/apf_defs.h"
#include "v5/apf.h"
#include "disassembler.h"

// If "c" is of a signed type, generate a compile warning that gets promoted to an error.
// This makes bounds checking simpler because ">= 0" can be avoided. Otherwise adding
// superfluous ">= 0" with unsigned expressions generates compile warnings.
#define ENFORCE_UNSIGNED(c) ((c)==(uint32_t)(c))

char print_buf[512];
char* buf_ptr;
int buf_remain;

__attribute__ ((format (printf, 1, 2) ))
static void bprintf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buf_ptr, buf_remain, format, args);
    va_end(args);
    if (ret < 0) return;
    if (ret >= buf_remain) ret = buf_remain;
    buf_ptr += ret;
    buf_remain -= ret;
}

static void print_opcode(const char* opcode) {
    bprintf("%-12s", opcode);
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
    [WRITE_OPCODE] = "write",
};

static void print_jump_target(uint32_t target, uint32_t program_len) {
    if (target == program_len) {
        bprintf("PASS");
    } else if (target == program_len + 1) {
        bprintf("DROP");
    } else {
        bprintf("%u", target);
    }
}

const char* apf_disassemble(const uint8_t* program, uint32_t program_len, uint32_t* const pc) {
    buf_ptr = print_buf;
    buf_remain = sizeof(print_buf);
    if (*pc > program_len + 1) {
        bprintf("pc is overflow: pc %d, program_len: %d", *pc, program_len);
        return print_buf;
    }

    bprintf("%8u: ", *pc);

    if (*pc == program_len) {
        bprintf("PASS");
        ++(*pc);
        return print_buf;
    }

    if (*pc == program_len + 1) {
        bprintf("DROP");
        ++(*pc);
        return print_buf;
    }

    const uint8_t bytecode = program[(*pc)++];
    const uint32_t opcode = EXTRACT_OPCODE(bytecode);

#define PRINT_OPCODE() print_opcode(opcode_names[opcode])
#define DECODE_IMM(value, length)                                              \
    for (uint32_t i = 0; i < (length) && *pc < program_len; i++)               \
        value = (value << 8) | program[(*pc)++]

    const uint32_t reg_num = EXTRACT_REGISTER(bytecode);
    // All instructions have immediate fields, so load them now.
    const uint32_t len_field = EXTRACT_IMM_LENGTH(bytecode);
    uint32_t imm = 0;
    int32_t signed_imm = 0;
    if (len_field != 0) {
        const uint32_t imm_len = 1 << (len_field - 1);
        DECODE_IMM(imm, imm_len);
        // Sign extend imm into signed_imm.
        signed_imm = imm << ((4 - imm_len) * 8);
        signed_imm >>= (4 - imm_len) * 8;
    }
    switch (opcode) {
        case LDB_OPCODE:
        case LDH_OPCODE:
        case LDW_OPCODE:
            PRINT_OPCODE();
            bprintf("r%d, [%u]", reg_num, imm);
            break;
        case LDBX_OPCODE:
        case LDHX_OPCODE:
        case LDWX_OPCODE:
            PRINT_OPCODE();
            if (imm) {
                bprintf("r%d, [r1+%u]", reg_num, imm);
            } else {
                bprintf("r%d, [r1]", reg_num);
            }
            break;
        case JMP_OPCODE:
            PRINT_OPCODE();
            print_jump_target(*pc + imm, program_len);
            break;
        case JEQ_OPCODE:
        case JNE_OPCODE:
        case JGT_OPCODE:
        case JLT_OPCODE:
        case JSET_OPCODE:
        case JNEBS_OPCODE: {
            PRINT_OPCODE();
            bprintf("r0, ");
            // Load second immediate field.
            uint32_t cmp_imm = 0;
            if (reg_num == 1) {
                bprintf("r1, ");
            } else if (len_field == 0) {
                bprintf("0, ");
            } else {
                DECODE_IMM(cmp_imm, 1 << (len_field - 1));
                bprintf("0x%x, ", cmp_imm);
            }
            if (opcode == JNEBS_OPCODE) {
                print_jump_target(*pc + imm + cmp_imm, program_len);
                bprintf(", ");
                while (cmp_imm--) {
                    uint8_t byte = program[(*pc)++];
                    bprintf("%02x", byte);
                }
            } else {
                print_jump_target(*pc + imm, program_len);
            }
            break;
        }
        case SH_OPCODE:
            PRINT_OPCODE();
            if (reg_num) {
                bprintf("r0, r1");
            } else {
                bprintf("r0, %d", signed_imm);
            }
            break;
        case ADD_OPCODE:
        case MUL_OPCODE:
        case DIV_OPCODE:
        case AND_OPCODE:
        case OR_OPCODE:
            PRINT_OPCODE();
            if (reg_num) {
                bprintf("r0, r1");
            } else if (!imm && opcode == DIV_OPCODE) {
                bprintf("pass (div 0)");
            } else {
                bprintf("r0, %u", imm);
            }
            break;
        case LI_OPCODE:
            PRINT_OPCODE();
            bprintf("r%d, %d", reg_num, signed_imm);
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
                print_opcode("ldm");
                bprintf("r%d, m[%u]", reg_num, imm - LDM_EXT_OPCODE);
            } else if (imm >= STM_EXT_OPCODE && imm < (STM_EXT_OPCODE + MEMORY_ITEMS)) {
                print_opcode("stm");
                bprintf("r%d, m[%u]", reg_num, imm - STM_EXT_OPCODE);
            } else switch (imm) {
                case NOT_EXT_OPCODE:
                    print_opcode("not");
                    bprintf("r%d", reg_num);
                    break;
                case NEG_EXT_OPCODE:
                    print_opcode("neg");
                    bprintf("r%d", reg_num);
                    break;
                case SWAP_EXT_OPCODE:
                    print_opcode("swap");
                    break;
                case MOV_EXT_OPCODE:
                    print_opcode("mov");
                    bprintf("r%d, r%d", reg_num, reg_num ^ 1);
                    break;
                case ALLOCATE_EXT_OPCODE:
                    print_opcode("alloc");
                    bprintf("r%d", reg_num);
                    break;
                case TRANSMITDISCARD_EXT_OPCODE:
                    print_opcode("trans");
                    bprintf("r%d", reg_num);
                    break;
                case EWRITE1_EXT_OPCODE:
                case EWRITE2_EXT_OPCODE:
                case EWRITE4_EXT_OPCODE: {
                    print_opcode("write");
                    bprintf("r%d, %d", reg_num, 1 << (imm - EWRITE1_EXT_OPCODE));
                    break;
                }
                case EDATACOPY_EXT_OPCODE:
                case EPKTCOPY_EXT_OPCODE: {
                    if (imm == EPKTCOPY_EXT_OPCODE) {
                        print_opcode("pcopy");
                    } else {
                        print_opcode("dcopy");
                    }
                    if (len_field > 0) {
                        const uint32_t imm_len = 1 << (len_field - 1);
                        uint32_t relative_offs = 0;
                        DECODE_IMM(relative_offs, imm_len);
                        uint32_t copy_len = 0;
                        DECODE_IMM(copy_len, 1);

                        bprintf("[r%u+%d], %d", reg_num, relative_offs, copy_len);
                    }
                    break;
                }
                default:
                    bprintf("unknown_ext %u", imm);
                    break;
            }
            break;
        case LDDW_OPCODE:
        case STDW_OPCODE:
            PRINT_OPCODE();
            if (signed_imm > 0) {
                bprintf("r%u, [r%u+%d]", reg_num, reg_num ^ 1, signed_imm);
            } else if (signed_imm < 0) {
                bprintf("r%u, [r%u-%d]", reg_num, reg_num ^ 1, -signed_imm);
            } else {
                bprintf("r%u, [r%u]", reg_num, reg_num ^ 1);
            }
            break;
        case WRITE_OPCODE: {
            PRINT_OPCODE();
            uint32_t write_len = 1 << (len_field - 1);
            if (write_len > 0) {
                bprintf("0x");
            }
            for (uint32_t i = 0; i < write_len; ++i) {
                uint8_t byte =
                    (uint8_t) ((imm >> (write_len - 1 - i) * 8) & 0xff);
                bprintf("%02x", byte);

            }
            break;
        }
        case PKTDATACOPY_OPCODE: {
            if (reg_num == 0) {
                print_opcode("pcopy");
            } else {
                print_opcode("dcopy");
            }
            if (len_field > 0) {
                uint32_t src_offs = imm;
                uint32_t copy_len = 0;
                DECODE_IMM(copy_len, 1);
                bprintf("%d, %d", src_offs, copy_len);
            }
            break;
        }
        // Unknown opcode
        default:
            bprintf("unknown %u", opcode);
            break;
    }
    return print_buf;
}
