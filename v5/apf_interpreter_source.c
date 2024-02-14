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

// TODO: Remove the dependency of the standard library and make the interpreter self-contained.
#include <string.h>// For memcmp

typedef enum { false, true } bool;

#include "apf_defs.h"
#include "apf.h"
#include "apf_utils.h"
#include "apf_dns.h"
#include "apf_checksum.h"

// User hook for interpreter debug tracing.
#ifdef APF_TRACE_HOOK
extern void APF_TRACE_HOOK(u32 pc, const u32* regs, const u8* program,
                           u32 program_len, const u8 *packet, u32 packet_len,
                           const u32* memory, u32 ram_len);
#else
#define APF_TRACE_HOOK(pc, regs, program, program_len, packet, packet_len, memory, memory_len) \
    do { /* nop*/                                                                              \
    } while (0)
#endif

// Frame header size should be 14
#define APF_FRAME_HEADER_SIZE 14
// Return code indicating "packet" should accepted.
#define PASS_PACKET 1
// Return code indicating "packet" should be dropped.
#define DROP_PACKET 0
// Verify an internal condition and accept packet if it fails.
#define ASSERT_RETURN(c) if (!(c)) return PASS_PACKET
// If "c" is of an unsigned type, generate a compile warning that gets promoted to an error.
// This makes bounds checking simpler because ">= 0" can be avoided. Otherwise adding
// superfluous ">= 0" with unsigned expressions generates compile warnings.
#define ENFORCE_UNSIGNED(c) ((c)==(u32)(c))

u32 apf_version(void) {
    return 20240124;
}

int apf_run(void* ctx, u8* const program, const u32 program_len,
            const u32 ram_len, const u8* const packet,
            const u32 packet_len, const u32 filter_age_16384ths) {
// Is offset within program bounds?
#define IN_PROGRAM_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < program_len)
// Is offset within ram bounds?
#define IN_RAM_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < ram_len)
// Is offset within packet bounds?
#define IN_PACKET_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < packet_len)
// Is access to offset |p| length |size| within data bounds?
#define IN_DATA_BOUNDS(p, size) (ENFORCE_UNSIGNED(p) && \
                                 ENFORCE_UNSIGNED(size) && \
                                 (p) + (size) <= ram_len && \
                                 (p) >= program_len && \
                                 (p) + (size) >= (p))  // catch wraparounds
// Accept packet if not within program bounds
#define ASSERT_IN_PROGRAM_BOUNDS(p) ASSERT_RETURN(IN_PROGRAM_BOUNDS(p))
// Accept packet if not within ram bounds
#define ASSERT_IN_RAM_BOUNDS(p) ASSERT_RETURN(IN_RAM_BOUNDS(p))
// Accept packet if not within packet bounds
#define ASSERT_IN_PACKET_BOUNDS(p) ASSERT_RETURN(IN_PACKET_BOUNDS(p))
// Accept packet if not within data bounds
#define ASSERT_IN_DATA_BOUNDS(p, size) ASSERT_RETURN(IN_DATA_BOUNDS(p, size))

  // Program counter.
  u32 pc = 0;
// Accept packet if not within program or not ahead of program counter
#define ASSERT_FORWARD_IN_PROGRAM(p) ASSERT_RETURN(IN_PROGRAM_BOUNDS(p) && (p) >= pc)
  // Memory slot values.
  memory_type mem = {};
  // Fill in pre-filled memory slot values.
  mem.named.tx_buf_offset = 0;
  mem.named.program_size = program_len;
  mem.named.ram_len = ram_len;
  mem.named.packet_size = packet_len;
  mem.named.filter_age = filter_age_16384ths >> 14;
  mem.named.filter_age_16384ths = filter_age_16384ths;
  ASSERT_IN_PACKET_BOUNDS(APF_FRAME_HEADER_SIZE);
  // Only populate if IP version is IPv4.
  if ((packet[APF_FRAME_HEADER_SIZE] & 0xf0) == 0x40) {
      mem.named.ipv4_header_size = (packet[APF_FRAME_HEADER_SIZE] & 15) * 4;
  }
  // Register values.
  u32 registers[2] = {};
  // Count of instructions remaining to execute. This is done to ensure an
  // upper bound on execution time. It should never be hit and is only for
  // safety. Initialize to the number of bytes in the program which is an
  // upper bound on the number of instructions in the program.
  u32 instructions_remaining = program_len;

  // The output buffer pointer
  u8* tx_buf = NULL;
  // The length of the output buffer
  u32 tx_buf_len = 0;
// Is access to offset |p| length |size| within output buffer bounds?
#define IN_OUTPUT_BOUNDS(p, size) (ENFORCE_UNSIGNED(p) && \
                                 ENFORCE_UNSIGNED(size) && \
                                 (p) + (size) <= tx_buf_len && \
                                 (p) + (size) >= (p))
// Accept packet if not write within allocated output buffer
#define ASSERT_IN_OUTPUT_BOUNDS(p, size) ASSERT_RETURN(IN_OUTPUT_BOUNDS(p, size))

// Decode the imm length.
#define DECODE_IMM(value, length)                                              \
    do {                                                                       \
        ASSERT_FORWARD_IN_PROGRAM(pc + length - 1);                            \
        value = 0;                                                             \
        u32 i;                                                            \
        for (i = 0; i < (length) && pc < program_len; i++)                     \
            value = (value << 8) | program[pc++];                              \
    } while (0)

  do {
      APF_TRACE_HOOK(pc, registers, program, program_len, packet, packet_len, mem.slot, ram_len);
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
      // All instructions have immediate fields, so load them now.
      const u32 len_field = EXTRACT_IMM_LENGTH(bytecode);
      u32 imm = 0;
      s32 signed_imm = 0;
      if (len_field != 0) {
          const u32 imm_len = 1 << (len_field - 1);
          ASSERT_FORWARD_IN_PROGRAM(pc + imm_len - 1);
          DECODE_IMM(imm, imm_len);
          // Sign extend imm into signed_imm.
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
                  // Note: this can overflow and actually decrease offs.
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
                  // Immediately enclosing switch statement guarantees
                  // opcode cannot be any other value.
              }
              const u32 end_offs = offs + (load_size - 1);
              // Catch overflow/wrap-around.
              ASSERT_RETURN(end_offs >= offs);
              ASSERT_IN_PACKET_BOUNDS(end_offs);
              u32 val = 0;
              while (load_size--)
                  val = (val << 8) | packet[offs++];
              REG = val;
              break;
          }
          case JMP_OPCODE:
              // This can jump backwards. Infinite looping prevented by instructions_remaining.
              pc += imm;
              break;
          case JEQ_OPCODE:
          case JNE_OPCODE:
          case JGT_OPCODE:
          case JLT_OPCODE:
          case JSET_OPCODE:
          case JBSMATCH_OPCODE: {
              // Load second immediate field.
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
                  case JBSMATCH_OPCODE: {
                      // cmp_imm is size in bytes of data to compare.
                      // pc is offset of program bytes to compare.
                      // imm is jump target offset.
                      // REG is offset of packet bytes to compare.
                      ASSERT_FORWARD_IN_PROGRAM(pc + cmp_imm - 1);
                      ASSERT_IN_PACKET_BOUNDS(REG);
                      const u32 last_packet_offs = REG + cmp_imm - 1;
                      ASSERT_RETURN(last_packet_offs >= REG);
                      ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
                      if (memcmp(program + pc, packet + REG, cmp_imm))
                          pc += imm;
                      // skip past comparison bytes
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
// If LDM_EXT_OPCODE is 0 and imm is compared with it, a compiler error will result,
// instead just enforce that imm is unsigned (so it's always greater or equal to 0).
#if LDM_EXT_OPCODE == 0
                  ENFORCE_UNSIGNED(imm) &&
#else
                  imm >= LDM_EXT_OPCODE &&
#endif
                  imm < (LDM_EXT_OPCODE + MEMORY_ITEMS)) {
                REG = mem.slot[imm - LDM_EXT_OPCODE];
              } else if (imm >= STM_EXT_OPCODE && imm < (STM_EXT_OPCODE + MEMORY_ITEMS)) {
                mem.slot[imm - STM_EXT_OPCODE] = REG;
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
                    ASSERT_RETURN(tx_buf == NULL);
                    if (reg_num == 0) {
                        tx_buf_len = REG;
                    } else {
                        DECODE_IMM(tx_buf_len, 2);
                    }
                    // checksumming functions requires minimum 74 byte buffer for correctness
                    if (tx_buf_len < 74) tx_buf_len = 74;
                    tx_buf = apf_allocate_buffer(ctx, tx_buf_len);
                    ASSERT_RETURN(tx_buf != NULL);
                    memset(tx_buf, 0, tx_buf_len);
                    mem.named.tx_buf_offset = 0;
                    break;
                  case TRANSMITDISCARD_EXT_OPCODE:
                    ASSERT_RETURN(tx_buf != NULL);
                    u32 pkt_len = mem.named.tx_buf_offset;
                    // If pkt_len > allocate_buffer_len, it means sth. wrong
                    // happened and the tx_buf should be deallocated.
                    if (pkt_len > tx_buf_len) {
                        apf_transmit_buffer(ctx, tx_buf, 0 /* len */, 0 /* dscp */);
                        tx_buf = NULL;
                        tx_buf_len = 0;
                        return PASS_PACKET;
                    }
                    // tx_buf_len cannot be large because we'd run out of RAM,
                    // so the above unsigned comparison effectively guarantees casting pkt_len
                    // to a signed value does not result in it going negative.
                    int dscp = calculate_checksum_and_return_dscp(tx_buf, (s32)pkt_len);
                    int ret = apf_transmit_buffer(ctx, tx_buf, pkt_len, dscp);
                    tx_buf = NULL;
                    tx_buf_len = 0;
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
                    while (pc + 1 < program_len && !(program[pc] == 0 && program[pc + 1] == 0)) {
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
                  default:  // Unknown extended opcode
                    return PASS_PACKET;  // Bail out
              }
              break;
          case LDDW_OPCODE: {
              u32 offs = OTHER_REG + (u32)signed_imm;
              u32 size = 4;
              u32 val = 0;
              // Negative offsets wrap around the end of the address space.
              // This allows us to efficiently access the end of the
              // address space with one-byte immediates without using %=.
              if (offs & 0x80000000) {
                  offs = ram_len + offs;  // unsigned overflow intended
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
              // Negative offsets wrap around the end of the address space.
              // This allows us to efficiently access the end of the
              // address space with one-byte immediates without using %=.
              if (offs & 0x80000000) {
                  offs = ram_len + offs;  // unsigned overflow intended
              }
              ASSERT_IN_DATA_BOUNDS(offs, size);
              while (size--) {
                  program[offs++] = (val >> 24);
                  val <<= 8;
              }
              break;
          }
          case WRITE_OPCODE: {
              ASSERT_RETURN(tx_buf != NULL);
              ASSERT_RETURN(len_field > 0);
              u32 offs = mem.named.tx_buf_offset;
              const u32 write_len = 1 << (len_field - 1);
              ASSERT_RETURN(write_len > 0);
              ASSERT_IN_OUTPUT_BOUNDS(offs, write_len);
              u32 i;
              for (i = 0; i < write_len; ++i) {
                  *(tx_buf + offs) =
                      (u8) ((imm >> (write_len - 1 - i) * 8) & 0xff);
                  offs++;
              }
              mem.named.tx_buf_offset = offs;
              break;
          }
          case PKTDATACOPY_OPCODE: {
              ASSERT_RETURN(tx_buf != NULL);
              u32 src_offs = imm;
              u32 copy_len;
              DECODE_IMM(copy_len, 1);
              u32 dst_offs = mem.named.tx_buf_offset;
              ASSERT_IN_OUTPUT_BOUNDS(dst_offs, copy_len);
              // reg_num == 0 copy from packet, reg_num == 1 copy from data.
              if (reg_num == 0) {
                  ASSERT_IN_PACKET_BOUNDS(src_offs);
                  const u32 last_packet_offs = src_offs + copy_len - 1;
                  ASSERT_RETURN(last_packet_offs >= src_offs);
                  ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
                  memmove(tx_buf + dst_offs, packet + src_offs, copy_len);
              } else {
                  ASSERT_IN_RAM_BOUNDS(src_offs + copy_len - 1);
                  memmove(tx_buf + dst_offs, program + src_offs, copy_len);
              }
              dst_offs += copy_len;
              mem.named.tx_buf_offset = dst_offs;
              break;
          }
          default:  // Unknown opcode
              return PASS_PACKET;  // Bail out
      }
  } while (instructions_remaining--);
  return PASS_PACKET;
}
