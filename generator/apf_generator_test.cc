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

#include <gtest/gtest.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <memory>
#include <string>
#include <vector>

#include "disassembler.h"

namespace {

constexpr uint32_t kDefaultRamLen = 4096;

struct ApfGeneratorDeleter {
    void operator()(struct apf_generator *gen) const { apf_generator_free(gen); }
};

struct FreeDeleter {
    void operator()(void *ptr) const { free(ptr); }
};

using UniqueApfGenerator = std::unique_ptr<struct apf_generator, ApfGeneratorDeleter>;
using UniqueByteBuf = std::unique_ptr<uint8_t, FreeDeleter>;

UniqueApfGenerator AllocGen(uint32_t version = APF_VERSION_61,
                            uint32_t ram_len = kDefaultRamLen) {
    return UniqueApfGenerator(apf_generator_alloc(version, ram_len));
}

UniqueByteBuf GenerateProgram(struct apf_generator *gen, size_t *out_len) {
    if (!out_len) {
        return nullptr;
    }
    size_t req_len = 0;
    if (apf_gen_generate(gen, nullptr, 0, &req_len) != 0) {
        *out_len = 0;
        return nullptr;
    }
    UniqueByteBuf buf(static_cast<uint8_t *>(malloc(req_len > 0 ? req_len : 1)));
    if (!buf) {
        *out_len = 0;
        return nullptr;
    }
    if (apf_gen_generate(gen, buf.get(), req_len, out_len) != 0) {
        return nullptr;
    }
    EXPECT_EQ(*out_len, req_len);
    return buf;
}

std::string Trim(const std::string &s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::vector<std::string> DisassembleProgram(const uint8_t *prog, size_t len) {
    std::vector<std::string> lines;
    for (uint32_t pc = 0; pc < len;) {
        const disas_ret ret =
            apf_disassemble(prog, static_cast<uint32_t>(len), &pc, true /* is_v6 */);
        lines.push_back(Trim(ret.content));
    }
    return lines;
}

uint8_t HexNibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0;
}

std::vector<uint8_t> HexToBytes(const char *hex) {
    std::vector<uint8_t> out;
    size_t len = strlen(hex);
    out.reserve(len / 2);
    for (size_t i = 0; i + 1 < len; i += 2) {
        out.push_back(static_cast<uint8_t>((HexNibble(hex[i]) << 4) | HexNibble(hex[i + 1])));
    }
    return out;
}

int AddJbsneHex(struct apf_generator *gen, apf_label tgt_label, const char *hex) {
    std::vector<uint8_t> bytes = HexToBytes(hex);
    return apf_gen_add_jbsne(gen, tgt_label, bytes.data(), static_cast<uint16_t>(bytes.size()));
}

}  // namespace

TEST(ApfGeneratorTest, testApfInstructions) {
    // Freshly allocated program auto-emits 3-byte empty jmpdata + 4-byte debugbuf prologue
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        size_t len = 999;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 7u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{"0: data        0,", "3: debugbuf    size=4065"}));
    }

    // Test pass opcode: opcode=0 (PASSDROP), imm_len=0, R=0 -> 0x00
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_pass(gen.get());
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 8u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4064",
                      "7: pass",
                  }));
    }

    // Test jumping to pass label (target offset = 0): opcode=14 (JMP), imm_len=0, R=0 -> 0x70
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_jmp(gen.get(), APF_LABEL_PASS);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 8u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4064",
                      "7: jmp         PASS",
                  }));
    }

    // Test jumping to drop label (target offset = 1): opcode=14 (JMP), imm_len=1, R=0, imm=1
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_jmp(gen.get(), APF_LABEL_DROP);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 9u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4063",
                      "7: jmp         DROP",
                  }));
    }

    // Test drop opcode: opcode=0 (PASSDROP), imm_len=0, R=1 -> 0x01
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_drop(gen.get());
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 8u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4064",
                      "7: drop",
                  }));
    }

    // Test jumping if equal to 0: opcode=15 (JEQ), imm_len=1, R=0, target=1, val=0
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_jeq(gen.get(), 0, APF_LABEL_DROP);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 10u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4062",
                      "7: jeq         r0, 0x0, DROP",
                  }));
    }

    // Test jumping if not equal to 0: opcode=16 (JNE), imm_len=1, R=0, target=1, val=0
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_jne(gen.get(), 0, APF_LABEL_DROP);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 10u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4062",
                      "7: jne         r0, 0x0, DROP",
                  }));
    }

    // Test R0 vs R1 branch comparisons (apf_gen_add_j*_r1 emits only target offset)
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_jeq_r1(gen.get(), apf_gen_cnt_drop_label(7));
        apf_gen_add_jne_r1(gen.get(), APF_LABEL_PASS);
        apf_gen_add_jgt_r1(gen.get(), APF_LABEL_DROP);
        apf_gen_add_jlt_r1(gen.get(), APF_LABEL_PASS);
        apf_gen_add_jset_r1(gen.get(), APF_LABEL_DROP);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 17u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4051",
                      "7: jeq         r0, r1, cnt_and_drop[cnt=7]",
                      "9: jne         r0, r1, PASS",
                      "11: jgt         r0, r1, DROP",
                      "13: jlt         r0, r1, PASS",
                      "15: jset        r0, r1, DROP",
                  }));
    }
}

TEST(ApfGeneratorTest, testImmediateEncoding) {
    // 0-byte immediate: li R0, 0
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R0, 0);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 8u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4064",
                      "7: li          r0, 0",
                  }));
    }

    // 1-byte immediate: li R0, 42
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R0, 42);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 9u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4063",
                      "7: li          r0, 42",
                  }));
    }

    // 2-byte immediate: li R1, 0x1234
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R1, 0x1234);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 10u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4062",
                      "7: li          r1, 4660",
                  }));
    }

    // 4-byte immediate: li R0, 0x12345678
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R0, 0x12345678);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 12u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4060",
                      "7: li          r0, 305419896",
                  }));
    }
}

TEST(ApfGeneratorTest, testNegativeImmediateEncoding) {
    // 1-byte negative immediate: li R0, -42
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R0, -42);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 9u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4063",
                      "7: li          r0, -42",
                  }));
    }

    // 2-byte negative immediate: li R1, -0x1122
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R1, -0x1122);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 10u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4062",
                      "7: li          r1, -4386",
                  }));
    }

    // 4-byte negative immediate: li R0, -0x11223344
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R0, -0x11223344);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 12u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4060",
                      "7: li          r0, -287454020",
                  }));
    }
}

TEST(ApfGeneratorTest, testInstructionCountAndProgramLen) {
    auto gen = AllocGen();
    ASSERT_NE(gen, nullptr);
    EXPECT_EQ(apf_gen_get_insn_count(gen.get()), 0u);
    EXPECT_EQ(apf_gen_get_program_len(gen.get()), 7u);

    apf_gen_add_ldb(gen.get(), APF_REG_R0, 5);
    EXPECT_EQ(apf_gen_get_insn_count(gen.get()), 1u);
    EXPECT_EQ(apf_gen_get_program_len(gen.get()), 9u);

    apf_gen_add_jeq(gen.get(), 10, apf_gen_cnt_drop_label(9));
    EXPECT_EQ(apf_gen_get_insn_count(gen.get()), 2u);
    EXPECT_EQ(apf_gen_get_program_len(gen.get()), 12u);

    apf_gen_add_pass(gen.get());
    EXPECT_EQ(apf_gen_get_insn_count(gen.get()), 3u);
    EXPECT_EQ(apf_gen_get_program_len(gen.get()), 13u);

    size_t len = 0;
    auto buf = GenerateProgram(gen.get(), &len);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(len, 13u);
    EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
    EXPECT_EQ(DisassembleProgram(buf.get(), len),
              (std::vector<std::string>{
                  "0: data        0,",
                  "3: debugbuf    size=4047",
                  "7: ldb         r0, [5]",
                  "9: jeq         r0, 0xa, cnt_and_drop[cnt=9]",
                  "12: pass",
              }));
}

TEST(ApfGeneratorTest, testVersionGuards) {
    // Versions prior to APFv6.1 (APFv2, APFv3, APFv4, APFv6.0) MUST be rejected
    EXPECT_EQ(AllocGen(2), nullptr);
    EXPECT_EQ(AllocGen(3), nullptr);
    EXPECT_EQ(AllocGen(4), nullptr);
    EXPECT_EQ(AllocGen(6000), nullptr);

    // APFv6.1+ Generator should allocate successfully
    auto gen_v61 = AllocGen(APF_VERSION_61);
    ASSERT_NE(gen_v61, nullptr);
    apf_gen_add_ldb(gen_v61.get(), APF_REG_R0, 0);
    size_t len = 0;
    auto buf = GenerateProgram(gen_v61.get(), &len);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(DisassembleProgram(buf.get(), len),
              (std::vector<std::string>{
                  "0: data        0,",
                  "3: debugbuf    size=4064",
                  "7: ldb         r0, [0]",
              }));
}

TEST(ApfGeneratorTest, testArithmeticLoadsAndMemoryInstructions) {
    // 1. Test sign-extension protection on AND/ADD/SH (e.g., 0xFF must use 2 bytes 0x00, 0xFF)
    //    and APFv6 arithmetic immediates targeting R1 (R=1, len_field > 0)
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_and(gen.get(), APF_REG_R0, 0xFF);
        apf_gen_add_add(gen.get(), APF_REG_R0, 200);
        apf_gen_add_sh(gen.get(), APF_REG_R0, -4);
        apf_gen_add_and(gen.get(), APF_REG_R0, 0);
        apf_gen_add_add(gen.get(), APF_REG_R1, 10);
        apf_gen_add_mul(gen.get(), APF_REG_R1, 20);
        apf_gen_add_div(gen.get(), APF_REG_R1, 30);
        apf_gen_add_and(gen.get(), APF_REG_R1, -4);
        apf_gen_add_or(gen.get(), APF_REG_R1, 0x80);
        apf_gen_add_sh(gen.get(), APF_REG_R1, 4);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 29u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4043",
                      "7: and         r0, 0xff",
                      "10: add         r0, 200",
                      "13: sh          r0, -4",
                      "15: and         r0, 0x0",
                      "17: add         r1, 10",
                      "19: mul         r1, 20",
                      "21: div         r1, 30",
                      "23: and         r1, 0xfffffffc",
                      "25: or          r1, 0x80",
                      "27: sh          r1, 4",
                  }));
    }

    // 2. Test register-to-register arithmetic (ADD, MUL, DIV, AND, OR, SH with 0-byte immediate)
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_add_reg(gen.get(), APF_REG_R0);
        apf_gen_add_mul_reg(gen.get(), APF_REG_R0);
        apf_gen_add_div_reg(gen.get(), APF_REG_R0);
        apf_gen_add_and_reg(gen.get(), APF_REG_R1);
        apf_gen_add_or_reg(gen.get(), APF_REG_R0);
        apf_gen_add_sh_reg(gen.get(), APF_REG_R0);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 13u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4059",
                      "7: add         r0, r1",
                      "8: mul         r0, r1",
                      "9: div         r0, r1",
                      "10: and         r1, r0",
                      "11: or          r0, r1",
                      "12: sh          r0, r1",
                  }));
    }

    // 3. Test loads, branches, JBSNE/JBSEQ (including max 2047-byte length), LDDW/STDW counters,
    //    and EXT opcodes (LDM, STM, NOT, NEG, SWAP, MOV)
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        const apf_label lbl1 = apf_gen_alloc_label(gen.get());
        const apf_label lbl2 = apf_gen_alloc_label(gen.get());
        const uint8_t oui[4] = {0x50, 0x6F, 0x9A, 0x13};
        const std::vector<uint8_t> max_jbs(2048, 0xAA);
        apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
        apf_gen_add_ldw(gen.get(), APF_REG_R1, 14);
        apf_gen_add_ldbx(gen.get(), APF_REG_R0, 1);
        apf_gen_add_ldhx(gen.get(), APF_REG_R0, 2);
        apf_gen_add_ldwx(gen.get(), APF_REG_R0, 4);
        apf_gen_add_jgt(gen.get(), 100, lbl1);
        apf_gen_add_jlt(gen.get(), 10, lbl1);
        apf_gen_add_jset(gen.get(), 0x01, lbl1);
        apf_gen_add_jbsne(gen.get(), lbl1, oui, sizeof(oui));
        apf_gen_add_jbseq(gen.get(), lbl1, oui, sizeof(oui));
        apf_gen_define_label(gen.get(), lbl1);
        apf_gen_add_jbsne(gen.get(), lbl2, max_jbs.data(), 2047);
        apf_gen_define_label(gen.get(), lbl2);
        apf_gen_add_ldm(gen.get(), APF_REG_R0, APF_MEM_PACKET_SIZE);
        apf_gen_add_stm(gen.get(), APF_REG_R0, 0);
        apf_gen_add_not(gen.get(), APF_REG_R0);
        apf_gen_add_neg(gen.get(), APF_REG_R1);
        apf_gen_add_swap(gen.get());
        apf_gen_add_mov(gen.get(), APF_REG_R1);
        apf_gen_add_lddw(gen.get(), APF_REG_R0, 7);
        apf_gen_add_stdw(gen.get(), APF_REG_R0, 7);

        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));

        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=1960",
                      "7: ldh         r0, [12]",
                      "9: ldw         r1, [14]",
                      "11: ldbx        r0, [r1+1]",
                      "13: ldhx        r0, [r1+2]",
                      "15: ldwx        r0, [r1+4]",
                      "17: jgt         r0, 0x64, 40",
                      "20: jlt         r0, 0xa, 40",
                      "23: jset        r0, 0x1, 40",
                      "26: jbsne       r0, (4), 40, 506f9a13",
                      "33: jbseq       r0, (4), 40, 506f9a13",
                      "40: jbsne       r0, (2047), 2092, " + std::string(2047 * 2, 'a'),
                      "2092: ldm         r0, m[14]",
                      "2094: stm         r0, m[0]",
                      "2096: not         r0",
                      "2098: neg         r1",
                      "2100: swap",
                      "2102: mov         r1, r0",
                      "2104: lddw        r0, counter=7",
                      "2106: stdw        counter=7, r0",
                  }));

        // Verify invalid operand cases return -1 and latch sticky error state
        auto err_gen = AllocGen();
        ASSERT_NE(err_gen, nullptr);
        EXPECT_EQ(apf_gen_add_ldh(err_gen.get(), static_cast<enum apf_register>(2), 12), -1);
        EXPECT_EQ(apf_gen_add_jbsne(err_gen.get(), APF_LABEL_DROP, max_jbs.data(), 2048), -1);
        EXPECT_EQ(apf_gen_add_ldm(err_gen.get(), APF_REG_R1, 16), -1);
        EXPECT_EQ(apf_gen_add_stm(err_gen.get(), APF_REG_R1, 16), -1);
        EXPECT_EQ(apf_gen_add_lddw(err_gen.get(), APF_REG_R0, 0), -1);
        EXPECT_EQ(apf_gen_add_lddw(err_gen.get(), APF_REG_R0, 20000), -1);
        EXPECT_EQ(apf_gen_add_stdw(err_gen.get(), APF_REG_R0, 0), -1);
        EXPECT_EQ(apf_gen_add_stdw(err_gen.get(), APF_REG_R0, 6), -1);
        EXPECT_EQ(apf_gen_add_cnt_and_pass(err_gen.get(), 0), -1);
        EXPECT_EQ(apf_gen_add_cnt_and_pass(err_gen.get(), 6), -1);
        EXPECT_EQ(apf_gen_add_cnt_and_drop(err_gen.get(), 0), -1);
        EXPECT_EQ(apf_gen_add_cnt_and_drop(err_gen.get(), 6), -1);
        EXPECT_EQ(apf_gen_add_div(err_gen.get(), APF_REG_R0, 0), -1);
        EXPECT_EQ(apf_gen_add_sh(err_gen.get(), APF_REG_R0, 32), -1);
        EXPECT_EQ(apf_gen_add_sh(err_gen.get(), APF_REG_R0, -32), -1);
        size_t err_len = 0;
        EXPECT_EQ(GenerateProgram(err_gen.get(), &err_len), nullptr);
    }
}

TEST(ApfGeneratorTest, testBranchLabelsAndTerminalTargets) {
    // 1. User-defined allocated labels + iterative branch shrinking
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_label lbl_ipv4 = apf_gen_alloc_label(gen.get());
        apf_label lbl_drop = apf_gen_alloc_label(gen.get());
        ASSERT_EQ(lbl_ipv4.id, -2);
        ASSERT_EQ(lbl_drop.id, -3);

        apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
        apf_gen_add_jeq(gen.get(), 0x0800, lbl_ipv4);
        apf_gen_add_cnt_and_drop(gen.get(), 7);
        apf_gen_define_label(gen.get(), lbl_ipv4);
        apf_gen_add_ldb(gen.get(), APF_REG_R0, 23);
        apf_gen_add_jne(gen.get(), 17, lbl_drop);
        apf_gen_add_pass(gen.get());
        apf_gen_define_label(gen.get(), lbl_drop);
        apf_gen_add_drop(gen.get());

        EXPECT_EQ(apf_gen_get_insn_count(gen.get()), 7u);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 23u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4045",
                      "7: ldh         r0, [12]",
                      "9: jeq         r0, 0x800, 16",
                      "14: drop        counter=7",
                      "16: ldb         r0, [23]",
                      "18: jne         r0, 0x11, 22",
                      "21: pass",
                      "22: drop",
                  }));
    }

    // 2. Terminal verdict targets: APF_LABEL_PASS, APF_LABEL_DROP,
    //    apf_gen_cnt_pass_label, apf_gen_cnt_drop_label
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_ldb(gen.get(), APF_REG_R0, 1);
        apf_gen_add_jeq(gen.get(), 1, APF_LABEL_PASS);
        apf_gen_add_jeq(gen.get(), 2, APF_LABEL_DROP);
        apf_gen_add_jeq(gen.get(), 3, apf_gen_cnt_pass_label(7));
        apf_gen_add_jeq(gen.get(), 4, apf_gen_cnt_drop_label(8));
        apf_gen_add_pass(gen.get());

        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 22u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4042",
                      "7: ldb         r0, [1]",
                      "9: jeq         r0, 0x1, PASS",
                      "12: jeq         r0, 0x2, DROP",
                      "15: jeq         r0, 0x3, cnt_and_pass[cnt=7]",
                      "18: jeq         r0, 0x4, cnt_and_drop[cnt=8]",
                      "21: pass",
                  }));
    }

    // 3. Error cases: duplicate labels, undefined labels, and invalid counter labels
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        EXPECT_EQ(apf_gen_cnt_pass_label(0).id, APF_LABEL_INVALID.id);
        EXPECT_EQ(apf_gen_cnt_pass_label(6).id, APF_LABEL_INVALID.id);
        EXPECT_EQ(apf_gen_cnt_drop_label(6).id, APF_LABEL_INVALID.id);
        EXPECT_EQ(apf_gen_cnt_drop_label(20000).id, APF_LABEL_INVALID.id);
        EXPECT_EQ(apf_gen_add_jeq(gen.get(), 1, apf_gen_cnt_pass_label(6)), -1);
        EXPECT_EQ(apf_gen_add_jeq(gen.get(), 1, apf_gen_cnt_drop_label(20000)), -1);
        // Terminal labels cannot be defined as intra-program branch anchors
        EXPECT_EQ(apf_gen_define_label(gen.get(), APF_LABEL_PASS), -1);
        apf_label lbl1 = apf_gen_alloc_label(gen.get());
        apf_label lbl_undef = apf_gen_alloc_label(gen.get());
        EXPECT_EQ(apf_gen_define_label(gen.get(), lbl1), 0);
        // Duplicate label definition must fail
        EXPECT_EQ(apf_gen_define_label(gen.get(), lbl1), -1);
        // Referencing an undefined allocated label causes apf_gen_generate() to fail
        auto undef_gen = AllocGen();
        ASSERT_NE(undef_gen, nullptr);
        apf_label unanchored = apf_gen_alloc_label(undef_gen.get());
        EXPECT_NE(unanchored.id, lbl_undef.id);
        apf_gen_add_jmp(undef_gen.get(), unanchored);
        size_t len = 0;
        EXPECT_EQ(GenerateProgram(undef_gen.get(), &len), nullptr);
        size_t err_idx = 99;
        EXPECT_EQ(apf_gen_get_error(undef_gen.get(), &err_idx), APF_GEN_ERR_UNDEFINED_LABEL);
        EXPECT_EQ(err_idx, 0u);
    }
}

/*
 * The following four full-program tests are APFv6.1 re-encodings of the
 * real-world APFv4 filter programs from ApfTest.java:
 *   - testFullApfV4ProgramGenerationIPV6
 *   - testFullApfV4ProgramGenerationIPV4
 *   - testFullApfV4ProgramGenerationNatTKeepAliveV4
 *   - testInfiniteLifetimeFullApfV4ProgramGeneration
 * Because libapfgenerator targets APFv6.1+, each program begins with the
 * auto-emitted 7-byte prologue ("0: data 0," + "3: debugbuf size=...") and
 * shifts user counter indices to start at APF_COUNTER_MIN_USER (7).
 */
TEST(ApfGeneratorTest, testFullApfV4ProgramGenerationIPV6) {
    auto gen = AllocGen();
    ASSERT_NE(gen, nullptr);
    const apf_label lbl_102 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_116 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_159 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_207 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_231 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_249 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_283 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_496 = apf_gen_alloc_label(gen.get());
    apf_gen_add_lddw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_add(gen.get(), APF_REG_R0, 1);
    apf_gen_add_stdw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jlt(gen.get(), 0x600, apf_gen_cnt_drop_label(33));
    apf_gen_add_jeq(gen.get(), 0x88a2, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88a4, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88b8, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88cd, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88e1, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88e3, apf_gen_cnt_drop_label(34));
    apf_gen_add_jne(gen.get(), 0x806, lbl_116);
    apf_gen_add_li(gen.get(), APF_REG_R0, 14);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(15), "000108000604");
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x1, lbl_102);
    apf_gen_add_jne(gen.get(), 0x2, apf_gen_cnt_pass_label(16));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 28);
    apf_gen_add_jeq(gen.get(), 0x0, apf_gen_cnt_drop_label(35));
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(17), "ffffffffffff");

    apf_gen_define_label(gen.get(), lbl_102);
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 38);
    apf_gen_add_jeq(gen.get(), 0x0, apf_gen_cnt_drop_label(22));
    apf_gen_add_cnt_and_pass(gen.get(), 8);

    apf_gen_define_label(gen.get(), lbl_116);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jne(gen.get(), 0x800, lbl_207);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 23);
    apf_gen_add_jne(gen.get(), 0x11, lbl_159);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jset(gen.get(), 0x1fff, lbl_159);
    apf_gen_add_ldm(gen.get(), APF_REG_R1, APF_MEM_IPV4_HEADER_SIZE);
    apf_gen_add_ldhx(gen.get(), APF_REG_R0, 16);
    apf_gen_add_jne(gen.get(), 0x44, lbl_159);
    apf_gen_add_li(gen.get(), APF_REG_R0, 50);
    apf_gen_add_add_reg(gen.get(), APF_REG_R0);
    AddJbsneHex(gen.get(), lbl_159, "e212507c6345");
    apf_gen_add_cnt_and_pass(gen.get(), 9);

    apf_gen_define_label(gen.get(), lbl_159);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 30);
    apf_gen_add_and(gen.get(), APF_REG_R0, 240);
    apf_gen_add_jeq(gen.get(), 0xe0, apf_gen_cnt_drop_label(27));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 30);
    apf_gen_add_jeq(gen.get(), 0xffffffffu, apf_gen_cnt_drop_label(25));
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(12), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 24);
    apf_gen_add_cnt_and_pass(gen.get(), 10);

    apf_gen_define_label(gen.get(), lbl_207);
    apf_gen_add_jeq(gen.get(), 0x86dd, lbl_231);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(18), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 20);

    apf_gen_define_label(gen.get(), lbl_231);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x3a, lbl_249);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 38);
    apf_gen_add_jeq(gen.get(), 0xff, apf_gen_cnt_drop_label(32));
    apf_gen_add_cnt_and_pass(gen.get(), 14);

    apf_gen_define_label(gen.get(), lbl_249);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 54);
    apf_gen_add_jeq(gen.get(), 0x85, apf_gen_cnt_drop_label(28));
    apf_gen_add_jne(gen.get(), 0x88, lbl_283);
    apf_gen_add_li(gen.get(), APF_REG_R0, 38);
    AddJbsneHex(gen.get(), lbl_283, "ff0200000000000000000000000000");
    apf_gen_add_cnt_and_drop(gen.get(), 29);

    apf_gen_define_label(gen.get(), lbl_283);
    apf_gen_add_ldm(gen.get(), APF_REG_R0, APF_MEM_PACKET_SIZE);
    apf_gen_add_jne(gen.get(), 0xa6, lbl_496);
    apf_gen_add_ldm(gen.get(), APF_REG_R0, APF_MEM_FILTER_AGE);
    apf_gen_add_jgt(gen.get(), 0x254, lbl_496);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), lbl_496, "e212507c6345648788fd6df086dd68");
    apf_gen_add_li(gen.get(), APF_REG_R0, 18);
    AddJbsneHex(
        gen.get(), lbl_496,
        "00703afffe800000000000002a0079e10abc1539fe80000000000000e01250fffe7c63458600");
    apf_gen_add_li(gen.get(), APF_REG_R0, 58);
    AddJbsneHex(gen.get(), lbl_496, "4000");
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 60);
    apf_gen_add_jlt(gen.get(), 0x254, lbl_496);
    apf_gen_add_li(gen.get(), APF_REG_R0, 62);
    AddJbsneHex(gen.get(), lbl_496, "0000000000000000");
    apf_gen_add_li(gen.get(), APF_REG_R0, 78);
    AddJbsneHex(gen.get(), lbl_496, "19050000");
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 82);
    apf_gen_add_jlt(gen.get(), 0x254, lbl_496);
    apf_gen_add_li(gen.get(), APF_REG_R0, 86);
    AddJbsneHex(gen.get(), lbl_496,
                "2001486048600000000000000000646420014860486000000000000000000064");
    apf_gen_add_li(gen.get(), APF_REG_R0, 118);
    AddJbsneHex(gen.get(), lbl_496, "030440c0");
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 122);
    apf_gen_add_jlt(gen.get(), 0x254, lbl_496);
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 126);
    apf_gen_add_jlt(gen.get(), 0x254, lbl_496);
    apf_gen_add_li(gen.get(), APF_REG_R0, 130);
    AddJbsneHex(gen.get(), lbl_496, "00000000");
    apf_gen_add_li(gen.get(), APF_REG_R0, 134);
    AddJbsneHex(gen.get(), lbl_496, "2a0079e10abc15390000000000000000");
    apf_gen_add_cnt_and_drop(gen.get(), 21);

    apf_gen_define_label(gen.get(), lbl_496);
    apf_gen_add_cnt_and_pass(gen.get(), 13);

    size_t len = 0;
    auto buf = GenerateProgram(gen.get(), &len);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
    EXPECT_EQ(
        DisassembleProgram(buf.get(), len),
        (std::vector<std::string>{
            "0: data        0,",
            "3: debugbuf    size=3495",
            "7: lddw        r0, counter=7",
            "9: add         r0, 1",
            "11: stdw        counter=7, r0",
            "13: ldh         r0, [12]",
            "15: jlt         r0, 0x600, cnt_and_drop[cnt=33]",
            "20: jeq         r0, 0x88a2, cnt_and_drop[cnt=34]",
            "25: jeq         r0, 0x88a4, cnt_and_drop[cnt=34]",
            "30: jeq         r0, 0x88b8, cnt_and_drop[cnt=34]",
            "35: jeq         r0, 0x88cd, cnt_and_drop[cnt=34]",
            "40: jeq         r0, 0x88e1, cnt_and_drop[cnt=34]",
            "45: jeq         r0, 0x88e3, cnt_and_drop[cnt=34]",
            "50: jne         r0, 0x806, 106",
            "55: li          r0, 14",
            "57: jbsne       r0, (6), cnt_and_pass[cnt=15], 000108000604",
            "68: ldh         r0, [20]",
            "70: jeq         r0, 0x1, 97",
            "73: jne         r0, 0x2, cnt_and_pass[cnt=16]",
            "78: ldw         r0, [28]",
            "80: jeq         r0, 0x0, cnt_and_drop[cnt=35]",
            "85: li          r0, 0",
            "86: jbsne       r0, (6), cnt_and_pass[cnt=17], ffffffffffff",
            "97: ldw         r0, [38]",
            "99: jeq         r0, 0x0, cnt_and_drop[cnt=22]",
            "104: pass        counter=8",
            "106: ldh         r0, [12]",
            "108: jne         r0, 0x800, 183",
            "113: ldb         r0, [23]",
            "115: jne         r0, 0x11, 146",
            "118: ldh         r0, [20]",
            "120: jset        r0, 0x1fff, 146",
            "125: ldm         r1, m[13]",
            "127: ldhx        r0, [r1+16]",
            "129: jne         r0, 0x44, 146",
            "132: li          r0, 50",
            "134: add         r0, r1",
            "135: jbsne       r0, (6), 146, e212507c6345",
            "144: pass        counter=9",
            "146: ldb         r0, [30]",
            "148: and         r0, 0xf0",
            "151: jeq         r0, 0xe0, cnt_and_drop[cnt=27]",
            "156: ldw         r0, [30]",
            "158: jeq         r0, 0xffffffff, cnt_and_drop[cnt=25]",
            "167: li          r0, 0",
            "168: jbsne       r0, (6), cnt_and_pass[cnt=12], ffffffffffff",
            "179: drop        counter=24",
            "181: pass        counter=10",
            "183: jeq         r0, 0x86dd, 202",
            "188: li          r0, 0",
            "189: jbsne       r0, (6), cnt_and_pass[cnt=18], ffffffffffff",
            "200: drop        counter=20",
            "202: ldb         r0, [20]",
            "204: jeq         r0, 0x3a, 216",
            "207: ldb         r0, [38]",
            "209: jeq         r0, 0xff, cnt_and_drop[cnt=32]",
            "214: pass        counter=14",
            "216: ldb         r0, [54]",
            "218: jeq         r0, 0x85, cnt_and_drop[cnt=28]",
            "223: jne         r0, 0x88, 248",
            "226: li          r0, 38",
            "228: jbsne       r0, (15), 248, ff0200000000000000000000000000",
            "246: drop        counter=29",
            "248: ldm         r0, m[14]",
            "250: jne         r0, 0xa6, 459",
            "253: ldm         r0, m[15]",
            "255: jgt         r0, 0x254, 459",
            "260: li          r0, 0",
            "261: jbsne       r0, (15), 459, e212507c6345648788fd6df086dd68",
            "279: li          r0, 18",
            "281: jbsne       r0, (38), 459, "
            "00703afffe800000000000002a0079e10abc1539fe80000000000000e01250fffe7c63458600",
            "322: li          r0, 58",
            "324: jbsne       r0, (2), 459, 4000",
            "329: ldh         r0, [60]",
            "331: jlt         r0, 0x254, 459",
            "336: li          r0, 62",
            "338: jbsne       r0, (8), 459, 0000000000000000",
            "349: li          r0, 78",
            "351: jbsne       r0, (4), 459, 19050000",
            "358: ldw         r0, [82]",
            "360: jlt         r0, 0x254, 459",
            "365: li          r0, 86",
            "367: jbsne       r0, (32), 459, "
            "2001486048600000000000000000646420014860486000000000000000000064",
            "402: li          r0, 118",
            "404: jbsne       r0, (4), 459, 030440c0",
            "411: ldw         r0, [122]",
            "413: jlt         r0, 0x254, 459",
            "418: ldw         r0, [126]",
            "420: jlt         r0, 0x254, 459",
            "425: li          r0, 130",
            "428: jbsne       r0, (4), 459, 00000000",
            "435: li          r0, 134",
            "438: jbsne       r0, (16), 459, 2a0079e10abc15390000000000000000",
            "457: drop        counter=21",
            "459: pass        counter=13",
        }));
}

TEST(ApfGeneratorTest, testFullApfV4ProgramGenerationIPV4) {
    auto gen = AllocGen();
    ASSERT_NE(gen, nullptr);
    const apf_label lbl_94 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_109 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_151 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_204 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_225 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_241 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_275 = apf_gen_alloc_label(gen.get());
    apf_gen_add_lddw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_add(gen.get(), APF_REG_R0, 1);
    apf_gen_add_stdw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jlt(gen.get(), 0x600, apf_gen_cnt_drop_label(33));
    apf_gen_add_jeq(gen.get(), 0x88a2, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88a4, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88b8, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88cd, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88e1, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88e3, apf_gen_cnt_drop_label(34));
    apf_gen_add_jne(gen.get(), 0x806, lbl_109);
    apf_gen_add_li(gen.get(), APF_REG_R0, 14);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(15), "000108000604");
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x1, lbl_94);
    apf_gen_add_jne(gen.get(), 0x2, apf_gen_cnt_pass_label(16));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 28);
    apf_gen_add_jeq(gen.get(), 0x0, apf_gen_cnt_drop_label(35));
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(17), "ffffffffffff");

    apf_gen_define_label(gen.get(), lbl_94);
    apf_gen_add_li(gen.get(), APF_REG_R0, 38);
    AddJbsneHex(gen.get(), apf_gen_cnt_drop_label(23), "c0a801b3");
    apf_gen_add_cnt_and_pass(gen.get(), 8);

    apf_gen_define_label(gen.get(), lbl_109);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jne(gen.get(), 0x800, lbl_204);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 23);
    apf_gen_add_jne(gen.get(), 0x11, lbl_151);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jset(gen.get(), 0x1fff, lbl_151);
    apf_gen_add_ldm(gen.get(), APF_REG_R1, APF_MEM_IPV4_HEADER_SIZE);
    apf_gen_add_ldhx(gen.get(), APF_REG_R0, 16);
    apf_gen_add_jne(gen.get(), 0x44, lbl_151);
    apf_gen_add_li(gen.get(), APF_REG_R0, 50);
    apf_gen_add_add_reg(gen.get(), APF_REG_R0);
    AddJbsneHex(gen.get(), lbl_151, "f683d58f832b");
    apf_gen_add_cnt_and_pass(gen.get(), 9);

    apf_gen_define_label(gen.get(), lbl_151);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 30);
    apf_gen_add_and(gen.get(), APF_REG_R0, 240);
    apf_gen_add_jeq(gen.get(), 0xe0, apf_gen_cnt_drop_label(27));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 30);
    apf_gen_add_jeq(gen.get(), 0xffffffffu, apf_gen_cnt_drop_label(25));
    apf_gen_add_jeq(gen.get(), 0xc0a801ffu, apf_gen_cnt_drop_label(26));
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(12), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 24);
    apf_gen_add_cnt_and_pass(gen.get(), 10);

    apf_gen_define_label(gen.get(), lbl_204);
    apf_gen_add_jeq(gen.get(), 0x86dd, lbl_225);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(18), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 20);

    apf_gen_define_label(gen.get(), lbl_225);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x3a, lbl_241);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 38);
    apf_gen_add_jeq(gen.get(), 0xff, apf_gen_cnt_drop_label(32));
    apf_gen_add_cnt_and_pass(gen.get(), 14);

    apf_gen_define_label(gen.get(), lbl_241);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 54);
    apf_gen_add_jeq(gen.get(), 0x85, apf_gen_cnt_drop_label(28));
    apf_gen_add_jne(gen.get(), 0x88, lbl_275);
    apf_gen_add_li(gen.get(), APF_REG_R0, 38);
    AddJbsneHex(gen.get(), lbl_275, "ff0200000000000000000000000000");
    apf_gen_add_cnt_and_drop(gen.get(), 29);

    apf_gen_define_label(gen.get(), lbl_275);
    apf_gen_add_cnt_and_pass(gen.get(), 13);

    size_t len = 0;
    auto buf = GenerateProgram(gen.get(), &len);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
    EXPECT_EQ(
        DisassembleProgram(buf.get(), len),
        (std::vector<std::string>{
            "0: data        0,",
            "3: debugbuf    size=3713",
            "7: lddw        r0, counter=7",
            "9: add         r0, 1",
            "11: stdw        counter=7, r0",
            "13: ldh         r0, [12]",
            "15: jlt         r0, 0x600, cnt_and_drop[cnt=33]",
            "20: jeq         r0, 0x88a2, cnt_and_drop[cnt=34]",
            "25: jeq         r0, 0x88a4, cnt_and_drop[cnt=34]",
            "30: jeq         r0, 0x88b8, cnt_and_drop[cnt=34]",
            "35: jeq         r0, 0x88cd, cnt_and_drop[cnt=34]",
            "40: jeq         r0, 0x88e1, cnt_and_drop[cnt=34]",
            "45: jeq         r0, 0x88e3, cnt_and_drop[cnt=34]",
            "50: jne         r0, 0x806, 100",
            "55: li          r0, 14",
            "57: jbsne       r0, (6), cnt_and_pass[cnt=15], 000108000604",
            "66: ldh         r0, [20]",
            "68: jeq         r0, 0x1, 89",
            "71: jne         r0, 0x2, cnt_and_pass[cnt=16]",
            "74: ldw         r0, [28]",
            "76: jeq         r0, 0x0, cnt_and_drop[cnt=35]",
            "79: li          r0, 0",
            "80: jbsne       r0, (6), cnt_and_pass[cnt=17], ffffffffffff",
            "89: li          r0, 38",
            "91: jbsne       r0, (4), cnt_and_drop[cnt=23], c0a801b3",
            "98: pass        counter=8",
            "100: ldh         r0, [12]",
            "102: jne         r0, 0x800, 182",
            "107: ldb         r0, [23]",
            "109: jne         r0, 0x11, 140",
            "112: ldh         r0, [20]",
            "114: jset        r0, 0x1fff, 140",
            "119: ldm         r1, m[13]",
            "121: ldhx        r0, [r1+16]",
            "123: jne         r0, 0x44, 140",
            "126: li          r0, 50",
            "128: add         r0, r1",
            "129: jbsne       r0, (6), 140, f683d58f832b",
            "138: pass        counter=9",
            "140: ldb         r0, [30]",
            "142: and         r0, 0xf0",
            "145: jeq         r0, 0xe0, cnt_and_drop[cnt=27]",
            "148: ldw         r0, [30]",
            "150: jeq         r0, 0xffffffff, cnt_and_drop[cnt=25]",
            "159: jeq         r0, 0xc0a801ff, cnt_and_drop[cnt=26]",
            "168: li          r0, 0",
            "169: jbsne       r0, (6), cnt_and_pass[cnt=12], ffffffffffff",
            "178: drop        counter=24",
            "180: pass        counter=10",
            "182: jeq         r0, 0x86dd, 199",
            "187: li          r0, 0",
            "188: jbsne       r0, (6), cnt_and_pass[cnt=18], ffffffffffff",
            "197: drop        counter=20",
            "199: ldb         r0, [20]",
            "201: jeq         r0, 0x3a, 211",
            "204: ldb         r0, [38]",
            "206: jeq         r0, 0xff, cnt_and_drop[cnt=32]",
            "209: pass        counter=14",
            "211: ldb         r0, [54]",
            "213: jeq         r0, 0x85, cnt_and_drop[cnt=28]",
            "216: jne         r0, 0x88, 241",
            "219: li          r0, 38",
            "221: jbsne       r0, (15), 241, ff0200000000000000000000000000",
            "239: drop        counter=29",
            "241: pass        counter=13",
        }));
}

TEST(ApfGeneratorTest, testFullApfV4ProgramGenerationNatTKeepAliveV4) {
    auto gen = AllocGen();
    ASSERT_NE(gen, nullptr);
    const apf_label lbl_100 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_115 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_157 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_243 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_263 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_284 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_303 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_337 = apf_gen_alloc_label(gen.get());
    apf_gen_add_lddw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_add(gen.get(), APF_REG_R0, 1);
    apf_gen_add_stdw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jlt(gen.get(), 0x600, apf_gen_cnt_drop_label(33));
    apf_gen_add_jeq(gen.get(), 0x88a2, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88a4, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88b8, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88cd, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88e1, apf_gen_cnt_drop_label(34));
    apf_gen_add_jeq(gen.get(), 0x88e3, apf_gen_cnt_drop_label(34));
    apf_gen_add_jne(gen.get(), 0x806, lbl_115);
    apf_gen_add_li(gen.get(), APF_REG_R0, 14);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(15), "000108000604");
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x1, lbl_100);
    apf_gen_add_jne(gen.get(), 0x2, apf_gen_cnt_pass_label(16));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 28);
    apf_gen_add_jeq(gen.get(), 0x0, apf_gen_cnt_drop_label(35));
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(17), "ffffffffffff");

    apf_gen_define_label(gen.get(), lbl_100);
    apf_gen_add_li(gen.get(), APF_REG_R0, 38);
    AddJbsneHex(gen.get(), apf_gen_cnt_drop_label(23), "c0a801be");
    apf_gen_add_cnt_and_pass(gen.get(), 8);

    apf_gen_define_label(gen.get(), lbl_115);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jne(gen.get(), 0x800, lbl_263);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 23);
    apf_gen_add_jne(gen.get(), 0x11, lbl_157);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jset(gen.get(), 0x1fff, lbl_157);
    apf_gen_add_ldm(gen.get(), APF_REG_R1, APF_MEM_IPV4_HEADER_SIZE);
    apf_gen_add_ldhx(gen.get(), APF_REG_R0, 16);
    apf_gen_add_jne(gen.get(), 0x44, lbl_157);
    apf_gen_add_li(gen.get(), APF_REG_R0, 50);
    apf_gen_add_add_reg(gen.get(), APF_REG_R0);
    AddJbsneHex(gen.get(), lbl_157, "ea42226789c0");
    apf_gen_add_cnt_and_pass(gen.get(), 9);

    apf_gen_define_label(gen.get(), lbl_157);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 30);
    apf_gen_add_and(gen.get(), APF_REG_R0, 240);
    apf_gen_add_jeq(gen.get(), 0xe0, apf_gen_cnt_drop_label(27));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 30);
    apf_gen_add_jeq(gen.get(), 0xffffffffu, apf_gen_cnt_drop_label(25));
    apf_gen_add_jeq(gen.get(), 0xc0a801ffu, apf_gen_cnt_drop_label(26));
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 23);
    apf_gen_add_jne(gen.get(), 0x11, lbl_243);
    apf_gen_add_li(gen.get(), APF_REG_R0, 26);
    AddJbsneHex(gen.get(), lbl_243, "6b7a1f1fc0a801be");
    apf_gen_add_ldm(gen.get(), APF_REG_R0, APF_MEM_IPV4_HEADER_SIZE);
    apf_gen_add_add(gen.get(), APF_REG_R0, 8);
    apf_gen_add_swap(gen.get());
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 16);
    apf_gen_add_neg(gen.get(), APF_REG_R1);
    apf_gen_add_add_reg(gen.get(), APF_REG_R0);
    apf_gen_add_jne(gen.get(), 0x1, lbl_243);
    apf_gen_add_ldm(gen.get(), APF_REG_R0, APF_MEM_IPV4_HEADER_SIZE);
    apf_gen_add_add(gen.get(), APF_REG_R0, 14);
    AddJbsneHex(gen.get(), lbl_243, "1194ceca");
    apf_gen_add_add(gen.get(), APF_REG_R0, 8);
    AddJbsneHex(gen.get(), lbl_243, "ff");
    apf_gen_add_cnt_and_drop(gen.get(), 38);

    apf_gen_define_label(gen.get(), lbl_243);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(12), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 24);
    apf_gen_add_cnt_and_pass(gen.get(), 10);

    apf_gen_define_label(gen.get(), lbl_263);
    apf_gen_add_jeq(gen.get(), 0x86dd, lbl_284);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(18), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 20);

    apf_gen_define_label(gen.get(), lbl_284);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x0, apf_gen_cnt_pass_label(12));
    apf_gen_add_jeq(gen.get(), 0x3a, lbl_303);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 38);
    apf_gen_add_jeq(gen.get(), 0xff, apf_gen_cnt_drop_label(32));
    apf_gen_add_cnt_and_pass(gen.get(), 14);

    apf_gen_define_label(gen.get(), lbl_303);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 54);
    apf_gen_add_jeq(gen.get(), 0x85, apf_gen_cnt_drop_label(28));
    apf_gen_add_jne(gen.get(), 0x88, lbl_337);
    apf_gen_add_li(gen.get(), APF_REG_R0, 38);
    AddJbsneHex(gen.get(), lbl_337, "ff0200000000000000000000000000");
    apf_gen_add_cnt_and_drop(gen.get(), 29);

    apf_gen_define_label(gen.get(), lbl_337);
    apf_gen_add_cnt_and_pass(gen.get(), 13);

    size_t len = 0;
    auto buf = GenerateProgram(gen.get(), &len);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
    EXPECT_EQ(
        DisassembleProgram(buf.get(), len),
        (std::vector<std::string>{
            "0: data        0,",
            "3: debugbuf    size=3641",
            "7: lddw        r0, counter=7",
            "9: add         r0, 1",
            "11: stdw        counter=7, r0",
            "13: ldh         r0, [12]",
            "15: jlt         r0, 0x600, cnt_and_drop[cnt=33]",
            "20: jeq         r0, 0x88a2, cnt_and_drop[cnt=34]",
            "25: jeq         r0, 0x88a4, cnt_and_drop[cnt=34]",
            "30: jeq         r0, 0x88b8, cnt_and_drop[cnt=34]",
            "35: jeq         r0, 0x88cd, cnt_and_drop[cnt=34]",
            "40: jeq         r0, 0x88e1, cnt_and_drop[cnt=34]",
            "45: jeq         r0, 0x88e3, cnt_and_drop[cnt=34]",
            "50: jne         r0, 0x806, 106",
            "55: li          r0, 14",
            "57: jbsne       r0, (6), cnt_and_pass[cnt=15], 000108000604",
            "68: ldh         r0, [20]",
            "70: jeq         r0, 0x1, 95",
            "73: jne         r0, 0x2, cnt_and_pass[cnt=16]",
            "78: ldw         r0, [28]",
            "80: jeq         r0, 0x0, cnt_and_drop[cnt=35]",
            "85: li          r0, 0",
            "86: jbsne       r0, (6), cnt_and_pass[cnt=17], ffffffffffff",
            "95: li          r0, 38",
            "97: jbsne       r0, (4), cnt_and_drop[cnt=23], c0a801be",
            "104: pass        counter=8",
            "106: ldh         r0, [12]",
            "108: jne         r0, 0x800, 239",
            "113: ldb         r0, [23]",
            "115: jne         r0, 0x11, 146",
            "118: ldh         r0, [20]",
            "120: jset        r0, 0x1fff, 146",
            "125: ldm         r1, m[13]",
            "127: ldhx        r0, [r1+16]",
            "129: jne         r0, 0x44, 146",
            "132: li          r0, 50",
            "134: add         r0, r1",
            "135: jbsne       r0, (6), 146, ea42226789c0",
            "144: pass        counter=9",
            "146: ldb         r0, [30]",
            "148: and         r0, 0xf0",
            "151: jeq         r0, 0xe0, cnt_and_drop[cnt=27]",
            "154: ldw         r0, [30]",
            "156: jeq         r0, 0xffffffff, cnt_and_drop[cnt=25]",
            "165: jeq         r0, 0xc0a801ff, cnt_and_drop[cnt=26]",
            "174: ldb         r0, [23]",
            "176: jne         r0, 0x11, 225",
            "179: li          r0, 26",
            "181: jbsne       r0, (8), 225, 6b7a1f1fc0a801be",
            "192: ldm         r0, m[13]",
            "194: add         r0, 8",
            "196: swap",
            "198: ldh         r0, [16]",
            "200: neg         r1",
            "202: add         r0, r1",
            "203: jne         r0, 0x1, 225",
            "206: ldm         r0, m[13]",
            "208: add         r0, 14",
            "210: jbsne       r0, (4), 225, 1194ceca",
            "217: add         r0, 8",
            "219: jbsne       r0, (1), 225, ff",
            "223: drop        counter=38",
            "225: li          r0, 0",
            "226: jbsne       r0, (6), cnt_and_pass[cnt=12], ffffffffffff",
            "235: drop        counter=24",
            "237: pass        counter=10",
            "239: jeq         r0, 0x86dd, 256",
            "244: li          r0, 0",
            "245: jbsne       r0, (6), cnt_and_pass[cnt=18], ffffffffffff",
            "254: drop        counter=20",
            "256: ldb         r0, [20]",
            "258: jeq         r0, 0x0, cnt_and_pass[cnt=12]",
            "261: jeq         r0, 0x3a, 271",
            "264: ldb         r0, [38]",
            "266: jeq         r0, 0xff, cnt_and_drop[cnt=32]",
            "269: pass        counter=14",
            "271: ldb         r0, [54]",
            "273: jeq         r0, 0x85, cnt_and_drop[cnt=28]",
            "276: jne         r0, 0x88, 301",
            "279: li          r0, 38",
            "281: jbsne       r0, (15), 301, ff0200000000000000000000000000",
            "299: drop        counter=29",
            "301: pass        counter=13",
        }));
}

TEST(ApfGeneratorTest, testInfiniteLifetimeFullApfV4ProgramGeneration) {
    auto gen = AllocGen();
    ASSERT_NE(gen, nullptr);
    const apf_label lbl_104 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_122 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_165 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_225 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_249 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_273 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_297 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_333 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_421 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_480 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_547 = apf_gen_alloc_label(gen.get());
    const apf_label lbl_574 = apf_gen_alloc_label(gen.get());
    apf_gen_add_lddw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_add(gen.get(), APF_REG_R0, 1);
    apf_gen_add_stdw(gen.get(), APF_REG_R0, 7);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jlt(gen.get(), 0x600, apf_gen_cnt_drop_label(35));
    apf_gen_add_jeq(gen.get(), 0x88a2, apf_gen_cnt_drop_label(36));
    apf_gen_add_jeq(gen.get(), 0x88a4, apf_gen_cnt_drop_label(36));
    apf_gen_add_jeq(gen.get(), 0x88b8, apf_gen_cnt_drop_label(36));
    apf_gen_add_jeq(gen.get(), 0x88cd, apf_gen_cnt_drop_label(36));
    apf_gen_add_jeq(gen.get(), 0x88e1, apf_gen_cnt_drop_label(36));
    apf_gen_add_jeq(gen.get(), 0x88e3, apf_gen_cnt_drop_label(36));
    apf_gen_add_jne(gen.get(), 0x806, lbl_122);
    apf_gen_add_li(gen.get(), APF_REG_R0, 14);
    AddJbsneHex(gen.get(), apf_gen_cnt_drop_label(43), "000108000604");
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x1, lbl_104);
    apf_gen_add_jne(gen.get(), 0x2, apf_gen_cnt_drop_label(44));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 28);
    apf_gen_add_jeq(gen.get(), 0x0, apf_gen_cnt_drop_label(37));
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(19), "ffffffffffff");

    apf_gen_define_label(gen.get(), lbl_104);
    apf_gen_add_li(gen.get(), APF_REG_R0, 38);
    AddJbsneHex(gen.get(), apf_gen_cnt_drop_label(25), "c0a801ec");
    apf_gen_add_cnt_and_pass(gen.get(), 10);

    apf_gen_define_label(gen.get(), lbl_122);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 12);
    apf_gen_add_jne(gen.get(), 0x800, lbl_249);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 23);
    apf_gen_add_jne(gen.get(), 0x11, lbl_165);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jset(gen.get(), 0x1fff, lbl_165);
    apf_gen_add_ldm(gen.get(), APF_REG_R1, APF_MEM_IPV4_HEADER_SIZE);
    apf_gen_add_ldhx(gen.get(), APF_REG_R0, 16);
    apf_gen_add_jne(gen.get(), 0x44, lbl_165);
    apf_gen_add_li(gen.get(), APF_REG_R0, 50);
    apf_gen_add_add_reg(gen.get(), APF_REG_R0);
    AddJbsneHex(gen.get(), lbl_165, "7e9046bc7008");
    apf_gen_add_cnt_and_pass(gen.get(), 11);

    apf_gen_define_label(gen.get(), lbl_165);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 30);
    apf_gen_add_and(gen.get(), APF_REG_R0, 240);
    apf_gen_add_jeq(gen.get(), 0xe0, apf_gen_cnt_drop_label(29));
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 30);
    apf_gen_add_jeq(gen.get(), 0xffffffffu, apf_gen_cnt_drop_label(27));
    apf_gen_add_jeq(gen.get(), 0xc0a801ffu, apf_gen_cnt_drop_label(28));
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 23);
    apf_gen_add_jne(gen.get(), 0x6, lbl_225);
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jset(gen.get(), 0x1fff, lbl_225);
    apf_gen_add_ldm(gen.get(), APF_REG_R1, APF_MEM_IPV4_HEADER_SIZE);
    apf_gen_add_ldhx(gen.get(), APF_REG_R0, 16);
    apf_gen_add_jne(gen.get(), 0x7, lbl_225);
    apf_gen_add_cnt_and_drop(gen.get(), 42);

    apf_gen_define_label(gen.get(), lbl_225);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(14), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 26);
    apf_gen_add_cnt_and_pass(gen.get(), 12);

    apf_gen_define_label(gen.get(), lbl_249);
    apf_gen_add_jeq(gen.get(), 0x86dd, lbl_273);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), apf_gen_cnt_pass_label(20), "ffffffffffff");
    apf_gen_add_cnt_and_drop(gen.get(), 22);

    apf_gen_define_label(gen.get(), lbl_273);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 20);
    apf_gen_add_jeq(gen.get(), 0x0, apf_gen_cnt_pass_label(14));
    apf_gen_add_jeq(gen.get(), 0x3a, lbl_297);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 38);
    apf_gen_add_jeq(gen.get(), 0xff, apf_gen_cnt_drop_label(34));
    apf_gen_add_cnt_and_pass(gen.get(), 16);

    apf_gen_define_label(gen.get(), lbl_297);
    apf_gen_add_ldb(gen.get(), APF_REG_R0, 54);
    apf_gen_add_jeq(gen.get(), 0x85, apf_gen_cnt_drop_label(30));
    apf_gen_add_jne(gen.get(), 0x88, lbl_333);
    apf_gen_add_li(gen.get(), APF_REG_R0, 38);
    AddJbsneHex(gen.get(), lbl_333, "ff0200000000000000000000000000");
    apf_gen_add_cnt_and_drop(gen.get(), 31);

    apf_gen_define_label(gen.get(), lbl_333);
    apf_gen_add_ldm(gen.get(), APF_REG_R0, APF_MEM_PACKET_SIZE);
    apf_gen_add_jne(gen.get(), 0x96, lbl_574);
    apf_gen_add_ldm(gen.get(), APF_REG_R0, APF_MEM_FILTER_AGE);
    apf_gen_add_jgt(gen.get(), 0x48e, lbl_574);
    apf_gen_add_li(gen.get(), APF_REG_R0, 0);
    AddJbsneHex(gen.get(), lbl_574, "7e9046bc700828c68e23672c86dd60");
    apf_gen_add_li(gen.get(), APF_REG_R0, 18);
    AddJbsneHex(gen.get(), lbl_574, "00603afffe800000000000002ac68efffe23672c");
    apf_gen_add_li(gen.get(), APF_REG_R0, 54);
    AddJbsneHex(gen.get(), lbl_574, "8600");
    apf_gen_add_li(gen.get(), APF_REG_R0, 58);
    AddJbsneHex(gen.get(), lbl_574, "40c0");
    apf_gen_add_ldh(gen.get(), APF_REG_R0, 60);
    apf_gen_add_jeq(gen.get(), 0x0, lbl_574);
    apf_gen_add_jlt(gen.get(), 0xb4, lbl_421);
    apf_gen_add_jlt(gen.get(), 0x91e, lbl_574);
    apf_gen_add_jgt(gen.get(), 0x1b58, lbl_574);

    apf_gen_define_label(gen.get(), lbl_421);
    apf_gen_add_li(gen.get(), APF_REG_R0, 62);
    AddJbsneHex(gen.get(), lbl_574,
                "0000000000000000010128c68e23672c05010000000005dc030440c0");
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 90);
    apf_gen_add_jeq(gen.get(), 0x0, lbl_574);
    apf_gen_add_jlt(gen.get(), 0xb4, lbl_480);
    apf_gen_add_jlt(gen.get(), 0x55555555u, lbl_574);
    apf_gen_add_jgt(gen.get(), 0xffffffffu, lbl_574);

    apf_gen_define_label(gen.get(), lbl_480);
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 94);
    apf_gen_add_jlt(gen.get(), 0x55555555u, lbl_574);
    apf_gen_add_jgt(gen.get(), 0xffffffffu, lbl_574);
    apf_gen_add_li(gen.get(), APF_REG_R0, 98);
    AddJbsneHex(gen.get(), lbl_574, "000000002401fa000480f000000000000000000019030000");
    apf_gen_add_ldw(gen.get(), APF_REG_R0, 122);
    apf_gen_add_jeq(gen.get(), 0x0, lbl_574);
    apf_gen_add_jlt(gen.get(), 0x78, lbl_547);
    apf_gen_add_jlt(gen.get(), 0x91e, lbl_574);
    apf_gen_add_jgt(gen.get(), 0x1b58, lbl_574);

    apf_gen_define_label(gen.get(), lbl_547);
    apf_gen_add_li(gen.get(), APF_REG_R0, 126);
    AddJbsneHex(gen.get(), lbl_574, "2401fa000480f00000000000000000010701");
    apf_gen_add_cnt_and_drop(gen.get(), 23);

    apf_gen_define_label(gen.get(), lbl_574);
    apf_gen_add_cnt_and_pass(gen.get(), 15);

    size_t len = 0;
    auto buf = GenerateProgram(gen.get(), &len);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
    EXPECT_EQ(
        DisassembleProgram(buf.get(), len),
        (std::vector<std::string>{
            "0: data        0,",
            "3: debugbuf    size=3392",
            "7: lddw        r0, counter=7",
            "9: add         r0, 1",
            "11: stdw        counter=7, r0",
            "13: ldh         r0, [12]",
            "15: jlt         r0, 0x600, cnt_and_drop[cnt=35]",
            "20: jeq         r0, 0x88a2, cnt_and_drop[cnt=36]",
            "25: jeq         r0, 0x88a4, cnt_and_drop[cnt=36]",
            "30: jeq         r0, 0x88b8, cnt_and_drop[cnt=36]",
            "35: jeq         r0, 0x88cd, cnt_and_drop[cnt=36]",
            "40: jeq         r0, 0x88e1, cnt_and_drop[cnt=36]",
            "45: jeq         r0, 0x88e3, cnt_and_drop[cnt=36]",
            "50: jne         r0, 0x806, 110",
            "55: li          r0, 14",
            "57: jbsne       r0, (6), cnt_and_drop[cnt=43], 000108000604",
            "68: ldh         r0, [20]",
            "70: jeq         r0, 0x1, 97",
            "73: jne         r0, 0x2, cnt_and_drop[cnt=44]",
            "78: ldw         r0, [28]",
            "80: jeq         r0, 0x0, cnt_and_drop[cnt=37]",
            "85: li          r0, 0",
            "86: jbsne       r0, (6), cnt_and_pass[cnt=19], ffffffffffff",
            "97: li          r0, 38",
            "99: jbsne       r0, (4), cnt_and_drop[cnt=25], c0a801ec",
            "108: pass        counter=10",
            "110: ldh         r0, [12]",
            "112: jne         r0, 0x800, 217",
            "117: ldb         r0, [23]",
            "119: jne         r0, 0x11, 150",
            "122: ldh         r0, [20]",
            "124: jset        r0, 0x1fff, 150",
            "129: ldm         r1, m[13]",
            "131: ldhx        r0, [r1+16]",
            "133: jne         r0, 0x44, 150",
            "136: li          r0, 50",
            "138: add         r0, r1",
            "139: jbsne       r0, (6), 150, 7e9046bc7008",
            "148: pass        counter=11",
            "150: ldb         r0, [30]",
            "152: and         r0, 0xf0",
            "155: jeq         r0, 0xe0, cnt_and_drop[cnt=29]",
            "160: ldw         r0, [30]",
            "162: jeq         r0, 0xffffffff, cnt_and_drop[cnt=27]",
            "171: jeq         r0, 0xc0a801ff, cnt_and_drop[cnt=28]",
            "180: ldb         r0, [23]",
            "182: jne         r0, 0x6, 201",
            "185: ldh         r0, [20]",
            "187: jset        r0, 0x1fff, 201",
            "192: ldm         r1, m[13]",
            "194: ldhx        r0, [r1+16]",
            "196: jne         r0, 0x7, 201",
            "199: drop        counter=42",
            "201: li          r0, 0",
            "202: jbsne       r0, (6), cnt_and_pass[cnt=14], ffffffffffff",
            "213: drop        counter=26",
            "215: pass        counter=12",
            "217: jeq         r0, 0x86dd, 236",
            "222: li          r0, 0",
            "223: jbsne       r0, (6), cnt_and_pass[cnt=20], ffffffffffff",
            "234: drop        counter=22",
            "236: ldb         r0, [20]",
            "238: jeq         r0, 0x0, cnt_and_pass[cnt=14]",
            "243: jeq         r0, 0x3a, 255",
            "246: ldb         r0, [38]",
            "248: jeq         r0, 0xff, cnt_and_drop[cnt=34]",
            "253: pass        counter=16",
            "255: ldb         r0, [54]",
            "257: jeq         r0, 0x85, cnt_and_drop[cnt=30]",
            "262: jne         r0, 0x88, 287",
            "265: li          r0, 38",
            "267: jbsne       r0, (15), 287, ff0200000000000000000000000000",
            "285: drop        counter=31",
            "287: ldm         r0, m[14]",
            "289: jne         r0, 0x96, 526",
            "292: ldm         r0, m[15]",
            "294: jgt         r0, 0x48e, 526",
            "299: li          r0, 0",
            "300: jbsne       r0, (15), 526, 7e9046bc700828c68e23672c86dd60",
            "318: li          r0, 18",
            "320: jbsne       r0, (20), 526, 00603afffe800000000000002ac68efffe23672c",
            "343: li          r0, 54",
            "345: jbsne       r0, (2), 526, 8600",
            "350: li          r0, 58",
            "352: jbsne       r0, (2), 526, 40c0",
            "357: ldh         r0, [60]",
            "359: jeq         r0, 0x0, 526",
            "362: jlt         r0, 0xb4, 375",
            "365: jlt         r0, 0x91e, 526",
            "370: jgt         r0, 0x1b58, 526",
            "375: li          r0, 62",
            "377: jbsne       r0, (28), 526, "
            "0000000000000000010128c68e23672c05010000000005dc030440c0",
            "408: ldw         r0, [90]",
            "410: jeq         r0, 0x0, 526",
            "413: jlt         r0, 0xb4, 434",
            "416: jlt         r0, 0x55555555, 526",
            "425: jgt         r0, 0xffffffff, 526",
            "434: ldw         r0, [94]",
            "436: jlt         r0, 0x55555555, 526",
            "445: jgt         r0, 0xffffffff, 526",
            "454: li          r0, 98",
            "456: jbsne       r0, (24), 526, 000000002401fa000480f000000000000000000019030000",
            "483: ldw         r0, [122]",
            "485: jeq         r0, 0x0, 526",
            "488: jlt         r0, 0x78, 501",
            "491: jlt         r0, 0x91e, 526",
            "496: jgt         r0, 0x1b58, 526",
            "501: li          r0, 126",
            "503: jbsne       r0, (18), 526, 2401fa000480f00000000000000000010701",
            "524: drop        counter=23",
            "526: pass        counter=15",
        }));
}

TEST(ApfGeneratorTest, testBoundaryWidthsAndStickyErrorLatching) {
    // 1. Signed vs. unsigned boundary immediate widths and shared branch field width
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_gen_add_li(gen.get(), APF_REG_R0, -128);    // 1-byte signed (2 bytes total)
        apf_gen_add_li(gen.get(), APF_REG_R0, -129);    // 2-byte signed (3 bytes total)
        apf_gen_add_li(gen.get(), APF_REG_R0, 127);     // 1-byte signed (2 bytes total)
        apf_gen_add_li(gen.get(), APF_REG_R0, 128);     // 2-byte signed (3 bytes total)
        apf_gen_add_li(gen.get(), APF_REG_R0, -32768);  // 2-byte signed (3 bytes total)
        apf_gen_add_li(gen.get(), APF_REG_R0, -32769);  // 4-byte signed (5 bytes total)
        apf_gen_add_li(gen.get(), APF_REG_R0, 32767);   // 2-byte signed (3 bytes total)
        apf_gen_add_li(gen.get(), APF_REG_R0, 32768);   // 4-byte signed (5 bytes total)
        apf_gen_add_ldb(gen.get(), APF_REG_R0, 255);    // 1-byte unsigned (2 bytes total)
        apf_gen_add_ldb(gen.get(), APF_REG_R0, 256);    // 2-byte unsigned (3 bytes total)
        apf_gen_add_ldb(gen.get(), APF_REG_R0, 65535);  // 2-byte unsigned (3 bytes total)
        apf_gen_add_ldb(gen.get(), APF_REG_R0, 65536);  // 4-byte unsigned (5 bytes total)
        apf_gen_add_mul(gen.get(), APF_REG_R0, 0);      // 1-byte non-zero-imm (2 bytes total)
        apf_gen_add_div(gen.get(), APF_REG_R0, 2);      // 1-byte non-zero-imm (2 bytes total)
        apf_gen_add_or(gen.get(), APF_REG_R0, 0x100);   // 2-byte unsigned (3 bytes total)
        // Shared branch width: target=cnt_pass(128) (2 bytes), imm=1 -> field_len=2 (5 bytes)
        apf_gen_add_jeq(gen.get(), 1, apf_gen_cnt_pass_label(128));
        // Shared branch width: target=DROP (1 byte), imm=0x12345678 -> field_len=4 (9 bytes)
        apf_gen_add_jne(gen.get(), 0x12345678, APF_LABEL_DROP);
        // 2-byte unconditional jump target
        apf_gen_add_jmp(gen.get(), apf_gen_cnt_pass_label(1000));

        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        EXPECT_EQ(len, 70u);
        EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
        EXPECT_EQ(
            DisassembleProgram(buf.get(), len),
            (std::vector<std::string>{
                "0: data        0,",
                "3: debugbuf    size=26",
                "7: li          r0, -128",
                "9: li          r0, -129",
                "12: li          r0, 127",
                "14: li          r0, 128",
                "17: li          r0, -32768",
                "20: li          r0, -32769",
                "25: li          r0, 32767",
                "28: li          r0, 32768",
                "33: ldb         r0, [255]",
                "35: ldb         r0, [256]",
                "38: ldb         r0, [65535]",
                "41: ldb         r0, [65536]",
                "46: mul         r0, 0",
                "48: div         r0, 2",
                "50: or          r0, 0x100",
                "53: jeq         r0, 0x1, cnt_and_pass[cnt=128]",
                "58: jne         r0, 0x12345678, DROP",
                "67: jmp         cnt_and_pass[cnt=1000]",
            }));
    }

    // 2. 4-byte branch target (> 65535 bytes forward jump)
    {
        auto gen = AllocGen(APF_VERSION_61, 131072);
        ASSERT_NE(gen, nullptr);
        const std::vector<uint8_t> chunk(2047, 0x11);
        apf_gen_add_jmp(gen.get(), APF_LABEL_PASS);
        for (int i = 0; i < 33; i++) {
            apf_gen_add_jbsne(gen.get(), APF_LABEL_DROP, chunk.data(), 2047);
        }
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        // Leading jmp (at offset 7 after prologue) must use 4-byte target encoding (size_field = 3)
        EXPECT_EQ(buf.get()[7], (14u << 3) | (3u << 1) | 0u);
        EXPECT_EQ(len, apf_gen_get_program_len(gen.get()));
    }

    // 3. Sticky error latching and NULL pointer argument guards
    {
        size_t len = 123;
        EXPECT_EQ(apf_gen_generate(nullptr, nullptr, 0, &len), -1);
        EXPECT_EQ(len, 0u);
        EXPECT_EQ(apf_gen_add_pass(nullptr), -1);
        EXPECT_EQ(apf_gen_get_insn_count(nullptr), 0u);
        EXPECT_EQ(apf_gen_get_program_len(nullptr), 0u);
        size_t err_idx = 42;
        EXPECT_EQ(apf_gen_get_error(nullptr, &err_idx), APF_GEN_ERR_INVALID_ARGUMENT);
        EXPECT_EQ(err_idx, 0u);

        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        EXPECT_EQ(apf_gen_get_error(gen.get(), &err_idx), APF_GEN_OK);
        EXPECT_EQ(apf_gen_add_pass(gen.get()), 0);
        // Trigger a single invalid instruction call (divide by zero) at user instruction index 1
        EXPECT_EQ(apf_gen_add_div(gen.get(), APF_REG_R0, 0), -1);
        // Subsequent valid instruction calls still succeed, but apf_gen_generate() fails
        // because the generator's error state is sticky.
        EXPECT_EQ(apf_gen_add_pass(gen.get()), 0);
        EXPECT_EQ(GenerateProgram(gen.get(), &len), nullptr);
        EXPECT_EQ(apf_gen_get_error(gen.get(), &err_idx), APF_GEN_ERR_INVALID_ARGUMENT);
        EXPECT_EQ(err_idx, 1u);
    }

    // 4. 4-byte backward jump encoding (32-bit unsigned wraparound)
    {
        auto gen = AllocGen();
        ASSERT_NE(gen, nullptr);
        apf_label lbl = apf_gen_alloc_label(gen.get());
        ASSERT_NE(lbl.id, APF_LABEL_INVALID.id);
        apf_gen_define_label(gen.get(), lbl);
        apf_gen_add_pass(gen.get());
        apf_gen_add_jmp(gen.get(), lbl);
        size_t len = 0;
        auto buf = GenerateProgram(gen.get(), &len);
        ASSERT_NE(buf, nullptr);
        ASSERT_EQ(len, 13u);
        EXPECT_EQ(DisassembleProgram(buf.get(), len),
                  (std::vector<std::string>{
                      "0: data        0,",
                      "3: debugbuf    size=4059",
                      "7: pass",
                      "8: jmp         7",
                  }));
    }
}

TEST(ApfGeneratorTest, testRamModelErrorReportingAndCallerBuffer) {
    // 1. RAM size validation at allocation: ram_len >= 1024, ram_len % 4 == 0, ram_len < 2 GiB
    EXPECT_EQ(AllocGen(APF_VERSION_61, 0), nullptr);
    EXPECT_EQ(AllocGen(APF_VERSION_61, 512), nullptr);
    EXPECT_EQ(AllocGen(APF_VERSION_61, 1020), nullptr);
    EXPECT_EQ(AllocGen(APF_VERSION_61, 1025), nullptr);
    EXPECT_EQ(AllocGen(APF_VERSION_61, 1026), nullptr);
    EXPECT_EQ(AllocGen(APF_VERSION_61, 0x80000000u), nullptr);

    // 2. Counter beyond RAM (4 * 300 = 1200 > 1024)
    {
        auto gen = AllocGen(APF_VERSION_61, 1024);
        ASSERT_NE(gen, nullptr);
        EXPECT_EQ(apf_gen_add_jmp(gen.get(), apf_gen_cnt_drop_label(300)), 0);
        size_t len = 0;
        EXPECT_EQ(GenerateProgram(gen.get(), &len), nullptr);
        EXPECT_EQ(apf_gen_get_error(gen.get(), nullptr), APF_GEN_ERR_RAM_OVERFLOW);
    }

    // 3. Counter inside program (710-byte program + 4 * 100 = 1110 > 1024)
    {
        auto gen = AllocGen(APF_VERSION_61, 1024);
        ASSERT_NE(gen, nullptr);
        const std::vector<uint8_t> payload(696, 0xAA);
        EXPECT_EQ(apf_gen_add_jbsne(gen.get(), APF_LABEL_PASS, payload.data(),
                                    static_cast<uint16_t>(payload.size())),
                  0);
        EXPECT_EQ(apf_gen_add_cnt_and_drop(gen.get(), 100), 0);
        size_t len = 0;
        EXPECT_EQ(GenerateProgram(gen.get(), &len), nullptr);
        EXPECT_EQ(apf_gen_get_error(gen.get(), nullptr), APF_GEN_ERR_RAM_OVERFLOW);
    }

    // 4. Program colliding with 6 system counters (program_len + 24 > 1024)
    {
        auto gen = AllocGen(APF_VERSION_61, 1024);
        ASSERT_NE(gen, nullptr);
        const std::vector<uint8_t> payload(995, 0xBB);
        EXPECT_EQ(apf_gen_add_jbsne(gen.get(), APF_LABEL_PASS, payload.data(),
                                    static_cast<uint16_t>(payload.size())),
                  0);
        size_t len = 0;
        EXPECT_EQ(GenerateProgram(gen.get(), &len), nullptr);
        EXPECT_EQ(apf_gen_get_error(gen.get(), nullptr), APF_GEN_ERR_RAM_OVERFLOW);
    }

    // 5. Caller buffer too small (recoverable retry) and forbidding mutations after generate()
    {
        auto gen = AllocGen(APF_VERSION_61, 1024);
        ASSERT_NE(gen, nullptr);
        EXPECT_EQ(apf_gen_add_pass(gen.get()), 0);
        size_t out_len = 0;
        EXPECT_EQ(apf_gen_generate(gen.get(), nullptr, 0, &out_len), 0);
        EXPECT_EQ(out_len, 8u);
        uint8_t out_buf[8];
        EXPECT_EQ(apf_gen_generate(gen.get(), out_buf, sizeof(out_buf), &out_len), 0);
        EXPECT_EQ(out_len, 8u);

        // Adding instructions or labels after the program has been written is forbidden
        EXPECT_EQ(apf_gen_add_drop(gen.get()), -1);
        EXPECT_EQ(apf_gen_alloc_label(gen.get()).id, APF_LABEL_INVALID.id);
        EXPECT_EQ(apf_gen_get_error(gen.get(), nullptr), APF_GEN_ERR_ALREADY_GENERATED);

        auto gen2 = AllocGen(APF_VERSION_61, 1024);
        ASSERT_NE(gen2, nullptr);
        const uint8_t data[4] = {0x11, 0x22, 0x33, 0x44};
        EXPECT_EQ(apf_gen_set_data(gen2.get(), data, sizeof(data)), 0);
        EXPECT_EQ(apf_gen_add_pass(gen2.get()), 0);
        uint8_t small_buf[4];
        size_t len2 = 0;
        EXPECT_EQ(apf_gen_generate(gen2.get(), small_buf, sizeof(small_buf), &len2), -1);
        EXPECT_EQ(len2, 12u);
        EXPECT_EQ(apf_gen_get_error(gen2.get(), nullptr), APF_GEN_OK);

        std::vector<uint8_t> retry_buf(len2);
        EXPECT_EQ(apf_gen_generate(gen2.get(), retry_buf.data(), retry_buf.size(), &len2), 0);
        EXPECT_EQ(len2, 12u);
        EXPECT_EQ(DisassembleProgram(retry_buf.data(), len2),
                  (std::vector<std::string>{
                      "0: data        4, 11223344",
                      "7: debugbuf    size=988",
                      "11: pass",
                  }));
    }
}
