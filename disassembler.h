/*
 * Copyright 2019, The Android Open Source Project
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

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Disassembles a APF program into a human-readable format.
 *
 * @param program the program bytecode.
 * @param program_len the length of the program bytecode.
 * @param pc The program counter which point to the current instruction.
 * @param output_buffer A pointer to a buffer where the disassembled
 *                      instruction will be stored.
 * @param output_buffer_len the length of the output buffer.
 *
 * @return the program counter which point to the next instruction.
 */
uint32_t apf_disassemble(const uint8_t* program, uint32_t program_len,
                         uint32_t pc, char* output_buffer,
                         int output_buffer_len);

#ifdef __cplusplus
}
#endif
