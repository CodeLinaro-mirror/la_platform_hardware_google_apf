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

#ifndef APF_INTERPRETER_V5_H_
#define APF_INTERPRETER_V5_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Version of APF instruction set processed by apf_run().
 * Should be returned by wifi_get_packet_filter_info.
 */
uint32_t apf_version();

/**
 * Allocates a buffer for APF program to write the transmit packet.
 *
 * The implementations must always support allocating at least one 1500 bytes
 * buffer until it is effectively transmitted.
 *
 * The firmware is responsible for freeing everything that was allocated by APF.
 * It is OK if the firmware decides only to limit allocations to at most one
 * response packet for every packet received by APF. In other words, while
 * processing a single received packet, it is OK for apf_allocate_buffer() to
 * succeed only once and return NULL after that.
 *
 * @param size the size of buffer to allocate, it should be the size of the
 *             packet to be transmitted.
 * @return the pointer to the allocated region. The function can return null to
 *         indicate the allocation failure due to not enough memory. This may
 *         happened if there are too many buffers allocated that have not been
 *         transmitted and deallocated yet.
 */
uint8_t* apf_allocate_buffer(uint32_t size);

/**
 * Transmits the allocated buffer and deallocates the memory region.
 *
 * The function is responsible to verify if the range [ptr, ptr + len) is within
 * the buffer it allocated for the program when apf_transmit_buffer() is called.
 *
 * The content of the buffer between [ptr, ptr + len) is the transmit packet
 * bytes, starting from the 802.3 header and not including any CRC bytes at the
 * end.
 *
 * The firmware must guarantee the transmit packet is not modified after the APF
 * calls the apf_transmit_buffer().
 *
 * The firmware is expected to make its best effort to transmit. If it
 * exhausts retries, or if there is no channel for too long and the transmit
 * queue is full, then it is OK for the packet to be dropped.
 *
 * @param ptr pointer to the transmit buffer
 * @param len the length of buffer to be transmitted, 0 means don't transmit the
 *            buffer but only deallocate it
 * @param dscp the first 6 bits of the TOS field in the IPv4 header or traffic
 *             class field in the IPv6 header.
 */
void apf_transmit_buffer(uint8_t *ptr, uint32_t len, uint8_t dscp);

/**
 * Runs a packet filtering program over a packet.
 *
 * The return value of the apf_run indicates whether the packet should be
 * passed to AP or not. As a part of apf_run execution, the packet filtering
 * program can call apf_allocate_buffer()/apf_transmit_buffer() to construct
 * an egress packet to transmit it.
 *
 * The text section containing the program instructions starts at address
 * program and stops at + program_len - 1, and the writable data section
 * begins at program + program_len and ends at program + ram_len - 1,
 * as described in the following diagram:
 *
 *     program         program + program_len    program + ram_len
 *        |    text section    |      data section      |
 *        +--------------------+------------------------+
 *
 * @param program the program bytecode, followed by the writable data region.
 * @param program_len the length in bytes of the read-only portion of the APF
 *                    buffer pointed to by {@code program}.
 * @param ram_len total length of the APF buffer pointed to by {@code program},
 *                including the read-only bytecode portion and the read-write
 *                data portion.
 * @param packet the packet bytes, starting from the 802.3 header and not
 *               including any CRC bytes at the end.
 * @param packet_len the length of {@code packet} in bytes.
 * @param filter_age the number of seconds since the filter was programmed.
 *
 * @return non-zero if packet should be passed to AP, zero if
 *         packet should be dropped. Return 1 indicating the packet is accepted
 *         without error. Negative return values are reserved for error code.
 */
int apf_run(uint8_t* program, uint32_t program_len, uint32_t ram_len,
                  const uint8_t* packet, uint32_t packet_len,
                  uint32_t filter_age);

#ifdef __cplusplus
}
#endif

#endif  // APF_INTERPRETER_V5_H_
