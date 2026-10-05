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

#ifndef _UAPI_LINUX_NET_APF_H
#define _UAPI_LINUX_NET_APF_H

#include <linux/types.h>

#define NET_APF_FAMILY_NAME	"net-apf"
#define NET_APF_FAMILY_VERSION	1

enum {
	NET_APF_A_IFINDEX = 1,
	NET_APF_A_INFO_VERSION,
	NET_APF_A_INFO_CHIP_ID,
	NET_APF_A_INFO_TOTAL_RAM,
	NET_APF_A_INFO_USED_RAM,
	NET_APF_A_INFO_OVERHEAD,
	NET_APF_A_INFO_GRANULARITY,
	NET_APF_A_RAM_SIZE,
	NET_APF_A_OFFSET,
	NET_APF_A_DATA,
	NET_APF_A_DATA_LEN,
	NET_APF_A_FP_UCAST_MAC,
	NET_APF_A_FP_VLAN_TAG,
	NET_APF_A_FP_UCAST_ADDR4,
	NET_APF_A_FP_ENABLE_IPV6,

	__NET_APF_A_MAX,
	NET_APF_A_MAX = (__NET_APF_A_MAX - 1)
};

enum {
	NET_APF_CMD_GET_INFO = 1,
	NET_APF_CMD_SET_ID,
	NET_APF_CMD_ENABLE,
	NET_APF_CMD_GET_RAM_SIZE,
	NET_APF_CMD_READ,
	NET_APF_CMD_WRITE,
	NET_APF_CMD_DISABLE,
	NET_APF_CMD_SET_FAST_PATH,

	__NET_APF_CMD_MAX,
	NET_APF_CMD_MAX = (__NET_APF_CMD_MAX - 1)
};

#endif /* _UAPI_LINUX_NET_APF_H */
