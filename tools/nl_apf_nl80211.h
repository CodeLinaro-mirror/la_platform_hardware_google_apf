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

#ifndef NL_APF_NL80211_H
#define NL_APF_NL80211_H

#include "net_apf.h"

#define OUI_GOOGLE 0x001A11

/* APF nl80211 vendor subcommands, 1:1 with enum net_apf_cmd. Must match
 * enum google_nl80211_apf_subcmds in the kernel driver. */
enum google_nl80211_apf_subcmds {
	GOOGLE_NL80211_SUBCMD_APF_GET_INFO	= 0x1810,
	GOOGLE_NL80211_SUBCMD_APF_SET_ID	= 0x1811,
	GOOGLE_NL80211_SUBCMD_APF_ENABLE	= 0x1812,
	GOOGLE_NL80211_SUBCMD_APF_GET_RAM_SIZE	= 0x1813,
	GOOGLE_NL80211_SUBCMD_APF_READ		= 0x1814,
	GOOGLE_NL80211_SUBCMD_APF_WRITE		= 0x1815,
	GOOGLE_NL80211_SUBCMD_APF_DISABLE	= 0x1816,
	GOOGLE_NL80211_SUBCMD_APF_SET_FAST_PATH	= 0x1817,
};

#endif /* NL_APF_NL80211_H */
