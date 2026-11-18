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

/* Android vendor commands, defined in the master copy
 * external/wpa_supplicant_8/wpa_supplicant/aidl/android_vendor.h. The APF
 * subcommands carry the net-apf attributes: each attribute ID there
 * (APF_ATTR_*) is the same as NET_APF_A_*. */
#define ANDROID_OUI 0xF4F5E8

enum android_nl80211_apf_subcmds {
	ANDROID_NL80211_SUBCMD_APF_GET_INFO	= 4,
	ANDROID_NL80211_SUBCMD_APF_SET_ID	= 5,
	ANDROID_NL80211_SUBCMD_APF_ENABLE	= 6,
	ANDROID_NL80211_SUBCMD_APF_GET_RAM_SIZE	= 7,
	ANDROID_NL80211_SUBCMD_APF_READ		= 8,
	ANDROID_NL80211_SUBCMD_APF_WRITE	= 9,
	ANDROID_NL80211_SUBCMD_APF_DISABLE	= 10,
	ANDROID_NL80211_SUBCMD_APF_SET_FAST_PATH = 11,
};

#endif /* NL_APF_NL80211_H */
