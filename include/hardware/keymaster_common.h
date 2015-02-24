/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef ANDROID_HARDWARE_KEYMASTER_COMMON_H
#define ANDROID_HARDWARE_KEYMASTER_COMMON_H

#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>

#include <hardware/hardware.h>

/**
 * The id of this module
 */
#define KEYSTORE_HARDWARE_MODULE_ID "keystore"

#define KEYSTORE_KEYMASTER "keymaster"


/**
 * Settings for "module_api_version" and "hal_api_version"
 * fields in the keymaster_module initialization.
 */

/**
 * Keymaster 0.X module version provide the same APIs, but later versions add more options
 * for algorithms and flags.
 */
#define KEYMASTER_MODULE_API_VERSION_0_2 HARDWARE_MODULE_API_VERSION(0, 2)
#define KEYMASTER_DEVICE_API_VERSION_0_2 HARDWARE_DEVICE_API_VERSION(0, 2)

#define KEYMASTER_MODULE_API_VERSION_0_3 HARDWARE_MODULE_API_VERSION(0, 3)
#define KEYMASTER_DEVICE_API_VERSION_0_3 HARDWARE_DEVICE_API_VERSION(0, 3)

/**
 * Keymaster 1.0 module version provides a completely different API, incompatible with 0.X.
 */
#define KEYMASTER_MODULE_API_VERSION_1_0 HARDWARE_MODULE_API_VERSION(1, 0)
#define KEYMASTER_DEVICE_API_VERSION_0_4 HARDWARE_DEVICE_API_VERSION(1, 0)

struct keystore_module {
    /**
     * Common methods of the keystore module.  This *must* be the first member of keystore_module as
     * users of this structure will cast a hw_module_t to keystore_module pointer in contexts where
     * it's known the hw_module_t references a keystore_module.
     */
    hw_module_t common;

    /* There are no keystore module methods other than the common ones. */
};

#endif  // ANDROID_HARDWARE_KEYMASTER_COMMON_H
