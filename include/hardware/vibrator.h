/*
 * Copyright (C) 2013 The Android Open Source Project
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

#ifndef _HARDWARE_VIBRATOR_H
#define _HARDWARE_VIBRATOR_H

#include <hardware/hardware.h>

__BEGIN_DECLS

#define VIBRATOR_API_VERSION HARDWARE_MODULE_API_VERSION(1,0)

/**
 * The id of this module
 */
#define VIBRATOR_HARDWARE_MODULE_ID "vibrator"

/**
 * The id of the main vibrator device
 */
#define VIBRATOR_DEVICE_ID_MAIN "main_vibrator"

struct vibra_device;
typedef struct vibra_device {
  struct hw_device_t common;

    /**
     * Turn on vibrator
     *
     * @param timeout_ms number of milliseconds to vibrate
     *
     * @return 0 if successful, negative if error
     */
    int (*vibrator_on)(struct vibra_device* vibradev, int timeout_ms);

    /**
     * Turn off vibrator
     *
     * @return 0 if successful, negative if error
     */
    int (*vibrator_off)(struct vibra_device* vibradev);
} vibra_device_t;

static inline int vibrator_open(const struct hw_module_t* module, vibra_device_t** device)
{
    return module->methods->open(module, VIBRATOR_DEVICE_ID_MAIN, (struct hw_device_t**)device);
}

__END_DECLS

#endif  // _HARDWARE_VIBRATOR_H
