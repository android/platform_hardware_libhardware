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

#define VIBRATOR_API_VERSION 1

/**
 * The id of this module
 */
#define VIBRATOR_HARDWARE_MODULE_ID "vibrator"

typedef struct {
  struct hw_device_t common;

    /**
     * Turn on vibrator
     *
     * @param timeout_ms number of milliseconds to vibrate
     *
     * @return 0 if successful, negative if error
     */
    int (*vibrator_on)(int timeout_ms);

    /**
     * Turn off vibrator
     *
     * @return 0 if successful, negative if error
     */
    int (*vibrator_off)(void);
} vibra_device_t;

static inline int vibrator_hw_device_open(const struct hw_module_t* module, vibra_device_t** device)
{
    return module->methods->open(module, VIBRATOR_HARDWARE_MODULE_ID, (struct hw_device_t**)device);
}

__END_DECLS

#endif  // _HARDWARE_VIBRATOR_H
