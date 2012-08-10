/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>

#include <hardware/hardware.h>

__BEGIN_DECLS

#define VIBRATOR_API_VERSION 1

/**
 * The id of this module
 */
#define VIBRATOR_HARDWARE_MODULE_ID "vibrator"

/**
 * Every hardware module must have a data structure named HAL_MODULE_INFO_SYM
 * and the fields of this data structure must begin with hw_module_t
 * followed by module specific information.
 */
typedef struct vibrator_module {
    struct hw_module_t common;

    /**
     * Return whether the device has a vibrator.
     *
     * @return 1 if a vibrator exists, 0 if it doesn't.
     */
    int (*vibrator_exists)();

    /**
     * Turn on vibrator
     *
     * @param timeout_ms number of milliseconds to vibrate
     *
     * @return 0 if successful, -1 if error
     */
    int (*vibrator_on)(int timeout_ms);

    /**
     * Turn off vibrator
     *
     * @return 0 if successful, -1 if error
     */
    int (*vibrator_off)();
} vibrator_module_t;


__END_DECLS

#endif  // _HARDWARE_VIBRATOR_H
