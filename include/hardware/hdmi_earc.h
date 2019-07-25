/*
 * Copyright (C) 2014 The Android Open Source Project
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

#ifndef ANDROID_INCLUDE_HARDWARE_HDMI_EARC_H
#define ANDROID_INCLUDE_HARDWARE_HDMI_EARC_H

#include <stdint.h>
#include <sys/cdefs.h>

#include <hardware/hardware.h>

__BEGIN_DECLS

#define HDMI_EARC_MODULE_API_VERSION_1_0 HARDWARE_MODULE_API_VERSION(1, 0)
#define HDMI_EARC_MODULE_API_VERSION_CURRENT HDMI_MODULE_API_VERSION_1_0

#define HDMI_EARC_DEVICE_API_VERSION_1_0 HARDWARE_DEVICE_API_VERSION(1, 0)
#define HDMI_EARC_DEVICE_API_VERSION_CURRENT HDMI_DEVICE_API_VERSION_1_0

#define HDMI_EARC_HARDWARE_MODULE_ID "hdmi_earc"
#define HDMI_EARC_HARDWARE_INTERFACE "hdmi_earc_hw_if"

/*
 * earc event type. used for hdmi_earc_event_t.
 */
enum {
    EARC_STATUS_CHG = 1,
};

/*
 * HDMI earc event type. Used when the event
 * type is HDMI_EVENT_EARC_STATUS.
 */
typedef enum earc_status {
    HDMI_EARC_NOT_ENABLED = 0,
    HDMI_EARC_WAITING  = 1,
    HDMI_EARC_ENABLED  = 2,
} earc_status_t;

typedef struct earc_event {
    /*
     * notify the state of eARC state Diagram.
     */
    earc_status_t status;
    int port_id;
} earc_event_t;

/*
 * HDMI earc event generated from HAL.
 */
typedef struct hdmi_earc_event {
    int type;
    struct hdmi_earc_device* dev;
    struct earc_event earc;
} hdmi_earc_event_t;

/*
 * Callback function type that will be called by HAL implementation.
 * Services can not close/open the device in the callback.
 */
typedef void (*earc_callback_t)(const hdmi_earc_event_t* event, void* arg);

typedef struct hdmi_earc_module {
    /**
     * Common methods of the HDMI EARC module.  This *must* be the first member of
     * hdmi_earc_module as users of this structure will cast a hw_module_t to hdmi_earc_module
     * pointer in contexts where it's known the hw_module_t references a hdmi_earc_module.
     */
    struct hw_module_t common;
} hdmi_earc_module_t;

/*
 * HDMI-CEC HAL interface definition.
 */
typedef struct hdmi_earc_device {
    /**
     * Common methods of the HDMI CEC device.  This *must* be the first member of
     * hdmi_cec_device as users of this structure will cast a hw_device_t to hdmi_cec_device
     * pointer in contexts where it's known the hw_device_t references a hdmi_cec_device.
     */
    struct hw_device_t common;

    /*
     * (*register_event_callback)() registers a callback that HDMI-EARC HAL
     * can later use for incoming EARC messages.
     * When calling from C++, use the argument arg to pass the calling object.
     * It will be passed back when the callback is invoked so that the context
     * can be retrieved.
     */
    void (*register_event_callback)(const struct hdmi_earc_device* dev,
            earc_callback_t callback, void* arg);

    /*
     * (*get_earc_status)() returns the state of earc state Diagram of the specified port.
     * Returns HDMI_EARC_NOT_ENABLED if earc device is not connected,
     * or HDMI_EARC_WAITING if earc connection is establishing,
     * or HDMI_EARC_ENABLED if earc device is connected.
     */
    earc_status_t (*get_earc_status)(const struct hdmi_earc_device* dev, int port_id);

    /* Reserved for future use to maximum 16 functions. Must be NULL. */
    void* reserved[16 - 3];
} hdmi_earc_device_t;

/** convenience API for opening and closing a device */

static inline int hdmi_earc_open(const struct hw_module_t* module,
        struct hdmi_earc_device** device) {
    return module->methods->open(module,
            HDMI_EARC_HARDWARE_INTERFACE, TO_HW_DEVICE_T_OPEN(device));
}

static inline int hdmi_earc_close(struct hdmi_earc_device* device) {
    return device->common.close(&device->common);
}

__END_DECLS

#endif /* ANDROID_INCLUDE_HARDWARE_HDMI_EARC_H */
