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

/**
 * Version History:
 *
 * HDMI_EARC_MODULE_API_VERSION_0_1:
 * Initial HDMI EARC hardware module API.
 */
#define HDMI_EARC_MODULE_API_VERSION_0_1        HARDWARE_MODULE_API_VERSION(0, 1)

#define HDMI_EARC_DEVICE_API_VERSION_0_1        HARDWARE_DEVICE_API_VERSION(0, 1)

#define HDMI_EARC_HARDWARE_MODULE_ID            "hdmi_earc"
#define HDMI_EARC_HARDWARE_INTERFACE            "hdmi_earc_hw_if"

/*
 * HDMI EARC event type.
 */
enum {
    HDMI_EARC_EVENT_STATUS_CHG = 0,
    HDMI_EARC_EVENT_CAPABILITY_CHG,
    HDMI_EARC_EVENT_LATENCY_CHG
};

/*
 * HDMI EARC flag.
 */
enum {
    NO_WAY = 0, /* all off */
    ARC_ONLY,
    PREFER_EARC
};

/*
 * HDMI EARC status change.
 */
enum {
    STATUS_CHG_TRUE = 1
};

/*
 * HDMI EARC Result code.
 */
enum {
    OK = 0,
    EARC_NOT_SUPPORT,
    INVALID_ARG,
    NO_RESPONED,
    UNKNOWN
};

/*
 * HDMI EARC connect status.
 */
typedef enum hdmi_earc_status {
    HDMI_EARC_IDLE = 0,     /* idle1          */
    HDMI_EARC_WAITING,      /* disc1_disc2    */
    HDMI_EARC_NOT_ENABLED,  /* idle2 for arc  */
    HDMI_EARC_ENABLED       /* earc connected */
} hdmi_earc_status_t;

/*
 * HDMI EARC Capability.
 */
#define EARC_CAP_MAX_SIZE   256
typedef struct hdmi_earc_cap {
    int payload_len;
    uint8_t payload[EARC_CAP_MAX_SIZE];
} hdmi_earc_cap_t;

/*
 * HDMI EARC Status Change Event.
 */
typedef struct status_change_event {
    hdmi_earc_status_t status;
} sta_chg_evt_t;

/*
 * HDMI EARC Capability Change Event.
 */
typedef struct cap_change_event {
    int flag;
} cap_chg_evt_t;

/*
 * HDMI EARC Latency Change Event.
 */
typedef int hdmi_earc_latcy_t;
typedef struct latency_change_event {
    int flag;
} latcy_chg_evt_t;

/*
 * HDMI-EARC event.
 */
typedef struct hdmi_earc_event {
    int type;
    struct hdmi_earc_device* dev;
    union {
        sta_chg_evt_t mode;
        latcy_chg_evt_t latcy;
        cap_chg_evt_t cap;
    };
} hdmi_earc_event_t;

/*
 * Callback function type that will be called by HAL implementation.
 * Services can not close/open the device in the callback.
 */
typedef void (*earc_event_cb)(const hdmi_earc_event_t* event, void* arg);

typedef struct hdmi_earc_module {
    /**
     * Common methods of the HDMI EARC module.  This *must* be the first member of
     * hdmi_earc_module as users of this structure will cast a hw_module_t to hdmi_earc_module
     * pointer in contexts where it's known the hw_module_t references a hdmi_earc_module.
     */
    struct hw_module_t common;
} hdmi_earc_module_t;

/*
 * HDMI-EARC HAL interface definition.
 */
typedef struct hdmi_earc_device {
    /*
     * Common methods of the HDMI EARC device.  This *must* be the first member of
     * hdmi_earc_device as users of this structure will cast a hw_device_t to hdmi_earc_device
     * pointer in contexts where it's known the hw_device_t references a hdmi_earc_device.
     */
    struct hw_device_t common;

    /*
     * (*is_supported)() related with hardware variation.
     *
     * Return Is earc support?
     * and the result code.
     */
    int (*is_supported)(const struct hdmi_earc_device* dev, int* status);

    /*
     * (*get_portId)() should be called when is_earc_support return true.
     *
     * Return the current earc port if existed 
     * and the result code.
     */
    int (*get_portId)(const struct hdmi_earc_device* dev, int* port_id);

    /*
     * (*control_feature)() UI control Earc feature. 
     * HDMI CTS specific user could control the earc feature(off/arc/earc)
     *
     * Return the result code.
     */
    int (*control_feature)(const struct hdmi_earc_device* dev, int flag);

    /*
     * (*get_status)() 
     * Earc which named the enhanced audio return channel is the first priority,
     * To avoid the ARC handshake in CEC Framework at first,
     * It's completely necessary to know the current driver status.
     * 
     * Return the current earc status(hdmi_earc_status_t).
     * HDMI_EARC_IDLE           : device power off.
     * HDMI_EARC_WAITING        : framework should not establish arc handshake 
     *                              until earc connected or timeout.
     * HDMI_EARC_NOT_ENABLED    : framework could extablish arc handshake immediately
     * HDMI_EARC_ENABLED        : framework should handle earc feature
     *
     * Return the result code.
     */
    int (*get_status)(const struct hdmi_earc_device* dev, hdmi_earc_status_t* status);

    /*
     * (*get_capability)() return the earc capability block,
     * the data structure as defined in hdmi2.1 spec 9.5 and example in Appendix H,
     * Which indicate the audio formats and sample rates that Earc rx support.
     * Earc tx shall only send Basic audio or audio that capability indicates it support.
     *
     * Return the result code.
     */
    int (*get_capability)(const struct hdmi_earc_device* dev,
                                        hdmi_earc_cap_t* capability);

    /*
     * (*get_latency)() return the latency value,
     * which sent from earc device and would be controled to 
     * adjust the audio latency.
     *
     * Return the result code.
     */
    int (*get_latency)(const struct hdmi_earc_device* dev,
                                        hdmi_earc_latcy_t* latency);

    /*
     * (*control_audio_latency)()
     * To support the eARC audio latency feature, it's used by the framework to
     * control/adjust the audio latencty in eARC mode. 
     *
     * Return the result code.
     */
    int (*control_audio_latency)(const struct hdmi_earc_device* dev,
                                        hdmi_earc_latcy_t latency);

    /*
     * (*register_event_callback)() registers callback for earc hal.
     * HDMI-EARC HAL could receive the event notify with
     * Mode/Capability/Latency Change.
     * The arg would be used to pass the calling object when calling from C++.
     * It will be passed back when the callback is invoked so that the context
     * can be retrieved.
     *
     * Return the result code.
     */
    int (*register_event_callback)(const struct hdmi_earc_device* dev,
                                        earc_event_cb callback, void* arg);

    /* Reserved for future use to maximum 16 functions. Must be NULL. */
    void* reserved[16 - 8];
} hdmi_earc_device_t;

/** convenience API for opening and closing a device */

static inline int hdmi_earc_open(const struct hw_module_t* module,
        struct hdmi_earc_device** device) {
    return module->methods->open(module, HDMI_EARC_HARDWARE_INTERFACE,
                TO_HW_DEVICE_T_OPEN(device));
}

static inline int hdmi_earc_close(struct hdmi_earc_device* device) {
    return device->common.close(&device->common);
}

__END_DECLS

#endif /* ANDROID_INCLUDE_HARDWARE_HDMI_EARC_H */

