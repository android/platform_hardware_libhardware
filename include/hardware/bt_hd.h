/*
 * Copyright (C) 2012 The Android Open Source Project
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

#ifndef ANDROID_INCLUDE_BT_HD_H
#define ANDROID_INCLUDE_BT_HD_H

#include <stdint.h>

__BEGIN_DECLS

#define BTHD_MAX_DSC_LEN   884

/* HD connection states */
typedef enum
{
    BTHD_CONN_STATE_CONNECTED              = 0,
    BTHD_CONN_STATE_CONNECTING,
    BTHD_CONN_STATE_DISCONNECTED,
    BTHD_CONN_STATE_DISCONNECTING,
    BTHD_CONN_STATE_FAILED_MOUSE_FROM_HOST,
    BTHD_CONN_STATE_FAILED_KBD_FROM_HOST,
    BTHD_CONN_STATE_FAILED_TOO_MANY_DEVICES,
    BTHD_CONN_STATE_FAILED_NO_BTHID_DRIVER,
    BTHD_CONN_STATE_FAILED_GENERIC,
    BTHD_CONN_STATE_UNKNOWN
} bthd_connection_state_t;

typedef enum
{
    BTHD_OK                = 0,
    BTHD_HS_HID_NOT_READY,        /* handshake error : device not ready */
    BTHD_HS_INVALID_RPT_ID,       /* handshake error : invalid report ID */
    BTHD_HS_TRANS_NOT_SPT,        /* handshake error : transaction not spt */
    BTHD_HS_INVALID_PARAM,        /* handshake error : invalid paremter */
    BTHD_HS_ERROR,                /* handshake error : unspecified HS error */
    BTHD_ERR,                     /* general BTA HD error */
    BTHD_ERR_SDP,                 /* SDP error */
    BTHD_ERR_PROTO,               /* SET_Protocol error,
                                                                only used in BTA_HD_OPEN_EVT callback */
    BTHD_ERR_DB_FULL,             /* device database full error, used  */
    BTHD_ERR_TOD_UNSPT,           /* type of device not supported */
    BTHD_ERR_NO_RES,              /* out of system resources */
    BTHD_ERR_AUTH_FAILED,         /* authentication fail */
    BTHD_ERR_HDL
}bthd_status_t;

/* Protocol modes */
typedef enum {
    BTHD_REPORT_MODE       = 0x00,
    BTHD_BOOT_MODE         = 0x01,
    BTHD_UNSUPPORTED_MODE  = 0xff
}bthd_protocol_mode_t;

/* Report types */
typedef enum {
    BTHD_INPUT_REPORT      = 1,
    BTHD_OUTPUT_REPORT,
    BTHD_FEATURE_REPORT
}bthd_report_type_t;

typedef struct
{
    int         attr_mask;
    uint8_t     sub_class;
    uint8_t     app_id;
    int         vendor_id;
    int         product_id;
    int         version;
    uint8_t     ctry_code;
    int         dl_len;
    uint8_t     dsc_list[BTHD_MAX_DSC_LEN];
} bthd_hid_info_t;

/** Callback for connection state change.
 *  state will have one of the values from bthd_connection_state_t
 */
typedef void (* bthd_connection_state_callback)(bt_bdaddr_t *bd_addr, bthd_connection_state_t state);

/** Callback for vitual unplug api.
 *  the status of the vitual unplug
 */
typedef void (* bthd_virtual_unplug_callback)(bt_bdaddr_t *bd_addr, bthd_status_t hd_status);

/** Callback for get hid info
 *  hid_info will contain attr_mask, sub_class, app_id, vendor_id, product_id, version, ctry_code, len
 */
typedef void (* bthd_hid_info_callback)(bt_bdaddr_t *bd_addr, bthd_hid_info_t hid_info);


/** BT-HD callback structure. */
typedef struct {
    /** set to sizeof(BtHfCallbacks) */
    size_t      size;
    bthd_connection_state_callback  connection_state_cb;
    bthd_hid_info_callback          hid_info_cb;
    bthd_virtual_unplug_callback    virtual_unplug_cb;
} bthd_callbacks_t;



/** Represents the standard BT-HD interface. */
typedef struct {

    /** set to sizeof(BtHdInterface) */
    size_t          size;

    /**
     * Register the BtHd callbacks
     */
    bt_status_t (*init)( bthd_callbacks_t* callbacks );

    /** connect to hid device */
    bt_status_t (*connect)( bt_bdaddr_t *bd_addr);

    /** dis-connect from hid device */
    bt_status_t (*disconnect)( bt_bdaddr_t *bd_addr );

    /** Virtual UnPlug (VUP) the specified HID device */
    bt_status_t (*virtual_unplug)(bt_bdaddr_t *bd_addr);

    /** Set the HID device descriptor for the specified HID device. */
    bt_status_t (*set_info)(bt_bdaddr_t *bd_addr, bthd_hid_info_t hid_info );

    /** Send data to HID device. */
    bt_status_t (*send_data)(bt_bdaddr_t *bd_addr, int data_len, char* data);

	/** Closes the interface. */
    void  (*cleanup)( void );

} bthd_interface_t;
__END_DECLS

#endif /* ANDROID_INCLUDE_BT_HD_H */


