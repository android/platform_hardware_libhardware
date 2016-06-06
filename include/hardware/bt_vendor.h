/*
 * Copyright (C) 2016 The Linux Foundation. All rights reserved
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

#ifndef ANDROID_INCLUDE_BT_VENDOR_H
#define ANDROID_INCLUDE_BT_VENDOR_H

__BEGIN_DECLS

/** Callback when bredr cleanup is done.
 */
typedef void (*  btvendor_bredr_cleanup_callback)(bool status);


/** BT-Vendor callback structure. */
typedef struct {
    /** set to sizeof(BtVendorCallbacks) */
    size_t      size;
    btvendor_bredr_cleanup_callback  bredr_cleanup_cb;
} btvendor_callbacks_t;

/** Represents the standard BT-Vendor interface.
 */
typedef struct {

    /** set to sizeof(BtVendorInterface) */
    size_t          size;

    /**
     * Register the BtVendor callbacks
     */
    bt_status_t (*init)( btvendor_callbacks_t* callbacks );

    /** Does SSR cleanup */
    void (*ssrcleanup)(void);

    /** Does BREDR cleanup */
    void (*bredrcleanup)(void);

    /** Closes the interface. */
    void  (*cleanup)( void );

} btvendor_interface_t;

__END_DECLS

#endif /* ANDROID_INCLUDE_BT_VENDOR_H */

