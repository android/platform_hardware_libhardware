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

#ifndef ANDROID_LIBRARY_KEYSTORE_ENFORCEMENT_H
#define ANDROID_LIBRARY_KEYSTORE_ENFORCEMENT_H

#define ANDROID_UNTRUSTED_ZONE

#include <cutils/hashmap.h>
#include <gtest/gtest_prod.h>
#include <hardware/keymaster.h>
#include <List.h>
#include <utils/List.h>
#include <stdio.h>

#ifdef ANDROID_UNTRUSTED_ZONE
#include <semaphore.h>
#endif // ANDROID_UNTRUSTED_ZONE

#include "authorization_set.h"

using namespace android;
using namespace keymaster;

typedef uint32_t km_id_t;

struct access_time_struct {
    uint32_t keyid;
    time_t atime;
};

class KeystoreEnforcement {
    friend class KeystoreBaseTest; 

public:

    KeystoreEnforcement();

    ~KeystoreEnforcement();

    /**
     * Iterates through the authorization set and returns the corresponding
     * keymaster error. Will return KM_ERROR_OK if all criteria is met
     * for the given purpose in the authorization set. Used for encrypt, decrypt
     * sign, and verify.
     */
    keymaster_error_t AuthorizeOperation(const km_id_t keyid, const AuthorizationSet *auth_set,
            const uid_t uid, const keymaster_blob_t appid);

    /**
     * Ensures that all access control criteria are met for a rescope including
     * added and deleted parameters. Returns KM_ERROR_OK if all criteria is
     * met.
     */
    keymaster_error_t AuthorizeRescope(const km_id_t keyid, const AuthorizationSet *old_auth_set,
            const AuthorizationSet *new_auth_set, const uid_t uid);

    /**
     * If the tag is an access control tag then the function will determine if
     * all criteria for access has been met and return KM_ERROR_OK if so.
     */
    keymaster_error_t AuthorizeParameter(const AuthorizationSet *auth_set, const km_id_t keyid,
            const keymaster_key_param_t param, const keymaster_purpose_t purpose, const uid_t uid,
            keymaster_blob_t appid);

    /**
     * TODO: move to keymaster_util.
     * Returns if the tags and values associated with param1 and param2 are equal.
     */
    static bool km_param_compare(const keymaster_key_param_t param1,
            const keymaster_key_param_t param2);

    /**
     * Returns KM_ERROR_OK if currentTime is greater than the the time value
     * associated with param.
     */
    keymaster_error_t authorize_active_time(const keymaster_key_param_t param,
            const time_t current_time);

    /**
     * Returns KM_ERROR_OK if currentTime is less than the time value
     * associated with param and if purpose is KM_PURPOSE_VERIFY.
     * If purpose is not KM_PURPOSE_VERIFY will return KM_ERROR_OK.
     */
    keymaster_error_t authorize_usage_expire_time(const keymaster_key_param_t param,
            const time_t current_time, const keymaster_purpose_t purpose);
    /**
     * Returns KM_ERROR_OK if currentTime is less than the time value
     * associated with param and if purpose is KM_PURPOSE_SIGN.
     * If purpose is not KM_PURPOSE_SIGN will return KM_ERROR_OK.
     */
    keymaster_error_t authorize_origination_expire_time(const keymaster_key_param_t param,
            const time_t current_time, const keymaster_purpose_t purpose);

    /**
     * Returns KM_ERROR_OK if the difference between currentTime and the last accessed
     * time for the keyid is less than the time value associated with param.
     */
    keymaster_error_t authorize_min_time_between_ops(const keymaster_key_param_t param,
            const km_id_t keyid, const time_t current_time);

    /**
     * Returns KM_ERROR_OK if the keyid's last accessed time is -1 (has not been
     * accessed).
     */
    keymaster_error_t authorize_single_use_per_boot(const keymaster_key_param_t param,
            const km_id_t keyid);

    /**
     * Returns KM_ERROR_OK if the integer value of the parameter
     * is equal to the appId derived from the uid.
     */
    keymaster_error_t authorize_user_id(const keymaster_key_param_t param, const uid_t uid);

    /**
     * Returns KM_ERROR_OK if the last time the user authenticated is within
     * the required freshness.
     */
    keymaster_error_t authorize_auth_timeout(const keymaster_key_param_t param,
            const time_t current_time);

    /**
     * Returns KM_ERROR_OK if the appid's data and length matches the
     * length and data of the parameter's blob value.
     */
    keymaster_error_t authorize_auth_id(const AuthorizationSet *auth_set,
            const keymaster_key_param_t param, const keymaster_blob_t appid);

    /**
     * Returns KM_ERROR_OK if KM_TAG_APPLICATION_ID is not also
     * in the authorization set.
     */
    keymaster_error_t authorize_all_apps(const AuthorizationSet *auth_set);

    /** Returns KM_ERROR_OK if purpose is included in the authSet. */
    keymaster_error_t authorize_purpose(const keymaster_key_param_t purpose_param,
            const AuthorizationSet *auth_set);

    /**
     * This is maintaine din system/core/include/cutiles/multiuser.h but
     * copied here so that this code can be reused without access to the
     * core Android libs.
     */
    static const uint32_t MULTIUSER_APP_PER_USER_RANGE = 100000;

    /**
     * Updates the most recent user authentication time to the current time. */
    void update_user_authentication_time();

private:
    FRIEND_TEST(RescopeBaseTest, TEST_RESCOPE_DEL_SUB);
    FRIEND_TEST(RescopeBaseTest, TEST_RESCOPE_ADD_SUB);

    /* Class to abstract the mechanism used to keep track of access times. */
    class AccessTimeMap {
        public:
            AccessTimeMap();

            /* Returns the last time the key was accessed. */
            time_t get_last_key_access_time(uint32_t index);

            /* Updates the last key access time with the currentTime parameter. */
            void update_key_access_time(uint32_t index, time_t current_time);


        private:
            /**
             * Internal datastructure that maps keyid to access time. Can be
             * replaced with the cutil hashmap, linked list, etc.
             */
            List <access_time_struct>last_access_list;

            /* Returns an iterator to the node with the keyid or end if not found. */
            List<access_time_struct>::iterator find(uint32_t keyid);

    };


    /**
     * Returns true if it is valid to delete tag from authSet. It is valid to
     * be deleted if authSet contains a KM_TAG_RESCOPING_DEL parameter with
     * tag as it's value.
     */
    bool valid_rescope_add(const AuthorizationSet *auth_set, const keymaster_tag_t tag);

    /**
     * Returns true if it is valid to add tag to the authSet. It is valid to
     * be added if authSet contains a KM_TAG_RESCOPING_ADD parameter with
     * tag as it's value.
     */
    bool valid_rescope_del(const AuthorizationSet *auth_set, const keymaster_tag_t tag);


    /* Abstraction that currently just returns time(NULL). */
    time_t get_current_time();

    /* Translate the id of the key to be an index in the table. */
    static uint32_t key_id_to_index(const km_id_t keyid);

    /**
     * Updates the last time that the key was accessed to the current time.
     */
    void update_key_access_time(const km_id_t keyid);

    /**
     * Returns the last time that the key was accessed.
     */
    time_t get_last_access_time(km_id_t keyid);

    /**
     * Generates the userId from the uid using the formula
     * userId = uid / MULTIUSER_APP_PER_USER_RAGE.
     */
    static uint32_t get_user_id_from_uid(uid_t uid);

    /* Returns the last time that the user authenticated. */
    time_t get_last_auth_time();

    /* Acquires the lock. */
    int get_key_lock();

    /* Releases the lock. */
    int release_key_lock();

    /* Hashmap of last access times. */
    AccessTimeMap accessTimeMap;

#ifdef ANDROID_UNTRUSTED_ZONE
    /**
     * Serialize access to keys otherwise the min time between operations
     * and single use per boot will be racy. There may be a better way to
     * do it than a global lock.
     */
    sem_t key_lock;
#endif // ANDROID_UNTRUSTED_ZONE

    /* The time of the most recent user authentication. */
    time_t last_auth_time;

    /* Tests if the purpose is a valid member of keymaster_purpose_t. */
    bool is_valid_purpose(keymaster_purpose_t purpose);
};

#endif // KEYSTORE_ENFORCEMENT_H
