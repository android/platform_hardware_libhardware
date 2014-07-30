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

#include <cutils/hashmap.h>
#include <hardware/keymaster.h>
#include <semaphore.h>
#include <stdio.h>

#include <map>

#include "authorization_set.h"

#ifndef ANDROID_LIBRARY_KEYSTORE_ENFORCEMENT_H
#define ANDROID_LIBRARY_KEYSTORE_ENFORCEMENT_H

using namespace keymaster;

typedef uint32_t km_id_t;


class KeystoreEnforcement {

public:

    KeystoreEnforcement();

    ~KeystoreEnforcement();

    /**
     * Iterates through the authorization set and returns the corresponding
     * keymaster error. Will return KM_ERROR_OK if all criteria is met
     * for the given purpose in the authorization set. Used for encrypt, decrypt
     * sign, and verify.
     */
    keymaster_error_t authorizeOperation(km_id_t keyid,
            AuthorizationSet *authSet, uid_t uid, keymaster_blob_t appid);

    /**
     * Ensures that all access control criteria are met for a rescope including
     * added and deleted parameters. Returns KM_ERROR_OK if all criteria is
     * met.
     */
    keymaster_error_t authorizeRescope(km_id_t keyid,
            AuthorizationSet *oldAuthSet, AuthorizationSet *newAuthSet,
            uid_t uid);

    /**
     * If the tag is an access control tag then the function will determine if
     * all criteria for access has been met and return KM_ERROR_OK if so.
     */
    keymaster_error_t authorizeParameter(km_id_t keyid, keymaster_key_param_t param,
            keymaster_purpose_t purpose, uid_t uid, keymaster_blob_t appid);

    /**
     * Returns true if it is valid to delete tag from authSet. It is valid to
     * be deleted if authSet contains a KM_TAG_RESCOPING_DEL parameter with
     * tag as it's value.
     */
    bool validRescopeAdd(AuthorizationSet *authSet, keymaster_tag_t tag);

    /**
     * Returns true if it is valid to add tag to the authSet. It is valid to
     * be added if authSet contains a KM_TAG_RESCOPING_ADD parameter with
     * tag as it's value.
     */
    bool validRescopeDel(AuthorizationSet *authSet, keymaster_tag_t tag);

    /**
     * TODO: move to keymaster_util.
     * Returns if the tags and values associated with param1 and param2 are equal.
     */
    static bool kmParamCompare(keymaster_key_param_t param1, keymaster_key_param_t param2);

    /**
     * Returns KM_ERROR_OK if currentTime is greater than the the time value
     * associated with param.
     */
    keymaster_error_t authorizeActiveTime(
            keymaster_key_param_t param, time_t currentTime);

    /**
     * Returns KM_ERROR_OK if currentTime is less than the time value
     * associated with param and if purpose is KM_PURPOSE_VERIFY.
     * If purpose is not KM_PURPOSE_VERIFY will return KM_ERROR_OK.
     */
    keymaster_error_t authorizeUsageExpireTime(
            keymaster_key_param_t param, time_t currentTime,
            keymaster_purpose_t purpose);
    /**
     * Returns KM_ERROR_OK if currentTime is less than the time value
     * associated with param and if purpose is KM_PURPOSE_SIGN.
     * If purpose is not KM_PURPOSE_SIGN will return KM_ERROR_OK.
     */
    keymaster_error_t authorizeOriginationExpireTime(
            keymaster_key_param_t param, time_t currentTime,
            keymaster_purpose_t purpose);

    /**
     * Returns KM_ERROR_OK if the difference between currentTime and the last accessed
     * time for the keyid is less than the time value associated with param.
     */
    keymaster_error_t authorizeMinTimeBetweenOps(
            keymaster_key_param_t param, km_id_t keyid, time_t currentTime);

    /**
     * Returns KM_ERROR_OK if the keyid's last accessed time is -1 (has not been
     * accessed).
     */
    keymaster_error_t authorizeSingleUsePerBoot(
            keymaster_key_param_t param, km_id_t keyid);

    /**
     * Returns KM_ERROR_OK if the integer value of the parameter
     * is equal to the appId derived from the uid.
     */
    keymaster_error_t authorizeUserID(
            keymaster_key_param_t param, uid_t uid);

    /**
     * TODO (rileyspahn)
     */
    keymaster_error_t handleUserAuthID(keymaster_key_param_t param);

    /**
     * Returns KM_ERROR_OK if the last time the user authenticated is within
     * the required freshness.
     */
    keymaster_error_t authorizeAuthTimeout(
            keymaster_key_param_t param, time_t currentTime);

    /**
     * Returns KM_ERROR_OK if the appid's data and length matches the
     * length and data of the parameter's blob value.
     */
    keymaster_error_t authorizeAppId(keymaster_key_param_t param,
            keymaster_blob_t appid);

    /**
     * This is maintaine din system/core/include/cutiles/multiuser.h but
     * copied here so that this code can be reused without access to the
     * core Android libs.
     */
    static const uint32_t MULTIUSER_APP_PER_USER_RANGE = 100000;

    /**
     * Updates the most recent user authentication time to the current time. */
    void updateUserAuthenticationTime();

private:
    /* Class to abstract the mechanism used to keep track of access times. */
    class AccessTimeMap {
        public:
            /* Returns the last time the key was accessed. */
            time_t getLastKeyAccessTime(uint32_t index);

            /* Updates the last key access time with the currentTime parameter. */
            void updateKeyAccessTime(uint32_t index, time_t currentTime);

        private:
            /**
             * Internal datastructure that maps keyid to access time. Can be
             * replaced with the cutil hashmap, linked list, etc.
             */
            std::map<uint32_t, time_t> lastAccessMap;
    };

    /* Abstraction that currently just returns time(NULL). */
    time_t getCurrentTime();

    /* Translate the id of the key to be an index in the table. */
    static uint32_t keyIdToIndex(km_id_t keyId);

    /**
     * Updates the last time that the key was accessed to the current time.
     */
    void updateKeyAccessTime(km_id_t keyId);

    /**
     * Returns the last time that the key was accessed.
     */
    time_t getLastAccessTime(km_id_t keyId);

    /* Guess at the initial size of the hashmap. Don't konw how many keys. */
    static const uint32_t initialHashMapSize = 32;

    /**
     * Generates the appId from the uid using the formula:
     * appId = uid % MULTIUSER_APP_PER_USER_RANGE.
     */
    static uint32_t getAppIdFromUID(uid_t uid);

    /**
     * Generates the userId from the uid using the formula
     * userId = uid / MULTIUSER_APP_PER_USER_RAGE.
     */
    static uint32_t getUserIdFromUID(uid_t uid);

    /* Returns the last time that the user authenticated. */
    time_t getLastAuthTime();

    /* Hashmap of last access times. */
    AccessTimeMap accessTimeMap;

    /**
     * Serialize access to keys otherwise the min time between operations
     * and single use per boot will be racy. There may be a better way to
     * do it than a global lock.
     */
    sem_t keyLock;

    /* The time of the most recent user authentication. */
    time_t lastAuthTime;
};



#endif // KEYSTORE_ENFORCEMENT_H
