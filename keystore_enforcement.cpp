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

#include <string.h>
#include <time.h>

#include "keystore_enforcement.h"

using namespace keymaster;

static int keyid_hash(void *keyid) {
    //return hashmapHash(keyid, sizeof(km_id_t));
    return -1;
}

static bool keyid_equals(void *key1, void* key2) {
    km_id_t *k1;
    km_id_t *k2;

    k1 = (km_id_t *)key1;
    k2 = (km_id_t *)key2;
    return *k1 == *k2;
}

KeystoreEnforcement::KeystoreEnforcement() {
    sem_init(&keyLock, 1, 1);
    lastAuthTime = -1;
}

KeystoreEnforcement::~KeystoreEnforcement() {
}

keymaster_error_t KeystoreEnforcement::authorizeOperation(km_id_t keyid,
        AuthorizationSet *authSet, uid_t uid, keymaster_blob_t appid) {
    sem_wait(&keyLock);

    keymaster_purpose_t purpose;
    keymaster_error_t returnError = KM_ERROR_OK;

    int purposeIndex = authSet->find(KM_TAG_PURPOSE);
    if (purposeIndex < 0) {
        returnError = KM_ERROR_UNSUPPORTED_PURPOSE;
        goto cleanUp;
    }
    purpose = static_cast<keymaster_purpose_t> ((*authSet)[purposeIndex].enumerated);

    for (unsigned int i = 0; returnError == KM_ERROR_OK && i < authSet->size(); i++) {
        keymaster_key_param_t param = (*authSet)[i];
        returnError = authorizeParameter(keyid, param, purpose, uid, appid);
    }

cleanUp:
    sem_post(&keyLock);
    if (returnError == KM_ERROR_OK) {
        updateKeyAccessTime(keyid);
    }
    return returnError;
}

keymaster_error_t KeystoreEnforcement::authorizeParameter(km_id_t keyid,
        keymaster_key_param_t param, keymaster_purpose_t purpose, uid_t uid,
        keymaster_blob_t appid) {

    keymaster_tag_t tag = param.tag;
    time_t currentTime = getCurrentTime();
    keymaster_error_t returnError = KM_ERROR_OK;

    switch (tag) {
        case KM_TAG_ACTIVE_DATETIME:
            returnError = authorizeActiveTime(param, currentTime);
            break;
        case KM_TAG_USAGE_EXPIRE_DATETIME:
            returnError = authorizeUsageExpireTime(param, currentTime, purpose);
            break;
        case KM_TAG_ORIGINATION_EXPIRE_DATETIME:
            returnError = authorizeOriginationExpireTime(param, currentTime,
                    purpose);
            break;
        case KM_TAG_MIN_SECONDS_BETWEEN_OPS:
            returnError = authorizeMinTimeBetweenOps(param, keyid, currentTime);
            break;
        case KM_TAG_SINGLE_USE_PER_BOOT:
            returnError = authorizeSingleUsePerBoot(param, keyid);
            break;
        case KM_TAG_ALL_USERS:
            returnError = KM_ERROR_OK;
            break;
        case KM_TAG_USER_ID:
            returnError = authorizeUserID(param, uid);
            break;
        case KM_TAG_NO_AUTH_REQUIRED:
            returnError = KM_ERROR_OK;
            break;
        case KM_TAG_USER_AUTH_ID:
            returnError = handleUserAuthID(param);
            break;
        case KM_TAG_AUTH_TIMEOUT:
        case KM_TAG_RESCOPE_AUTH_TIMEOUT:
            returnError = authorizeAuthTimeout(param, currentTime);
            break;
        case KM_TAG_ALL_APPLICATIONS:
            returnError = KM_ERROR_OK;
            break;
        case KM_TAG_APPLICATION_ID:
            returnError = authorizeAppId(param, appid);
            break;
        default:
            returnError = KM_ERROR_OK;
            break;
    }

    return returnError;
}

keymaster_error_t KeystoreEnforcement::authorizeActiveTime(
        keymaster_key_param_t param, time_t currentTime) {
    time_t activationTime = param.date_time;
    if (difftime(currentTime, activationTime) < 0) {
        return KM_ERROR_KEY_NOT_YET_VALID;
    }

    return KM_ERROR_OK;
}

keymaster_error_t KeystoreEnforcement::authorizeUsageExpireTime(
        keymaster_key_param_t param, time_t currentTime,
        keymaster_purpose_t purpose) {
    if (purpose != KM_PURPOSE_VERIFY) {
        return KM_ERROR_OK;
    }

    time_t expireTime = param.date_time;
    if (difftime(currentTime, expireTime) > 0) {
        return KM_ERROR_KEY_EXPIRED;
    }
    return KM_ERROR_OK;
}

keymaster_error_t KeystoreEnforcement::authorizeOriginationExpireTime(
        keymaster_key_param_t param, time_t currentTime,
        keymaster_purpose_t purpose) {
    if (purpose != KM_PURPOSE_SIGN) {
        return KM_ERROR_OK;
    }

    time_t expireTime = param.date_time;
    if (difftime(currentTime, expireTime) > 0) {
        return KM_ERROR_KEY_EXPIRED;
    }
    return KM_ERROR_OK;
}

keymaster_error_t KeystoreEnforcement::authorizeMinTimeBetweenOps(
        keymaster_key_param_t param, km_id_t keyid, time_t currentTime) {
    uint32_t minTimeBetween = param.integer;

    if (difftime(currentTime, getLastAccessTime(keyid)) < minTimeBetween) {
        return KM_ERROR_TOO_MANY_OPERATIONS;
    }
    return KM_ERROR_OK;
}

keymaster_error_t KeystoreEnforcement::authorizeSingleUsePerBoot(
        keymaster_key_param_t param, km_id_t keyid) {
    if (getLastAccessTime(keyid) > -1) {
        return KM_ERROR_TOO_MANY_OPERATIONS;
    }
    return KM_ERROR_OK;
}

keymaster_error_t KeystoreEnforcement::authorizeUserID(
        keymaster_key_param_t param, uid_t uid) {
    uint32_t validUserId = param.integer;
    uint32_t userIdToTest = getUserIdFromUID(uid);

    if (validUserId == userIdToTest) {
        return KM_ERROR_OK;
    } else {
        return KM_ERROR_INVALID_USER_ID;
    }
}

keymaster_error_t KeystoreEnforcement::handleUserAuthID(keymaster_key_param_t param) {
    /* TODO (rileyspahn)*/
    return KM_ERROR_OK;
}

keymaster_error_t KeystoreEnforcement::authorizeAuthTimeout(
        keymaster_key_param_t param, time_t currentTime) {
    time_t lastAuthTime = getLastAuthTime();
    time_t required_time = param.integer;
    if (difftime(currentTime, lastAuthTime) > 0) {
        return KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
    } else {
        return KM_ERROR_OK;
    }
}

keymaster_error_t KeystoreEnforcement::authorizeAppId(keymaster_key_param_t param,
        keymaster_blob_t appid) {
    keymaster_blob_t validAppId = param.blob;

    if (validAppId.data_length == appid.data_length &&
            memcmp(validAppId.data, appid.data, appid.data_length) == 0) {
        return KM_ERROR_OK;
    } else {
        /* TODO (rileyspahn): Is there an eror for invalid app id? */
        return KM_ERROR_INVALID_USER_ID;
    }
}

bool KeystoreEnforcement::validRescopeDel(AuthorizationSet *authSet, keymaster_tag_t tag) {
    int tagIndex = authSet->find(KM_TAG_RESCOPING_DEL);
    while (tagIndex >= 0) {
        if (static_cast<keymaster_tag_t> ((*authSet)[tagIndex].integer) == tag) {
            return true;
        }
        tagIndex = authSet->find(KM_TAG_RESCOPING_DEL, tagIndex);
    }

    return false;
}

bool KeystoreEnforcement::validRescopeAdd(AuthorizationSet *authSet, keymaster_tag_t tag) {
    int tagIndex = authSet->find(KM_TAG_RESCOPING_ADD);
    while (tagIndex >= 0) {
        if (static_cast<keymaster_tag_t> ((*authSet)[tagIndex].integer) == tag) {
            return true;
        }
        tagIndex = authSet->find(KM_TAG_RESCOPING_ADD, tagIndex);
    }

    return false;
}

keymaster_error_t KeystoreEnforcement::authorizeRescope(km_id_t keyid,
        AuthorizationSet *oldAuthSet, AuthorizationSet *newAuthSet, uid_t uid) {

    for (unsigned int i = 0; i < oldAuthSet->size(); i++) {
        keymaster_key_param_t kkpOld = (*oldAuthSet)[i];
        if (kkpOld.tag == KM_TAG_RESCOPING_ADD || kkpOld.tag == KM_TAG_RESCOPING_DEL) {
            continue;
        }
        int newIndex = newAuthSet->find(kkpOld.tag);
        if (newIndex < 0) {
            if (!validRescopeDel(oldAuthSet, kkpOld.tag)){
                return KM_ERROR_INVALID_RESCOPING;
            }
        } else {
            keymaster_key_param_t kkpNew = (*newAuthSet)[newIndex];
            if (!kmParamCompare(kkpOld, kkpNew) &&
                    (!validRescopeAdd(oldAuthSet, kkpOld.tag) ||
                     !validRescopeDel(oldAuthSet, kkpOld.tag))) {
                    return KM_ERROR_INVALID_RESCOPING;
            }
        }
    }

    for (unsigned int i = 0; i < newAuthSet->size(); i++) {
        keymaster_key_param_t kkpNew = (*newAuthSet)[i];
        if (kkpNew.tag == KM_TAG_RESCOPING_ADD || kkpNew.tag == KM_TAG_RESCOPING_DEL) {
            continue;
        }
        int oldIndex = oldAuthSet->find(kkpNew.tag);
        if (oldIndex < 0) {
            if (!validRescopeAdd(oldAuthSet, kkpNew.tag)) {
                return KM_ERROR_INVALID_RESCOPING;
            }
        }
    }

    return KM_ERROR_OK;
}

void KeystoreEnforcement::updateKeyAccessTime(km_id_t keyId) {
    uint32_t keyIndex = keyIdToIndex(keyId);
    accessTimeMap.updateKeyAccessTime(keyId, getCurrentTime());
}

uint32_t KeystoreEnforcement::keyIdToIndex(km_id_t keyId) {
    return keyId;
}

bool KeystoreEnforcement::kmParamCompare(keymaster_key_param_t param1,
        keymaster_key_param_t param2) {
    if (param1.tag != param2.tag) {
        return false;
    }

    keymaster_tag_type_t tagType = keymaster_tag_get_type(param1.tag);
    switch(tagType) {
        case KM_ENUM:
        case KM_ENUM_REP:
            return param1.enumerated == param2.enumerated;
        case KM_INT:
        case KM_INT_REP:
            return param1.integer == param2.integer;
        case KM_LONG:
            return param1.long_integer == param2.long_integer;
        case KM_DATE:
            return param1.date_time == param2.date_time;
        case KM_BOOL:
            return param1.boolean == param2.boolean;
        case KM_BIGNUM:
        case KM_BYTES:
            if (param1.blob.data_length != param2.blob.data_length) {
                return false;
            }
            return (memcmp(param1.blob.data, param2.blob.data,
                        param1.blob.data_length) == 0);
        default:
            return false;
    }
}

time_t KeystoreEnforcement::getCurrentTime() {
    return time(NULL);
}

time_t KeystoreEnforcement::getLastAccessTime(km_id_t keyId) {
    uint32_t keyIndex = keyIdToIndex(keyId);
    return accessTimeMap.getLastKeyAccessTime(keyIndex);
}

uint32_t KeystoreEnforcement::getAppIdFromUID(uid_t uid) {
    uint32_t appId = uid % MULTIUSER_APP_PER_USER_RANGE;
    return appId;
}

uint32_t KeystoreEnforcement::getUserIdFromUID(uid_t uid) {
    uint32_t userId = uid / MULTIUSER_APP_PER_USER_RANGE;
    return userId;
}

time_t KeystoreEnforcement::getLastAuthTime() {
    return lastAuthTime;
}

void KeystoreEnforcement::updateUserAuthenticationTime() {
    sem_wait(&keyLock);
    time_t lastAuthTime = getCurrentTime();
    sem_post(&keyLock);
}

void KeystoreEnforcement::AccessTimeMap::updateKeyAccessTime(uint32_t keyIndex,
        time_t currentTime) {
    lastAccessMap[keyIndex] = currentTime;
}

time_t KeystoreEnforcement::AccessTimeMap::getLastKeyAccessTime(
        uint32_t keyIndex) {

    std::map<uint32_t, time_t>::iterator returnIt;
    returnIt = lastAccessMap.find(keyIndex);
    if (returnIt == lastAccessMap.end()) {
        return -1;
    } else {
        return returnIt->second;
    }
}
