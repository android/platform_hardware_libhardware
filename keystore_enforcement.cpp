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

#include "keystore_enforcement.h"
#include <string.h>
#include <time.h>

using namespace keymaster;

KeystoreEnforcement::KeystoreEnforcement() {
    sem_init(&keyLock, 1, 1);
    for (uint32_t i = 0; i < max_id; i++) {
        last_access[i] = -1;
    }
}

keymaster_error_t KeystoreEnforcement::authorizeOperation(km_id_t keyid,
        AuthorizationSet *authSet, uid_t uid) {
    sem_wait(&keyLock);

    keymaster_purpose_t purpose;
    AuthorizationSet _authSet = *authSet;
    keymaster_error_t returnError = KM_ERROR_OK;

    int purposeIndex = authSet->find(KM_TAG_PURPOSE);
    if (purposeIndex < 0) {
        returnError = KM_ERROR_UNSUPPORTED_PURPOSE;
        goto cleanUp;
    }
    purpose = static_cast<keymaster_purpose_t> (_authSet[purposeIndex].enumerated);

    for (unsigned int i = 0; returnError == KM_ERROR_OK && i < _authSet.size(); i++) {
        keymaster_key_param_t param = _authSet[i];
        returnError = authorizeParameter(keyid, param, purpose, uid);
    }

cleanUp:
    sem_post(&keyLock);
    if (returnError == KM_ERROR_OK) {
        updateKeyAccess(keyid);
    }
    return returnError;
}

keymaster_error_t KeystoreEnforcement::authorizeParameter(km_id_t keyid,
        keymaster_key_param_t param, keymaster_purpose_t purpose, uid_t uid) {

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
            returnError = authorizeAuthTimeout(param, currentTime);
            break;
        case KM_TAG_RESCOPE_AUTH_TIMEOUT:
            returnError = authorizeRescopeAuthTimeout(param, currentTime);
            break;
        case KM_TAG_ALL_APPLICATIONS:
            returnError = KM_ERROR_OK;
            break;
        case KM_TAG_APPLICATION_ID:
            returnError = authorizeAppId(param, uid);
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
    uint32_t keyIndex = keyIdToIndex(keyid);

    if (difftime(currentTime, last_access[keyIndex]) < minTimeBetween) {
        return KM_ERROR_TOO_MANY_OPERATIONS;
    }
    return KM_ERROR_OK;
}

keymaster_error_t KeystoreEnforcement::authorizeSingleUsePerBoot(
        keymaster_key_param_t param, km_id_t keyid) {
    uint32_t keyIndex = keyIdToIndex(keyid);
    if (last_access[keyIndex] > -1) {
        return KM_ERROR_TOO_MANY_OPERATIONS;
    }
    return KM_ERROR_OK;
}

keymaster_error_t KeystoreEnforcement::authorizeUserID(
        keymaster_key_param_t param, uid_t uid) {
    /* TODO (rileyspahn)*/
    return KM_ERROR_OK;
}

keymaster_error_t KeystoreEnforcement::handleUserAuthID(keymaster_key_param_t param) {
    /* TODO (rileyspahn)*/
    return KM_ERROR_OK;
}

keymaster_error_t KeystoreEnforcement::authorizeAuthTimeout(
        keymaster_key_param_t param, time_t currentTime) {
    /* TODO (rileyspahn)*/
    return KM_ERROR_OK;
}

keymaster_error_t KeystoreEnforcement::authorizeRescopeAuthTimeout(
        keymaster_key_param_t param, time_t currentTime) {
    /* TODO (rileyspahn) */
    return KM_ERROR_OK;
}

keymaster_error_t KeystoreEnforcement::authorizeAppId(keymaster_key_param_t param,
        uid_t uid) {
    /* TODO (rileyspahn) */
    return KM_ERROR_OK;
}

bool KeystoreEnforcement::validRescopeDel(AuthorizationSet *authSet, keymaster_tag_t tag) {
    AuthorizationSet _authSet = *authSet;
    int tagIndex = _authSet.find(KM_TAG_RESCOPING_DEL);
    while (tagIndex >= 0) {
        if (static_cast<keymaster_tag_t> (_authSet[tagIndex].integer) == tag) {
            return true;
        }
        tagIndex = _authSet.find(KM_TAG_RESCOPING_DEL, tagIndex);
    }

    return false;
}

bool KeystoreEnforcement::validRescopeAdd(AuthorizationSet *authSet, keymaster_tag_t tag) {
    AuthorizationSet _authSet = *authSet;
    int tagIndex = _authSet.find(KM_TAG_RESCOPING_ADD);
    while (tagIndex >= 0) {
        if (static_cast<keymaster_tag_t> (_authSet[tagIndex].integer) == tag) {
            return true;
        }
        tagIndex = _authSet.find(KM_TAG_RESCOPING_ADD, tagIndex);
    }

    return false;
}

keymaster_error_t KeystoreEnforcement::authorizeRescope(km_id_t keyid,
        AuthorizationSet *oldAuthSet, AuthorizationSet *newAuthSet, uid_t uid) {
    AuthorizationSet _oldAuthSet = *oldAuthSet;
    AuthorizationSet _newAuthSet = *newAuthSet;

    for (unsigned int i = 0; i < _oldAuthSet.size(); i++) {
        keymaster_key_param_t kkpOld = _oldAuthSet[i];
        if (kkpOld.tag == KM_TAG_RESCOPING_ADD || kkpOld.tag == KM_TAG_RESCOPING_DEL) {
            continue;
        }
        int newIndex = _newAuthSet.find(kkpOld.tag);
        if (newIndex < 0) {
            if (!validRescopeDel(oldAuthSet, kkpOld.tag)){
                return KM_ERROR_INVALID_RESCOPING;
            }
        } else {
            keymaster_key_param_t kkpNew = _newAuthSet[newIndex];
            if (!kmParamCompare(kkpOld, kkpNew) &&
                    (!validRescopeAdd(oldAuthSet, kkpOld.tag) ||
                     !validRescopeDel(oldAuthSet, kkpOld.tag))) {
                    return KM_ERROR_INVALID_RESCOPING;
            }
        }
    }

    for (unsigned int i = 0; i < _newAuthSet.size(); i++) {
        keymaster_key_param_t kkpNew = _newAuthSet[i];
        if (kkpNew.tag == KM_TAG_RESCOPING_ADD || kkpNew.tag == KM_TAG_RESCOPING_DEL) {
            continue;
        }
        int oldIndex = _oldAuthSet.find(kkpNew.tag);
        if (oldIndex < 0) {
            if (!validRescopeAdd(oldAuthSet, kkpNew.tag)) {
                return KM_ERROR_INVALID_RESCOPING;
            }
        }
    }

    return KM_ERROR_OK;
}

void KeystoreEnforcement::updateKeyAccess(km_id_t keyId) {
    uint32_t keyIndex = keyIdToIndex(keyId);
    last_access[keyIndex] = getCurrentTime();
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
