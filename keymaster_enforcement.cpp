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

#include "keymaster_enforcement.h"

namespace keymaster {

KeymasterEnforcement::KeymasterEnforcement() {
    last_auth_time = -1;

#ifdef ANDROID_KEYMASTER_UNTRUSTED_ZONE
    sem_init(&key_lock, 1, 1);
#endif  // ANDROID_KEYMASTER_UNTRUSTED_ZONE
}

KeymasterEnforcement::~KeymasterEnforcement() {
#ifdef ANDROID_KEYMASTER_UNTRUSTED_ZONE
    sem_destroy(&key_lock);
#endif  // ANDROID_KEYMASTER_UNTRUSTED_ZONE
}

keymaster_error_t KeymasterEnforcement::AuthorizeOperation(const keymaster_purpose_t purpose,
                                                           const km_id_t keyid,
                                                           const AuthorizationSet* auth_set,
                                                           const uid_t uid,
                                                           const keymaster_blob_t appid) {
    get_key_lock();
    time_t current_time;
    keymaster_error_t return_error;

    /* Pairs of tags that are incompatible and should return an error. */
    bool tag_all_users_present = false, tag_user_id_present = false;
    bool tag_user_auth_id_present = false, tag_no_auth_required_present = false;
    bool tag_all_applications_present = false, tag_application_id_present = false;

    return_error = KM_ERROR_OK;
    current_time = get_current_time();
    if ((return_error = valid_purpose(purpose, auth_set)) != KM_ERROR_OK) {
        goto operation_clean_up;
    }

    for (unsigned int i = 0; return_error == KM_ERROR_OK && i < auth_set->size(); i++) {
        keymaster_key_param_t param = (*auth_set)[i];
        switch (param.tag) {
        case KM_TAG_ACTIVE_DATETIME:
            return_error = authorize_active_time(param, current_time);
            break;
        case KM_TAG_ORIGINATION_EXPIRE_DATETIME:
            return_error = authorize_origination_expire_time(param, current_time, purpose);
            break;
        case KM_TAG_USAGE_EXPIRE_DATETIME:
            return_error = authorize_usage_expire_time(param, current_time, purpose);
            break;
        case KM_TAG_MIN_SECONDS_BETWEEN_OPS:
            return_error = authorize_min_time_between_ops(param, keyid, current_time);
            break;
        case KM_TAG_SINGLE_USE_PER_BOOT:
            return_error = authorize_single_use_per_boot(param, keyid);
            break;
        case KM_TAG_ALL_USERS:
            tag_all_users_present = true;
            return_error = KM_ERROR_OK;
            break;
        case KM_TAG_USER_ID:
            tag_user_id_present = true;
            return_error = authorize_user_id(param, uid);
            break;
        case KM_TAG_NO_AUTH_REQUIRED:
            return_error = KM_ERROR_OK;
            tag_no_auth_required_present = true;
            break;
        case KM_TAG_AUTH_TIMEOUT:
        case KM_TAG_RESCOPE_AUTH_TIMEOUT:
            return_error = authorize_auth_timeout(param, current_time);
            break;
        case KM_TAG_ALL_APPLICATIONS:
            tag_all_applications_present = true;
            break;
        case KM_TAG_APPLICATION_ID:
            tag_application_id_present = true;
            return_error = authorize_app_id(auth_set, param, appid);
            break;
        case KM_TAG_USER_AUTH_ID:
            tag_user_auth_id_present = true;
            break;
        default:
            return_error = KM_ERROR_OK;
            break;
        }
    }

    if ((tag_all_users_present && tag_user_id_present) ||
        (tag_user_auth_id_present && tag_no_auth_required_present) ||
        (tag_all_applications_present && tag_application_id_present)) {
        return_error = KM_ERROR_INVALID_TAG;
    }

operation_clean_up:
    if (return_error == KM_ERROR_OK) {
        update_key_access_time(keyid);
    }

    release_key_lock();
    return return_error;
}

keymaster_error_t KeymasterEnforcement::authorize_active_time(const keymaster_key_param_t param,
                                                              const time_t current_time) {
    time_t activation_time = param.date_time;
    if (difftime(current_time, activation_time) < 0) {
        return KM_ERROR_KEY_NOT_YET_VALID;
    }

    return KM_ERROR_OK;
}

keymaster_error_t
KeymasterEnforcement::authorize_usage_expire_time(const keymaster_key_param_t param,
                                                  const time_t current_time,
                                                  const keymaster_purpose_t purpose) {
    if (purpose != KM_PURPOSE_VERIFY) {
        return KM_ERROR_OK;
    }

    time_t expire_time = param.date_time;
    if (difftime(current_time, expire_time) > 0) {
        return KM_ERROR_KEY_EXPIRED;
    }
    return KM_ERROR_OK;
}

keymaster_error_t
KeymasterEnforcement::authorize_origination_expire_time(const keymaster_key_param_t param,
                                                        const time_t current_time,
                                                        const keymaster_purpose_t purpose) {
    if (purpose != KM_PURPOSE_SIGN) {
        return KM_ERROR_OK;
    }

    time_t expire_time = param.date_time;
    if (difftime(current_time, expire_time) > 0) {
        return KM_ERROR_KEY_EXPIRED;
    }
    return KM_ERROR_OK;
}

keymaster_error_t KeymasterEnforcement::authorize_min_time_between_ops(
    const keymaster_key_param_t param, const km_id_t keyid, const time_t current_time) {
    uint32_t min_time_between = param.integer;

    if (difftime(current_time, get_last_access_time(keyid)) < min_time_between) {
        return KM_ERROR_TOO_MANY_OPERATIONS;
    }
    return KM_ERROR_OK;
}

keymaster_error_t
KeymasterEnforcement::authorize_single_use_per_boot(const keymaster_key_param_t param,
                                                    const km_id_t keyid) {
    if (get_last_access_time(keyid) > -1) {
        return KM_ERROR_TOO_MANY_OPERATIONS;
    }
    return KM_ERROR_OK;
}

keymaster_error_t KeymasterEnforcement::authorize_user_id(const keymaster_key_param_t param,
                                                          const uid_t uid) {
    uint32_t valid_user_id = param.integer;
    uint32_t user_id_to_test = get_user_id_from_uid(uid);

    if (valid_user_id == user_id_to_test) {
        return KM_ERROR_OK;
    } else {
        return KM_ERROR_INVALID_USER_ID;
    }
}

keymaster_error_t KeymasterEnforcement::authorize_auth_timeout(const keymaster_key_param_t param,
                                                               const time_t current_time) {
    time_t last_auth_time = get_last_auth_time();
    time_t required_time = param.integer;
    if (difftime(current_time, last_auth_time) > required_time) {
        return KM_ERROR_OK;
    } else {
        return KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
    }
}

keymaster_error_t KeymasterEnforcement::authorize_app_id(const AuthorizationSet* auth_set,
                                                         const keymaster_key_param_t param,
                                                         const keymaster_blob_t appid) {
    keymaster_blob_t valid_app_id = param.blob;

    if (valid_app_id.data_length == appid.data_length &&
        memcmp(valid_app_id.data, appid.data, appid.data_length) == 0 &&
        auth_set->find(KM_TAG_ALL_APPLICATIONS) == -1) {
        return KM_ERROR_OK;
    } else {
        return KM_ERROR_INVALID_USER_ID;
    }
}

bool KeymasterEnforcement::valid_rescope_del(const AuthorizationSet* auth_set,
                                             const keymaster_tag_t tag) {
    int tag_index = auth_set->find(KM_TAG_RESCOPING_DEL);
    while (tag_index >= 0) {
        if (static_cast<keymaster_tag_t>((*auth_set)[tag_index].integer) == tag) {
            return true;
        }
        tag_index = auth_set->find(KM_TAG_RESCOPING_DEL, tag_index);
    }

    return false;
}

bool KeymasterEnforcement::valid_rescope_add(const AuthorizationSet* auth_set,
                                             const keymaster_tag_t tag) {
    int tag_index = auth_set->find(KM_TAG_RESCOPING_ADD);
    while (tag_index >= 0) {
        if (static_cast<keymaster_tag_t>((*auth_set)[tag_index].integer) == tag) {
            return true;
        }
        tag_index = auth_set->find(KM_TAG_RESCOPING_ADD, tag_index);
    }

    return false;
}

keymaster_error_t KeymasterEnforcement::AuthorizeRescope(const km_id_t keyid,
                                                         const AuthorizationSet* old_auth_set,
                                                         const AuthorizationSet* new_auth_set,
                                                         const uid_t uid) {
    get_key_lock();
    keymaster_error_t return_error = KM_ERROR_OK;
    time_t current_time = get_current_time();
    int rescope_auth_index = old_auth_set->find(KM_TAG_RESCOPE_AUTH_TIMEOUT);
    if (rescope_auth_index >= 0) {
        keymaster_key_param_t rescope_auth_param = (*old_auth_set)[rescope_auth_index];
        keymaster_error_t auth_error = authorize_auth_timeout(rescope_auth_param, current_time);
        if (auth_error != KM_ERROR_OK) {
            return_error = auth_error;
            goto rescope_clean_up;
        }
    }

    for (unsigned int i = 0; i < old_auth_set->size(); i++) {
        keymaster_key_param_t kkp_old = (*old_auth_set)[i];
        if (kkp_old.tag == KM_TAG_RESCOPING_ADD || kkp_old.tag == KM_TAG_RESCOPING_DEL) {
            continue;
        }
        int newIndex = new_auth_set->find(kkp_old.tag);
        if (newIndex < 0) {
            if (!valid_rescope_del(old_auth_set, kkp_old.tag)) {
                return_error = KM_ERROR_INVALID_RESCOPING;
                goto rescope_clean_up;
            }
        } else {
            keymaster_key_param_t kkp_new = (*new_auth_set)[newIndex];
            if (!km_param_compare(kkp_old, kkp_new) &&
                (!valid_rescope_add(old_auth_set, kkp_old.tag) ||
                 !valid_rescope_del(old_auth_set, kkp_old.tag))) {
                return_error = KM_ERROR_INVALID_RESCOPING;
                goto rescope_clean_up;
            }
        }
    }

    for (unsigned int i = 0; i < new_auth_set->size(); i++) {
        keymaster_key_param_t kkp_new = (*new_auth_set)[i];
        if (kkp_new.tag == KM_TAG_RESCOPING_ADD || kkp_new.tag == KM_TAG_RESCOPING_DEL) {
            continue;
        }
        int old_index = old_auth_set->find(kkp_new.tag);
        if (old_index < 0) {
            if (!valid_rescope_add(old_auth_set, kkp_new.tag)) {
                return_error = KM_ERROR_INVALID_RESCOPING;
                goto rescope_clean_up;
            }
        }
    }

rescope_clean_up:
    release_key_lock();
    return return_error;
}

void KeymasterEnforcement::update_key_access_time(const km_id_t keyid) {
    accessTimeMap.update_key_access_time(keyid, get_current_time());
}

bool KeymasterEnforcement::km_param_compare(const keymaster_key_param_t param1,
                                            const keymaster_key_param_t param2) {
    if (param1.tag != param2.tag) {
        return false;
    }

    keymaster_tag_type_t tagType = keymaster_tag_get_type(param1.tag);
    switch (tagType) {
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
        return (memcmp(param1.blob.data, param2.blob.data, param1.blob.data_length) == 0);
    default:
        return false;
    }
}

time_t KeymasterEnforcement::get_current_time() { return time(NULL); }

time_t KeymasterEnforcement::get_last_access_time(km_id_t keyid) {
    return accessTimeMap.get_last_key_access_time(keyid);
}

uint32_t KeymasterEnforcement::get_user_id_from_uid(uid_t uid) {
    uint32_t userId = uid / MULTIUSER_APP_PER_USER_RANGE;
    return userId;
}

time_t KeymasterEnforcement::get_last_auth_time() { return last_auth_time; }

void KeymasterEnforcement::update_user_authentication_time() {
    get_key_lock();
    last_auth_time = get_current_time();
    release_key_lock();
}

bool KeymasterEnforcement::supported_purpose(const keymaster_purpose_t purpose) {
    switch (purpose) {
    case KM_PURPOSE_ENCRYPT:
    case KM_PURPOSE_DECRYPT:
    case KM_PURPOSE_SIGN:
    case KM_PURPOSE_VERIFY:
        return true;
        break;
    default:
        return false;
    }
}

bool KeymasterEnforcement::supported_purposes(const AuthorizationSet* auth_set) {
    int purpose_index;
    keymaster_purpose_t test_purpose;

    purpose_index = auth_set->find(KM_TAG_PURPOSE);
    for (; purpose_index >= 0; purpose_index = auth_set->find(KM_TAG_PURPOSE, purpose_index)) {
        test_purpose = static_cast<keymaster_purpose_t>((*auth_set)[purpose_index].enumerated);
        if (!supported_purpose(test_purpose)) {
            return false;
        }
    }

    return true;
}

keymaster_error_t KeymasterEnforcement::valid_purpose(const keymaster_purpose_t purpose,
                                                      const AuthorizationSet* auth_set) {
    if (!supported_purpose(purpose) || !supported_purposes(auth_set)) {
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }

    int purpose_index;
    keymaster_purpose_t test_purpose;
    purpose_index = auth_set->find(KM_TAG_PURPOSE);
    for (; purpose_index >= 0; purpose_index = auth_set->find(KM_TAG_PURPOSE, purpose_index)) {
        test_purpose = static_cast<keymaster_purpose_t>((*auth_set)[purpose_index].enumerated);
        if (test_purpose == purpose) {
            return KM_ERROR_OK;
        }
    }

    return KM_ERROR_INCOMPATIBLE_PURPOSE;
}

int KeymasterEnforcement::get_key_lock() {
#ifdef ANDROID_KEYMASTER_UNTRUSTED_ZONE
    return sem_wait(&key_lock);
#else
    return 0;
#endif  // ANDROID_KEYMASTER_UNTRUSTED_ZONE
}

int KeymasterEnforcement::release_key_lock() {
#ifdef ANDROID_KEYMASTER_UNTRUSTED_ZONE
    return sem_post(&key_lock);
#else
    return 0;
#endif  // ANDROID_KEYMASTER_UNTRUSTED_ZONE
}

KeymasterEnforcement::AccessTimeMap::AccessTimeMap() {}

List<access_time_struct>::iterator KeymasterEnforcement::AccessTimeMap::find(uint32_t key_index) {
    List<access_time_struct>::iterator posn;

    posn = last_access_list.begin();
    for (; (*posn).keyid != key_index && posn != last_access_list.end(); posn++) {
    }
    return posn;
}

void KeymasterEnforcement::AccessTimeMap::update_key_access_time(uint32_t key_index,
                                                                 time_t current_time) {
    List<access_time_struct>::iterator posn;

    posn = find(key_index);
    if (posn != last_access_list.end()) {
        (*posn).access_time = current_time;
    } else {
        access_time_struct ac;
        ac.keyid = key_index;
        ac.access_time = current_time;
        last_access_list.push_front(ac);
    }
}

time_t KeymasterEnforcement::AccessTimeMap::get_last_key_access_time(uint32_t key_index) {
    List<access_time_struct>::iterator posn;

    posn = find(key_index);
    if (posn != last_access_list.end()) {
        return (*posn).access_time;
    }
    return -1;
}

}; /* namespace keymaster */
