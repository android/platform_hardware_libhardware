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

#include <gtest/gtest.h>

#include <errno.h>
#include <hardware/keymaster.h>
#include <stdio.h>
#include <time.h>

#include "authorization_set.h"
#include "keymaster_enforcement.h"

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    return result;
}

namespace keymaster {
namespace test {

class KeymasterBaseTest : public ::testing::Test {
  protected:
    KeymasterBaseTest() {
        past_time = 0;

        time_t t = time(NULL);
        future_tm = localtime(&t);
        future_tm->tm_year += 1;
        future_time = mktime(future_tm);
        sign_param = keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN);
    }
    virtual ~KeymasterBaseTest() {}

    tm past_tm;
    tm* future_tm;
    time_t past_time;
    time_t future_time;
    static const km_id_t key_id = 0xa;
    static const uid_t uid = 0xf;
    keymaster_key_param_t sign_param;
    keymaster_blob_t def_app_id;
    size_t def_app_id_size;
};

class ComparisonBaseTest : public KeymasterBaseTest {};

class RescopeBaseTest : public KeymasterBaseTest {
    friend class KeymasterEnforcement;
};

TEST_F(KeymasterBaseTest, TEST_VALID_KEY_PERIOD_NO_TAGS) {
    keymaster_key_param_t params[] = {
        sign_param,
    };
    AuthorizationSet single_auth_set(params, 1);
    KeymasterEnforcement kmen;

    keymaster_error_t kmer =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &single_auth_set, uid, def_app_id);
    ASSERT_EQ(KM_ERROR_OK, kmer);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_ACTIVE_TIME) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_bool(KM_TAG_NO_AUTH_REQUIRED),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, future_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 4);

    keymaster_error_t kmer_invalid_time =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, uid, def_app_id);
    ASSERT_EQ(KM_ERROR_KEY_NOT_YET_VALID, kmer_invalid_time);
}

TEST_F(KeymasterBaseTest, TEST_VALID_ACTIVE_TIME) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 3);

    keymaster_error_t kmer_valid_time =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, uid, def_app_id);
    ASSERT_EQ(KM_ERROR_OK, kmer_valid_time);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_ORIGINATION_EXPIRE_TIME) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_date(KM_TAG_ORIGINATION_EXPIRE_DATETIME, past_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 4);

    keymaster_error_t kmer_invalid_origination =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, uid, def_app_id);
    ASSERT_EQ(KM_ERROR_KEY_EXPIRED, kmer_invalid_origination);
}

TEST_F(KeymasterBaseTest, TEST_VALID_ORIGINATION_EXPIRE_TIME) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_date(KM_TAG_ORIGINATION_EXPIRE_DATETIME, future_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 4);

    keymaster_error_t kmer_valid_origination =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, uid, def_app_id);
    ASSERT_EQ(KM_ERROR_OK, kmer_valid_origination);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_USAGE_EXPIRE_TIME) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_VERIFY),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_date(KM_TAG_USAGE_EXPIRE_DATETIME, past_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 5);

    keymaster_error_t kmer_invalid_origination =
        kmen.AuthorizeOperation(KM_PURPOSE_VERIFY, key_id, &auth_set, uid, def_app_id);
    ASSERT_EQ(KM_ERROR_KEY_EXPIRED, kmer_invalid_origination);
}

TEST_F(KeymasterBaseTest, TEST_VALID_USAGE_EXPIRE_TIME) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_VERIFY),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_date(KM_TAG_USAGE_EXPIRE_DATETIME, future_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 4);

    keymaster_error_t kmer_valid_usage =
        kmen.AuthorizeOperation(KM_PURPOSE_VERIFY, key_id, &auth_set, uid, def_app_id);
    ASSERT_EQ(KM_ERROR_OK, kmer_valid_usage);
}

TEST_F(KeymasterBaseTest, TEST_VALID_SINGLE_USE_ACCESSES) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 3);

    keymaster_error_t kmer1 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, uid, def_app_id);
    keymaster_error_t kmer2 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, uid, def_app_id);

    ASSERT_EQ(KM_ERROR_OK, kmer1);
    ASSERT_EQ(KM_ERROR_OK, kmer2);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_SINGLE_USE_ACCESSES) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_bool(KM_TAG_SINGLE_USE_PER_BOOT),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 4);

    keymaster_error_t kmer1 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, uid, def_app_id);
    keymaster_error_t kmer2 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, uid, def_app_id);

    ASSERT_EQ(KM_ERROR_OK, kmer1);
    ASSERT_EQ(KM_ERROR_TOO_MANY_OPERATIONS, kmer2);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_TIME_BETWEEN_OPS) {
    keymaster_key_param_t params[] = {
        keymaster_param_bool(KM_TAG_ALL_USERS),
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_int(KM_TAG_MIN_SECONDS_BETWEEN_OPS, 10),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 5);

    keymaster_error_t kmer1 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, uid, def_app_id);
    keymaster_error_t kmer2 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, uid, def_app_id);

    ASSERT_EQ(KM_ERROR_OK, kmer1);
    sleep(2);
    ASSERT_EQ(KM_ERROR_TOO_MANY_OPERATIONS, kmer2);
}

TEST_F(KeymasterBaseTest, TEST_VALID_TIME_BETWEEN_OPS) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_VERIFY),
        keymaster_param_date(KM_TAG_USAGE_EXPIRE_DATETIME, future_time),
        keymaster_param_date(KM_TAG_ORIGINATION_EXPIRE_DATETIME, future_time),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_int(KM_TAG_MIN_SECONDS_BETWEEN_OPS, 2),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 7);

    keymaster_error_t kmer1 =
        kmen.AuthorizeOperation(KM_PURPOSE_VERIFY, key_id, &auth_set, uid, def_app_id);
    sleep(3);
    keymaster_error_t kmer2 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, uid, def_app_id);

    ASSERT_EQ(KM_ERROR_OK, kmer1);
    ASSERT_EQ(KM_ERROR_OK, kmer2);
}

TEST_F(KeymasterBaseTest, TEST_NO_RESCOPES) {
    keymaster_key_param_t params1[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_USER_ID, 1),
    };
    keymaster_key_param_t params2[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_USER_ID, 1),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 3);
    AuthorizationSet auth_set2(params2, 3);

    ASSERT_EQ(KM_ERROR_OK, kmen.AuthorizeRescope(1, &auth_set1, &auth_set2, 1));
}

TEST_F(RescopeBaseTest, TEST_VALID_RESCOPE_ADD) {
    keymaster_key_param_t params1[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_int(KM_TAG_RESCOPING_ADD, KM_TAG_SINGLE_USE_PER_BOOT),
        keymaster_param_int(KM_TAG_RESCOPING_ADD, KM_TAG_USAGE_EXPIRE_DATETIME),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_USER_ID, 1),
        keymaster_param_int(KM_TAG_RESCOPING_DEL, KM_TAG_USER_ID),
    };

    keymaster_key_param_t params2[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_USER_ID, 1), keymaster_param_bool(KM_TAG_SINGLE_USE_PER_BOOT),
    };

    keymaster_key_param_t params3[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_USER_ID, 1),
        keymaster_param_date(KM_TAG_USAGE_EXPIRE_DATETIME, 25),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 6);
    AuthorizationSet auth_set2(params2, 4);
    AuthorizationSet auth_set3(params3, 4);

    ASSERT_EQ(KM_ERROR_OK, kmen.AuthorizeRescope(1, &auth_set1, &auth_set2, 1));
    ASSERT_EQ(KM_ERROR_OK, kmen.AuthorizeRescope(1, &auth_set1, &auth_set3, 1));
}

TEST_F(RescopeBaseTest, TEST_VALID_RESCOPE_DEL) {
    keymaster_key_param_t params1[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_int(KM_TAG_RESCOPING_ADD, KM_TAG_SINGLE_USE_PER_BOOT),
        keymaster_param_int(KM_TAG_RESCOPING_ADD, KM_TAG_USAGE_EXPIRE_DATETIME),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_USER_ID, 1),
        keymaster_param_int(KM_TAG_RESCOPING_DEL, KM_TAG_USER_ID),
    };

    keymaster_key_param_t params2[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 6);
    AuthorizationSet auth_set2(params2, 2);

    ASSERT_EQ(KM_ERROR_OK, kmen.AuthorizeRescope(1, &auth_set1, &auth_set2, 1));
}

TEST_F(RescopeBaseTest, TEST_VALID_RESCOPE_ADD_DEL) {
    keymaster_key_param_t params1[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_USER_ID, 1),

        keymaster_param_int(KM_TAG_RESCOPING_ADD, KM_TAG_SINGLE_USE_PER_BOOT),
        keymaster_param_int(KM_TAG_RESCOPING_ADD, KM_TAG_USAGE_EXPIRE_DATETIME),
        keymaster_param_int(KM_TAG_RESCOPING_DEL, KM_TAG_USER_ID),
    };

    keymaster_key_param_t params2[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_bool(KM_TAG_SINGLE_USE_PER_BOOT),
        keymaster_param_date(KM_TAG_USAGE_EXPIRE_DATETIME, 128),
    };

    keymaster_key_param_t params3[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_bool(KM_TAG_SINGLE_USE_PER_BOOT),
        keymaster_param_int(KM_TAG_USER_ID, 1),
        keymaster_param_date(KM_TAG_USAGE_EXPIRE_DATETIME, 128),
    };

    keymaster_key_param_t params4[] = {
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 6);
    AuthorizationSet auth_set2(params2, 4);
    AuthorizationSet auth_set3(params3, 5);
    AuthorizationSet auth_set4(params4, 2);

    ASSERT_EQ(KM_ERROR_OK, kmen.AuthorizeRescope(1, &auth_set1, &auth_set2, 1));
    ASSERT_EQ(KM_ERROR_OK, kmen.AuthorizeRescope(1, &auth_set1, &auth_set3, 1));
    ASSERT_EQ(KM_ERROR_OK, kmen.AuthorizeRescope(1, &auth_set1, &auth_set4, 1));
}

TEST_F(RescopeBaseTest, TEST_INVALID_RESCOPE_ADD) {
    keymaster_key_param_t params1[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_int(KM_TAG_RESCOPING_ADD, KM_TAG_USAGE_EXPIRE_DATETIME),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_USER_ID, 1),
        keymaster_param_int(KM_TAG_RESCOPING_DEL, KM_TAG_USER_ID),
    };

    keymaster_key_param_t params2[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_USER_ID, 1), keymaster_param_bool(KM_TAG_SINGLE_USE_PER_BOOT),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 6);
    AuthorizationSet auth_set2(params2, 4);

    ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kmen.AuthorizeRescope(1, &auth_set1, &auth_set2, 1));
}

TEST_F(RescopeBaseTest, TEST_INVALID_RESCOPE_DEL) {
    keymaster_key_param_t params1[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_int(KM_TAG_RESCOPING_ADD, KM_TAG_USAGE_EXPIRE_DATETIME),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_RESCOPING_DEL, KM_TAG_PURPOSE),
        keymaster_param_int(KM_TAG_USER_ID, 1),
    };

    keymaster_key_param_t params2[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 5);
    AuthorizationSet auth_set2(params2, 2);

    ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kmen.AuthorizeRescope(1, &auth_set1, &auth_set2, 1));
}

TEST_F(RescopeBaseTest, TEST_INVALID_RESCOPE_ADD_DEL) {
    keymaster_key_param_t params1[] = {
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_USER_ID, 1),
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_date(KM_TAG_ORIGINATION_EXPIRE_DATETIME, past_time),
        keymaster_param_int(KM_TAG_RESCOPING_ADD, KM_TAG_ORIGINATION_EXPIRE_DATETIME),
    };

    keymaster_key_param_t params2[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_bool(KM_TAG_SINGLE_USE_PER_BOOT),
        keymaster_param_date(KM_TAG_USAGE_EXPIRE_DATETIME, 128),
    };

    keymaster_key_param_t params3[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_bool(KM_TAG_SINGLE_USE_PER_BOOT), keymaster_param_int(KM_TAG_USER_ID, 2),
        keymaster_param_date(KM_TAG_USAGE_EXPIRE_DATETIME, 128),
    };

    keymaster_key_param_t params4[] = {
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_USER_ID, 2),
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
    };

    keymaster_key_param_t params5[] = {
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_USER_ID, 1),
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_date(KM_TAG_ORIGINATION_EXPIRE_DATETIME, future_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 5);
    AuthorizationSet auth_set2(params2, 3);
    AuthorizationSet auth_set3(params3, 4);
    AuthorizationSet auth_set4(params4, 3);
    AuthorizationSet auth_set5(params5, 4);

    ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kmen.AuthorizeRescope(1, &auth_set1, &auth_set2, 1));
    ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kmen.AuthorizeRescope(1, &auth_set1, &auth_set3, 1));
    ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kmen.AuthorizeRescope(1, &auth_set1, &auth_set4, 1));
    ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kmen.AuthorizeRescope(1, &auth_set1, &auth_set5, 1));
}

TEST_F(ComparisonBaseTest, TEST_BOOLEAN_COMPARISON) {
    keymaster_tag_t tag = KM_TAG_SINGLE_USE_PER_BOOT;
    keymaster_key_param_t b1 = keymaster_param_bool(tag);
    keymaster_key_param_t b2 = keymaster_param_bool(tag);

    ASSERT_TRUE(KeymasterEnforcement::km_param_compare(b1, b2));
}

TEST_F(ComparisonBaseTest, TEST_VALID_LONG_INTEGER_COMPARISON) {
    uint64_t i1 = 0xfffff;
    uint64_t i2 = 0xfffff;
    uint64_t i3 = 0xfff3f;
    uint64_t i4 = 0xfff3f;

    keymaster_tag_t tag = KM_TAG_RSA_PUBLIC_EXPONENT;
    keymaster_key_param_t param1 = keymaster_param_long(tag, i1);
    keymaster_key_param_t param2 = keymaster_param_long(tag, i2);
    keymaster_key_param_t param3 = keymaster_param_long(tag, i3);
    keymaster_key_param_t param4 = keymaster_param_long(tag, i4);

    ASSERT_TRUE(KeymasterEnforcement::km_param_compare(param4, param3));
    ASSERT_TRUE(KeymasterEnforcement::km_param_compare(param1, param2));
}

TEST_F(ComparisonBaseTest, TEST_INVALID_LONG_INTEGER_COMPARISON) {
    uint64_t i1 = 0xfffff;
    uint64_t i2 = 0xfff2f;
    uint64_t i3 = 0xfff3f;

    keymaster_tag_t tag = KM_TAG_RSA_PUBLIC_EXPONENT;
    keymaster_key_param_t param1 = keymaster_param_long(tag, i1);
    keymaster_key_param_t param2 = keymaster_param_long(tag, i2);
    keymaster_key_param_t param3 = keymaster_param_long(tag, i3);

    ASSERT_FALSE(KeymasterEnforcement::km_param_compare(param1, param2));
    ASSERT_FALSE(KeymasterEnforcement::km_param_compare(param1, param3));
    ASSERT_FALSE(KeymasterEnforcement::km_param_compare(param2, param3));
}

TEST_F(ComparisonBaseTest, TEST_INVALID_ENUM_COMPARISON) {
    keymaster_tag_t tag1 = KM_TAG_ALGORITHM;
    keymaster_tag_t tag2 = KM_TAG_PADDING;

    keymaster_key_param_t param1 = keymaster_param_enum(tag1, 1);
    keymaster_key_param_t param2 = keymaster_param_enum(tag2, 1);
    keymaster_key_param_t param3 = keymaster_param_enum(tag1, 6);

    ASSERT_FALSE(KeymasterEnforcement::km_param_compare(param1, param2));
    ASSERT_FALSE(KeymasterEnforcement::km_param_compare(param1, param3));
    ASSERT_FALSE(KeymasterEnforcement::km_param_compare(param2, param3));
}

TEST_F(ComparisonBaseTest, TEST_VALID_ENUM_COMPARISON) {
    keymaster_tag_t tag1 = KM_TAG_ALGORITHM;
    keymaster_tag_t tag2 = KM_TAG_PADDING;

    keymaster_key_param_t param1 = keymaster_param_enum(tag1, 5);
    keymaster_key_param_t param2 = keymaster_param_enum(tag1, 5);

    keymaster_key_param_t param3 = keymaster_param_enum(tag2, 9);
    keymaster_key_param_t param4 = keymaster_param_enum(tag2, 9);

    ASSERT_TRUE(KeymasterEnforcement::km_param_compare(param3, param4));
    ASSERT_TRUE(KeymasterEnforcement::km_param_compare(param1, param2));
}

TEST_F(ComparisonBaseTest, TEST_INVALID_INT_COMPARISON) {
    keymaster_tag_t tag1 = KM_TAG_MAC_LENGTH;
    keymaster_tag_t tag2 = KM_TAG_CHUNK_LENGTH;

    keymaster_key_param_t param1 = keymaster_param_int(tag1, 5);
    keymaster_key_param_t param2 = keymaster_param_int(tag1, 6);
    keymaster_key_param_t param3 = keymaster_param_int(tag2, 3);

    ASSERT_FALSE(KeymasterEnforcement::km_param_compare(param1, param2));
    ASSERT_FALSE(KeymasterEnforcement::km_param_compare(param1, param3));
    ASSERT_FALSE(KeymasterEnforcement::km_param_compare(param2, param3));
}

TEST_F(ComparisonBaseTest, TEST_VALID_INT_COMPARISON) {
    keymaster_tag_t tag1 = KM_TAG_MAC_LENGTH;
    keymaster_tag_t tag2 = KM_TAG_PADDING;

    keymaster_key_param_t param1 = keymaster_param_int(tag1, 9);
    keymaster_key_param_t param2 = keymaster_param_int(tag1, 9);

    keymaster_key_param_t param3 = keymaster_param_int(tag2, 7);
    keymaster_key_param_t param4 = keymaster_param_int(tag2, 7);

    ASSERT_TRUE(KeymasterEnforcement::km_param_compare(param1, param2));
    ASSERT_TRUE(KeymasterEnforcement::km_param_compare(param3, param4));
}

TEST_F(ComparisonBaseTest, TEST_NULL_BYTES_COMPARISON) {
    keymaster_tag_t tag1 = KM_TAG_APPLICATION_ID;
    const uint8_t* val1 = reinterpret_cast<const uint8_t*>("");
    const uint8_t* val2 = NULL;
    const uint8_t* val3 = reinterpret_cast<const uint8_t*>("");

    keymaster_key_param_t param1 = keymaster_param_blob(tag1, val1, 0);
    keymaster_key_param_t param2 = keymaster_param_blob(tag1, val2, 0);
    keymaster_key_param_t param3 = keymaster_param_blob(tag1, val3, 0);

    ASSERT_TRUE(KeymasterEnforcement::km_param_compare(param1, param2));
    ASSERT_TRUE(KeymasterEnforcement::km_param_compare(param1, param3));
    ASSERT_TRUE(KeymasterEnforcement::km_param_compare(param2, param3));
}

TEST_F(ComparisonBaseTest, TEST_NON_NULL_BYTES_COMPARISON) {
    keymaster_tag_t tag1 = KM_TAG_APPLICATION_ID;
    const uint8_t* val1 = reinterpret_cast<const uint8_t*>("Hello");
    const uint8_t* val2 = reinterpret_cast<const uint8_t*>("Hello");

    keymaster_key_param_t param1 = keymaster_param_blob(tag1, val1, 5);
    keymaster_key_param_t param2 = keymaster_param_blob(tag1, val2, 5);

    ASSERT_TRUE(KeymasterEnforcement::km_param_compare(param1, param2));
}

TEST_F(ComparisonBaseTest, TEST_INVALID_BYTES_COMPARISON) {
    keymaster_tag_t tag1 = KM_TAG_APPLICATION_ID;
    const uint8_t* val1 = reinterpret_cast<const uint8_t*>("byte1");
    const uint8_t* val2 = reinterpret_cast<const uint8_t*>("Hello");
    const uint8_t* val3 = reinterpret_cast<const uint8_t*>("Hello World");

    keymaster_key_param_t param1 = keymaster_param_blob(tag1, val1, 5);
    keymaster_key_param_t param2 = keymaster_param_blob(tag1, val2, 5);
    keymaster_key_param_t param3 = keymaster_param_blob(tag1, val3, 11);

    ASSERT_FALSE(KeymasterEnforcement::km_param_compare(param1, param2));
    ASSERT_FALSE(KeymasterEnforcement::km_param_compare(param1, param3));
    ASSERT_FALSE(KeymasterEnforcement::km_param_compare(param2, param3));
}

TEST_F(KeymasterBaseTest, TEST_USER_ID) {
    uint32_t valid_user_id = 25;
    uint32_t invalid_user_id1 = 37;
    uint32_t invalid_user_id2 = 50;
    uint32_t appId1 = 51;
    uint32_t appId2 = 52;

    uint32_t validuid1 = valid_user_id * KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE +
                         (appId1 % KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE);
    uint32_t validuid2 = valid_user_id * KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE +
                         (appId1 % KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE);

    uint32_t invaliduid1 = invalid_user_id1 * KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE +
                           (appId1 % KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE);
    uint32_t invaliduid2 = invalid_user_id1 * KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE +
                           (appId2 % KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE);
    uint32_t invaliduid3 = invalid_user_id2 * KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE +
                           (appId1 % KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE);
    uint32_t invaliduid4 = invalid_user_id2 * KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE +
                           (appId2 % KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE);

    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_int(KM_TAG_USER_ID, valid_user_id),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 2);

    keymaster_error_t valid_kmer1 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, validuid1, def_app_id);
    keymaster_error_t valid_kmer2 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, validuid2, def_app_id);

    keymaster_error_t invalid_kmer1 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, invaliduid1, def_app_id);
    keymaster_error_t invalid_kmer2 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, invaliduid2, def_app_id);
    keymaster_error_t invalid_kmer3 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, invaliduid3, def_app_id);
    keymaster_error_t invalid_kmer4 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, invaliduid4, def_app_id);

    ASSERT_EQ(KM_ERROR_OK, valid_kmer1);
    ASSERT_EQ(KM_ERROR_OK, valid_kmer2);

    ASSERT_EQ(KM_ERROR_INVALID_USER_ID, invalid_kmer1);
    ASSERT_EQ(KM_ERROR_INVALID_USER_ID, invalid_kmer2);
    ASSERT_EQ(KM_ERROR_INVALID_USER_ID, invalid_kmer3);
    ASSERT_EQ(KM_ERROR_INVALID_USER_ID, invalid_kmer4);
}

TEST_F(KeymasterBaseTest, TEST_APP_ID) {
    const uint32_t validBlobLength = 21;
    const char validBlobVal1[] = "com.google.valid_app1";
    const char validBlobVal2[] = "com.google.valid_app2";

    const uint8_t* validId1 = reinterpret_cast<const uint8_t*>(validBlobVal1);
    const uint8_t* validId2 = reinterpret_cast<const uint8_t*>(validBlobVal2);

    keymaster_blob_t validBlob1;
    validBlob1.data_length = validBlobLength;
    validBlob1.data = validId1;

    keymaster_blob_t validBlob2;
    validBlob2.data_length = validBlobLength;
    validBlob2.data = validId2;

    const uint32_t invalidBlobLength = 32;
    const char invalidBlobVal1[] = "com.google.invalid_app1";
    const char invalidBlobVal2[] = "com.google.invalid_app2";

    const uint8_t* invalidId1 = reinterpret_cast<const uint8_t*>(invalidBlobVal1);
    const uint8_t* invalidId2 = reinterpret_cast<const uint8_t*>(invalidBlobVal2);

    keymaster_blob_t invalidBlob1;
    invalidBlob1.data_length = invalidBlobLength;
    invalidBlob1.data = invalidId1;

    keymaster_blob_t invalidBlob2;
    invalidBlob2.data_length = invalidBlobLength;
    invalidBlob2.data = invalidId2;

    keymaster_key_param_t params1[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_blob(KM_TAG_APPLICATION_ID, validId1, validBlobLength),
    };

    keymaster_key_param_t params2[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_blob(KM_TAG_APPLICATION_ID, validId2, validBlobLength),
    };

    keymaster_key_param_t params3[] = {
        keymaster_param_bool(KM_TAG_ALL_APPLICATIONS),
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_blob(KM_TAG_APPLICATION_ID, validId2, validBlobLength),
    };

    keymaster_key_param_t params4[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_bool(KM_TAG_ALL_APPLICATIONS),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 2);
    AuthorizationSet auth_set2(params2, 2);
    AuthorizationSet auth_set3(params3, 3);
    AuthorizationSet auth_set4(params4, 2);

    keymaster_error_t valid_kmer1 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set1, uid, validBlob1);
    keymaster_error_t valid_kmer2 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set2, uid, validBlob2);
    keymaster_error_t valid_kmer3 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set4, uid, validBlob2);

    keymaster_error_t invalid_kmer1 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set1, uid, invalidBlob1);
    keymaster_error_t invalid_kmer2 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set1, uid, invalidBlob2);
    keymaster_error_t invalid_kmer3 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set2, uid, invalidBlob1);
    keymaster_error_t invalid_kmer4 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set2, uid, invalidBlob2);
    keymaster_error_t invalid_kmer5 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set3, uid, validBlob2);

    ASSERT_EQ(KM_ERROR_OK, valid_kmer1);
    ASSERT_EQ(KM_ERROR_OK, valid_kmer2);
    ASSERT_EQ(KM_ERROR_OK, valid_kmer3);

    ASSERT_NE(KM_ERROR_OK, invalid_kmer1);
    ASSERT_NE(KM_ERROR_OK, invalid_kmer2);
    ASSERT_NE(KM_ERROR_OK, invalid_kmer3);
    ASSERT_NE(KM_ERROR_OK, invalid_kmer4);
    ASSERT_NE(KM_ERROR_OK, invalid_kmer5);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_AUTH_TIMEOUT) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_int(KM_TAG_AUTH_TIMEOUT, 2),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 4);
    kmen.update_user_authentication_time();

    keymaster_error_t kmer =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, uid, def_app_id);
    ASSERT_EQ(KM_ERROR_KEY_USER_NOT_AUTHENTICATED, kmer);
}

TEST_F(KeymasterBaseTest, TEST_VALID_AUTH_TIMEOUT) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_int(KM_TAG_AUTH_TIMEOUT, 2),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 4);
    kmen.update_user_authentication_time();

    sleep(3);
    keymaster_error_t kmer =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, uid, def_app_id);
    ASSERT_EQ(KM_ERROR_OK, kmer);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_RESCOPE_AUTH_TIMEOUT) {
    keymaster_key_param_t params1[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_int(KM_TAG_RESCOPE_AUTH_TIMEOUT, 2),
    };

    keymaster_key_param_t params2[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_RESCOPE_AUTH_TIMEOUT, 2),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 4);
    AuthorizationSet auth_set2(params2, 4);

    kmen.update_user_authentication_time();
    keymaster_error_t kmer = kmen.AuthorizeRescope(key_id, &auth_set1, &auth_set2, uid);
    ASSERT_EQ(KM_ERROR_KEY_USER_NOT_AUTHENTICATED, kmer);
}

TEST_F(RescopeBaseTest, TEST_VALID_RESCOPE_AUTH_TIMEOUT) {
    keymaster_key_param_t params1[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_int(KM_TAG_RESCOPE_AUTH_TIMEOUT, 2),
    };

    keymaster_key_param_t params2[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_RESCOPE_AUTH_TIMEOUT, 2),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 4);
    AuthorizationSet auth_set2(params2, 4);

    kmen.update_user_authentication_time();
    sleep(3);
    keymaster_error_t kmer = kmen.AuthorizeRescope(key_id, &auth_set1, &auth_set2, uid);
    ASSERT_EQ(KM_ERROR_OK, kmer);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_PURPOSE) {
    keymaster_purpose_t invalidPurpose1 = static_cast<keymaster_purpose_t>(-1);
    keymaster_purpose_t invalidPurpose2 = static_cast<keymaster_purpose_t>(4);

    keymaster_key_param_t params1[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, invalidPurpose1),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
    };

    keymaster_key_param_t params2[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, invalidPurpose2),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 3);
    AuthorizationSet auth_set2(params2, 3);

    keymaster_error_t kmer1 =
        kmen.AuthorizeOperation(invalidPurpose1, key_id, &auth_set1, uid, def_app_id);
    keymaster_error_t kmer2 =
        kmen.AuthorizeOperation(invalidPurpose2, key_id, &auth_set2, uid, def_app_id);
    keymaster_error_t kmer3 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set2, uid, def_app_id);

    ASSERT_EQ(KM_ERROR_UNSUPPORTED_PURPOSE, kmer1);
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_PURPOSE, kmer2);
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_PURPOSE, kmer3);
}

TEST_F(KeymasterBaseTest, TEST_INCOMPATIBLE_PURPOSE) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_VERIFY),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
    };
    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 4);

    keymaster_error_t kmer_invalid1 =
        kmen.AuthorizeOperation(KM_PURPOSE_ENCRYPT, key_id, &auth_set, uid, def_app_id);
    keymaster_error_t kmer_invalid2 =
        kmen.AuthorizeOperation(KM_PURPOSE_DECRYPT, key_id, &auth_set, uid, def_app_id);

    keymaster_error_t kmer_valid1 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, &auth_set, uid, def_app_id);
    keymaster_error_t kmer_valid2 =
        kmen.AuthorizeOperation(KM_PURPOSE_VERIFY, key_id, &auth_set, uid, def_app_id);

    ASSERT_EQ(KM_ERROR_OK, kmer_valid1);
    ASSERT_EQ(KM_ERROR_OK, kmer_valid2);
    ASSERT_EQ(KM_ERROR_INCOMPATIBLE_PURPOSE, kmer_invalid1);
    ASSERT_EQ(KM_ERROR_INCOMPATIBLE_PURPOSE, kmer_invalid2);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_TAG_PAIRS) {
    const uint8_t* app_id = reinterpret_cast<const uint8_t*>("com.app");
    const size_t app_size = 7;
    keymaster_key_param_t params1[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_VERIFY),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_bool(KM_TAG_ALL_USERS),
        keymaster_param_int(KM_TAG_USER_ID, 1),
    };

    keymaster_key_param_t params2[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_VERIFY),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_bool(KM_TAG_NO_AUTH_REQUIRED),
        keymaster_param_int(KM_TAG_USER_AUTH_ID, 1),
    };

    keymaster_key_param_t params3[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_VERIFY),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_bool(KM_TAG_ALL_APPLICATIONS),
        keymaster_param_blob(KM_TAG_APPLICATION_ID, app_id, app_size),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 6);
    AuthorizationSet auth_set2(params2, 6);
    AuthorizationSet auth_set3(params2, 6);

    ASSERT_EQ(KM_ERROR_INVALID_TAG,
              kmen.AuthorizeOperation(KM_PURPOSE_VERIFY, key_id, &auth_set1, uid, def_app_id));
    ASSERT_EQ(KM_ERROR_INVALID_TAG,
              kmen.AuthorizeOperation(KM_PURPOSE_VERIFY, key_id, &auth_set2, uid, def_app_id));
    ASSERT_EQ(KM_ERROR_INVALID_TAG,
              kmen.AuthorizeOperation(KM_PURPOSE_VERIFY, key_id, &auth_set3, uid, def_app_id));
}

}; /* namespace test */
}; /* namespace keymaster */
