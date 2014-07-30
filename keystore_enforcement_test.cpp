#include <gtest/gtest.h>

#include <errno.h>
#include "authorization_set.h"
#include <hardware/keymaster.h>
#include "keystore_enforcement.h"
#include <stdio.h>
#include <time.h>

using namespace keymaster;

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    return result;
}

namespace test {

class KeystoreBaseTest : public ::testing::Test {
    protected:
        KeystoreBaseTest() {
            past_time = 0;

            time_t t = time(NULL);
            future_tm = localtime(&t);
            future_tm->tm_year += 1;
            future_time = mktime(future_tm);
        }
        virtual ~KeystoreBaseTest() {
        }

        tm past_tm;
        tm *future_tm;
        time_t past_time;
        time_t future_time;
        static const km_id_t key_id = 0xa;
        static const uid_t app_id = 0xf;
};

TEST_F(KeystoreBaseTest, TEST_VALID_KEY_PERIOD_NO_TAGS) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
    };
    AuthorizationSet singleAuthSet(params, 1);
    KeystoreEnforcement kse;

    keymaster_error_t kme = kse.authorizeOperation(key_id, &singleAuthSet, app_id);
    ASSERT_EQ(KM_ERROR_OK, kme);
}

TEST_F(KeystoreBaseTest, TEST_INVALID_ACTIVE_TIME) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, future_time),
    };

    KeystoreEnforcement kse;
    AuthorizationSet authSet(params, 3);

    keymaster_error_t kme_invalid_time = kse.authorizeOperation(key_id, &authSet, app_id);
    ASSERT_EQ(KM_ERROR_KEY_NOT_YET_VALID, kme_invalid_time);
}

TEST_F(KeystoreBaseTest, TEST_VALID_ACTIVE_TIME) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
    };

    KeystoreEnforcement kse;
    AuthorizationSet authSet(params, 3);

    keymaster_error_t kme_valid_time = kse.authorizeOperation(key_id, &authSet, app_id);
    ASSERT_EQ(KM_ERROR_OK, kme_valid_time);
}

TEST_F(KeystoreBaseTest, TEST_INVALID_ORIGINATION_EXPIRE_TIME) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_date(KM_TAG_ORIGINATION_EXPIRE_DATETIME,
                past_time),
    };

    KeystoreEnforcement kse;
    AuthorizationSet authSet(params, 4);

    keymaster_error_t kme_invalid_origination =
        kse.authorizeOperation(key_id, &authSet, app_id);
    ASSERT_EQ(KM_ERROR_KEY_EXPIRED, kme_invalid_origination);
}

TEST_F(KeystoreBaseTest, TEST_VALID_ORIGINATION_EXPIRE_TIME) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_date(KM_TAG_ORIGINATION_EXPIRE_DATETIME,
                future_time),
    };

    KeystoreEnforcement kse;
    AuthorizationSet authSet(params, 4);

    keymaster_error_t kme_valid_origination =
        kse.authorizeOperation(key_id, &authSet, app_id);
    ASSERT_EQ(KM_ERROR_OK, kme_valid_origination);
}

TEST_F(KeystoreBaseTest, TEST_INVALID_USAGE_EXPIRE_TIME) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_VERIFY),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_date(KM_TAG_USAGE_EXPIRE_DATETIME,
                past_time),
    };

    KeystoreEnforcement kse;
    AuthorizationSet authSet(params, 4);

    keymaster_error_t kme_invalid_origination =
        kse.authorizeOperation(key_id, &authSet, app_id);
    ASSERT_EQ(KM_ERROR_KEY_EXPIRED, kme_invalid_origination);
}

TEST_F(KeystoreBaseTest, TEST_VALID_USAGE_EXPIRE_TIME) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_VERIFY),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_date(KM_TAG_USAGE_EXPIRE_DATETIME,
                future_time),
    };

    KeystoreEnforcement kse;
    AuthorizationSet authSet(params, 4);

    keymaster_error_t kme_valid_usage =
        kse.authorizeOperation(key_id, &authSet, app_id);
    ASSERT_EQ(KM_ERROR_OK, kme_valid_usage);
}

TEST_F(KeystoreBaseTest, TEST_VALID_SINGLE_USE_ACCESSES) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
    };

    KeystoreEnforcement kse;
    AuthorizationSet authSet(params, 3);

    keymaster_error_t kme1 = kse.authorizeOperation(key_id, &authSet, app_id);
    keymaster_error_t kme2 = kse.authorizeOperation(key_id, &authSet, app_id);

    ASSERT_EQ(KM_ERROR_OK, kme1);
    ASSERT_EQ(KM_ERROR_OK, kme2);
}

TEST_F(KeystoreBaseTest, TEST_INVALID_SINGLE_USE_ACCESSES) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_bool(KM_TAG_SINGLE_USE_PER_BOOT),
    };

    KeystoreEnforcement kse;
    AuthorizationSet authSet(params, 4);

    keymaster_error_t kme1 = kse.authorizeOperation(key_id, &authSet, app_id);
    keymaster_error_t kme2 = kse.authorizeOperation(key_id, &authSet, app_id);

    ASSERT_EQ(KM_ERROR_OK, kme1);
    ASSERT_EQ(KM_ERROR_TOO_MANY_OPERATIONS, kme2);
}

TEST_F(KeystoreBaseTest, TEST_INVALID_TIME_BETWEEN_OPS) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_int(KM_TAG_MIN_SECONDS_BETWEEN_OPS, 10),
    };

    KeystoreEnforcement kse;
    AuthorizationSet authSet(params, 4);

    keymaster_error_t kme1 = kse.authorizeOperation(key_id, &authSet, app_id);
    keymaster_error_t kme2 = kse.authorizeOperation(key_id, &authSet, app_id);

    ASSERT_EQ(KM_ERROR_OK, kme1);
    sleep(2);
    ASSERT_EQ(KM_ERROR_TOO_MANY_OPERATIONS, kme2);
}

TEST_F(KeystoreBaseTest, TEST_VALID_TIME_BETWEEN_OPS) {
    keymaster_key_param_t params[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_date(KM_TAG_ACTIVE_DATETIME, past_time),
        keymaster_param_int(KM_TAG_MIN_SECONDS_BETWEEN_OPS, 2),
    };

    KeystoreEnforcement kse;
    AuthorizationSet authSet(params, 4);

    keymaster_error_t kme1 = kse.authorizeOperation(key_id, &authSet, app_id);
    sleep(3);
    keymaster_error_t kme2 = kse.authorizeOperation(key_id, &authSet, app_id);

    ASSERT_EQ(KM_ERROR_OK, kme1);
    ASSERT_EQ(KM_ERROR_OK, kme2);
}

TEST_F(KeystoreBaseTest, TEST_RESCOPE_DEL_SUB) {
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
        keymaster_param_int(KM_TAG_USER_ID, 1),
    };   

    KeystoreEnforcement kse;
    AuthorizationSet authSet(params1, 6);
    AuthorizationSet authSet2(params2, 3);

    ASSERT_TRUE(kse.validRescopeDel(&authSet, KM_TAG_USER_ID));
    ASSERT_FALSE(kse.validRescopeDel(&authSet, KM_TAG_ALL_USERS));
    ASSERT_FALSE(kse.validRescopeDel(&authSet2, KM_TAG_PURPOSE));
    ASSERT_FALSE(kse.validRescopeDel(&authSet2, KM_TAG_USER_ID));
}

TEST_F(KeystoreBaseTest, TEST_RESCOPE_ADD_SUB) {
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
        keymaster_param_int(KM_TAG_USER_ID, 1),
    };
    
    KeystoreEnforcement kse;
    AuthorizationSet authSet(params1, 6);
    AuthorizationSet authSet2(params2, 3);

    ASSERT_TRUE(kse.validRescopeAdd(&authSet, KM_TAG_SINGLE_USE_PER_BOOT));
    ASSERT_TRUE(kse.validRescopeAdd(&authSet, KM_TAG_USAGE_EXPIRE_DATETIME));
    ASSERT_FALSE(kse.validRescopeAdd(&authSet, KM_TAG_USER_ID));

    ASSERT_FALSE(kse.validRescopeAdd(&authSet2, KM_TAG_RESCOPE_AUTH_TIMEOUT));
    ASSERT_FALSE(kse.validRescopeAdd(&authSet2, KM_TAG_SINGLE_USE_PER_BOOT));
}

TEST_F(KeystoreBaseTest, TEST_NO_RESCOPES) {
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

    KeystoreEnforcement kse;
    AuthorizationSet authSet1(params1, 3);
    AuthorizationSet authSet2(params2, 3);

    ASSERT_EQ(KM_ERROR_OK, kse.authorizeRescope(1, &authSet1, &authSet2, 1));
}

TEST_F(KeystoreBaseTest, TEST_VALID_RESCOPE_ADD) {
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
        keymaster_param_int(KM_TAG_USER_ID, 1),
        keymaster_param_bool(KM_TAG_SINGLE_USE_PER_BOOT),
    };

    keymaster_key_param_t params3[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_USER_ID, 1),
        keymaster_param_date(KM_TAG_USAGE_EXPIRE_DATETIME, 25),
    };

    KeystoreEnforcement kse;
    AuthorizationSet authSet1(params1, 6);
    AuthorizationSet authSet2(params2, 4);
    AuthorizationSet authSet3(params3, 4);

    ASSERT_EQ(KM_ERROR_OK, kse.authorizeRescope(1, &authSet1, &authSet2, 1));
    ASSERT_EQ(KM_ERROR_OK, kse.authorizeRescope(1, &authSet1, &authSet3, 1));
}

TEST_F(KeystoreBaseTest, TEST_VALID_RESCOPE_DEL) {
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

    KeystoreEnforcement kse;
    AuthorizationSet authSet1(params1, 6);
    AuthorizationSet authSet2(params2, 2);

    ASSERT_EQ(KM_ERROR_OK, kse.authorizeRescope(1, &authSet1, &authSet2, 1));
}

TEST_F(KeystoreBaseTest, TEST_VALID_RESCOPE_ADD_DEL) {
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

    KeystoreEnforcement kse;
    AuthorizationSet authSet1(params1, 6);
    AuthorizationSet authSet2(params2, 4);
    AuthorizationSet authSet3(params3, 5);
    AuthorizationSet authSet4(params4, 2);

    ASSERT_EQ(KM_ERROR_OK, kse.authorizeRescope(1, &authSet1, &authSet2, 1));
    ASSERT_EQ(KM_ERROR_OK, kse.authorizeRescope(1, &authSet1, &authSet3, 1));
    ASSERT_EQ(KM_ERROR_OK, kse.authorizeRescope(1, &authSet1, &authSet4, 1));
}

TEST_F(KeystoreBaseTest, TEST_INVALID_RESCOPE_ADD) {
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
        keymaster_param_int(KM_TAG_USER_ID, 1),
        keymaster_param_bool(KM_TAG_SINGLE_USE_PER_BOOT),
    };

    KeystoreEnforcement kse;
    AuthorizationSet authSet1(params1, 6);
    AuthorizationSet authSet2(params2, 4);

    ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kse.authorizeRescope(1, &authSet1, &authSet2, 1));
}

TEST_F(KeystoreBaseTest, TEST_INVALID_RESCOPE_DEL) {
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

   KeystoreEnforcement kse;
   AuthorizationSet authSet1(params1, 5);
   AuthorizationSet authSet2(params2, 2);

   ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kse.authorizeRescope(1, &authSet1, &authSet2, 1));
}

TEST_F(KeystoreBaseTest, TEST_INVALID_RESCOPE_ADD_DEL) {
    keymaster_key_param_t params1[] = {
        keymaster_param_enum(KM_TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_int(KM_TAG_USER_ID, 1),
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
    };

    keymaster_key_param_t params2[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_bool(KM_TAG_SINGLE_USE_PER_BOOT),
        keymaster_param_date(KM_TAG_USAGE_EXPIRE_DATETIME, 128),
    };

    keymaster_key_param_t params3[] = {
        keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN),
        keymaster_param_bool(KM_TAG_SINGLE_USE_PER_BOOT),
        keymaster_param_int(KM_TAG_USER_ID, 2),
        keymaster_param_date(KM_TAG_USAGE_EXPIRE_DATETIME, 128),
    };

    KeystoreEnforcement kse;
    AuthorizationSet authSet1(params1, 3);
    AuthorizationSet authSet2(params2, 3);
    AuthorizationSet authSet3(params3, 4);

    ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kse.authorizeRescope(1, &authSet1, &authSet2, 1));
    ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kse.authorizeRescope(1, &authSet1, &authSet3, 1));
}

TEST_F(KeystoreBaseTest, TEST_INVALID_ENUM_COMPARISON) {
    keymaster_tag_t tag1 = KM_TAG_ALGORITHM;
    keymaster_tag_t tag2 = KM_TAG_PADDING;

    keymaster_key_param_t param1 = keymaster_param_enum(tag1, 1);
    keymaster_key_param_t param2 = keymaster_param_enum(tag2, 1);
    keymaster_key_param_t param3 = keymaster_param_enum(tag1, 6);

    ASSERT_FALSE(KeystoreEnforcement::kmParamCompare(param1, param2));
    ASSERT_FALSE(KeystoreEnforcement::kmParamCompare(param1, param3));
    ASSERT_FALSE(KeystoreEnforcement::kmParamCompare(param2, param3));
}

TEST_F(KeystoreBaseTest, TEST_VALID_ENUM_COMPARISON) {
    keymaster_tag_t tag1 = KM_TAG_ALGORITHM;
    keymaster_tag_t tag2 = KM_TAG_PADDING;

    keymaster_key_param_t param1 = keymaster_param_enum(tag1, 5);
    keymaster_key_param_t param2 = keymaster_param_enum(tag1, 5);

    keymaster_key_param_t param3 = keymaster_param_enum(tag2, 9);
    keymaster_key_param_t param4 = keymaster_param_enum(tag2, 9);

    ASSERT_TRUE(KeystoreEnforcement::kmParamCompare(param3, param4));
    ASSERT_TRUE(KeystoreEnforcement::kmParamCompare(param1, param2));
}

TEST_F(KeystoreBaseTest, TEST_INVALID_INT_COMPARISON) {
    keymaster_tag_t tag1 = KM_TAG_MAC_LENGTH;
    keymaster_tag_t tag2 = KM_TAG_CHUNK_LENGTH;

    keymaster_key_param_t param1 = keymaster_param_int(tag1, 5);
    keymaster_key_param_t param2 = keymaster_param_int(tag1, 6);
    keymaster_key_param_t param3 = keymaster_param_int(tag2, 3);

    ASSERT_FALSE(KeystoreEnforcement::kmParamCompare(param1, param2));
    ASSERT_FALSE(KeystoreEnforcement::kmParamCompare(param1, param3));
    ASSERT_FALSE(KeystoreEnforcement::kmParamCompare(param2, param3));
}

TEST_F(KeystoreBaseTest, TEST_VALID_INT_COMPARISON) {
    keymaster_tag_t tag1 = KM_TAG_MAC_LENGTH;
    keymaster_tag_t tag2 = KM_TAG_PADDING;

    keymaster_key_param_t param1 = keymaster_param_int(tag1, 9);
    keymaster_key_param_t param2 = keymaster_param_int(tag1, 9);

    keymaster_key_param_t param3 = keymaster_param_int(tag2, 7);
    keymaster_key_param_t param4 = keymaster_param_int(tag2, 7);

    ASSERT_TRUE(KeystoreEnforcement::kmParamCompare(param1, param2));
    ASSERT_TRUE(KeystoreEnforcement::kmParamCompare(param3, param4));
}

TEST_F(KeystoreBaseTest, TEST_NULL_BYTES_COMPARISON) {
    keymaster_tag_t tag1 = KM_TAG_APPLICATION_ID;
    const uint8_t *val1 = reinterpret_cast<const uint8_t*>("");
    const uint8_t *val2 = NULL;
    const uint8_t *val3 = reinterpret_cast<const uint8_t*>("");

    keymaster_key_param_t param1 = keymaster_param_blob(tag1, val1, 0);
    keymaster_key_param_t param2 = keymaster_param_blob(tag1, val2, 0);
    keymaster_key_param_t param3 = keymaster_param_blob(tag1, val3, 0);

    ASSERT_TRUE(KeystoreEnforcement::kmParamCompare(param1, param2));
    ASSERT_TRUE(KeystoreEnforcement::kmParamCompare(param1, param3));
    ASSERT_TRUE(KeystoreEnforcement::kmParamCompare(param2, param3));
}

TEST_F(KeystoreBaseTest, TEST_NON_NULL_BYTES_COMPARISON) {
    keymaster_tag_t tag1 = KM_TAG_APPLICATION_ID;
    const uint8_t *val1 = reinterpret_cast<const uint8_t*>("Hello");
    const uint8_t *val2 = reinterpret_cast<const uint8_t*>("Hello");

    keymaster_key_param_t param1 = keymaster_param_blob(tag1, val1, 5);
    keymaster_key_param_t param2 = keymaster_param_blob(tag1, val2, 5);

    ASSERT_TRUE(KeystoreEnforcement::kmParamCompare(param1, param2));
}

TEST_F(KeystoreBaseTest, TEST_INVALID_BYTES_COMPARISON) {
    keymaster_tag_t tag1 = KM_TAG_APPLICATION_ID;
    const uint8_t *val1 = reinterpret_cast<const uint8_t*>("byte1");
    const uint8_t *val2 = reinterpret_cast<const uint8_t*>("Hello");
    const uint8_t *val3 = reinterpret_cast<const uint8_t*>("Hello World");

    keymaster_key_param_t param1 = keymaster_param_blob(tag1, val1, 5);
    keymaster_key_param_t param2 = keymaster_param_blob(tag1, val2, 5);
    keymaster_key_param_t param3 = keymaster_param_blob(tag1, val3, 11);

    ASSERT_FALSE(KeystoreEnforcement::kmParamCompare(param1, param2));
    ASSERT_FALSE(KeystoreEnforcement::kmParamCompare(param1, param3));
    ASSERT_FALSE(KeystoreEnforcement::kmParamCompare(param2, param3));
}
}
