/*
 * Copyright (C) 2011 The Android Open Source Project
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

#ifndef ANDROID_HARDWARE_KEYMASTER_H
#define ANDROID_HARDWARE_KEYMASTER_H

#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>

#include <hardware/hardware.h>

__BEGIN_DECLS

/**
 * The id of this module
 */
#define KEYSTORE_HARDWARE_MODULE_ID "keystore"

#define KEYSTORE_KEYMASTER "keymaster"

/**
 * Settings for "module_api_version" and "hal_api_version"
 * fields in the keymaster_module initialization.
 */
#define KEYMASTER_HEADER_VERSION 4

#define KEYMASTER_MODULE_API_VERSION_0_2 HARDWARE_MODULE_API_VERSION(0, 2)
#define KEYMASTER_DEVICE_API_VERSION_0_2                                                           \
    HARDWARE_DEVICE_API_VERSION_2(0, 2, KEYMASTER_HEADER_VERSION)

#define KEYMASTER_MODULE_API_VERSION_0_3 HARDWARE_MODULE_API_VERSION(0, 3)
#define KEYMASTER_DEVICE_API_VERSION_0_3                                                           \
    HARDWARE_DEVICE_API_VERSION_2(0, 3, KEYMASTER_HEADER_VERSION)

#define KEYMASTER_MODULE_API_VERSION_0_4 HARDWARE_MODULE_API_VERSION(0, 4)
#define KEYMASTER_DEVICE_API_VERSION_0_4                                                           \
    HARDWARE_DEVICE_API_VERSION_2(0, 4, KEYMASTER_HEADER_VERSION)

/*!
 * \deprecated Flags for keymaster_device::flags
 *
 * keymaster_device::flags is deprecated and will be removed in the
 * next version of the API in favor of the more detailed information
 * available from TODO:
 */
enum {
    /*
     * Indicates this keymaster implementation does not have hardware that
     * keeps private keys out of user space.
     *
     * This should not be implemented on anything other than the default
     * implementation.
     */
    KEYMASTER_SOFTWARE_ONLY = 1 << 0,

    /*
     * This indicates that the key blobs returned via all the primitives
     * are sufficient to operate on their own without the trusted OS
     * querying userspace to retrieve some other data. Key blobs of
     * this type are normally returned encrypted with a
     * Key Encryption Key (KEK).
     *
     * This is currently used by "vold" to know whether the whole disk
     * encryption secret can be unwrapped without having some external
     * service started up beforehand since the "/data" partition will
     * be unavailable at that point.
     */
    KEYMASTER_BLOBS_ARE_STANDALONE = 1 << 1,

    /*
     * Indicates that the keymaster module supports DSA keys.
     */
    KEYMASTER_SUPPORTS_DSA = 1 << 2,

    /*
     * Indicates that the keymaster module supports EC keys.
     */
    KEYMASTER_SUPPORTS_EC = 1 << 3,
};

struct keystore_module {
    hw_module_t common;
};

/**
 * Asymmetric key pair types.
 */
typedef enum {
    TYPE_RSA = 1,
    TYPE_DSA = 2,
    TYPE_EC = 3,
} keymaster_keypair_t;

/**
 * Authorization tags each have an associated type.  This enumeration facilitates tagging each with
 * a type, by using the high four bits (of an implied 32-bit unsigned enum value) to specify up to
 * 16 data types.  These values are ORed with tag IDs to generate the final tag ID values.
 */
typedef enum {
    KM_ENUM = 0 << 28,
    KM_INT = 1 << 28,
    KM_DATE = 2 << 28,
    KM_BOOL = 3 << 28,
    KM_BIGNUM = 4 << 28,
    KM_BYTES = 5 << 28,
} keymaster_tag_type_t;

typedef enum {
    /*
     * Tags that must be semantically enforced by hardware and software implementations.
     */

    /* Crypto parameters */
    KM_TAG_PURPOSE = KM_ENUM | 0,    /* keymaster_purpose_t. Repeatable. */
    KM_TAG_ALGORITHM = KM_ENUM | 1,  /* keymaster_algorithm_t. */
    KM_TAG_KEY_SIZE = KM_INT | 3,    /* Key size in bits. */
    KM_TAG_BLOCK_MODE = KM_ENUM | 4, /* keymaster_block_mode_t. */
    KM_TAG_DIGEST = KM_ENUM | 5,     /* keymaster_digest_t. */
    KM_TAG_MAC_LENGTH = KM_INT | 6,  /* MAC length in bits. */
    KM_TAG_PADDING = KM_ENUM | 7,    /* keymaster_padding_t. */

    /* Other hardware-enforced. */
    KM_TAG_RESCOPING_ADD = KM_ENUM | 101, /* Tags authorized for addition via rescoping.
                                             Repeatable. */
    KM_TAG_RESCOPING_DEL = KM_ENUM | 102, /* Tags authorized for removal via rescoping.
                                             Repeatable. */

    /* Algorithm-specific. */
    KM_TAG_RSA_PUBLIC_EXPONENT = KM_BIGNUM | 200, /* Defaults to 2^16+1 */
    KM_TAG_DSA_GENERATOR = KM_BIGNUM | 201,
    KM_TAG_DSA_P = KM_BIGNUM | 202,
    KM_TAG_DSA_Q = KM_BIGNUM | 203,
    KM_TAG_DH_P = KM_BIGNUM | 204,
    KM_TAG_DH_G = KM_BIGNUM | 205,
    /* Note there are no EC-specific params.  Field size is defined by KM_TAG_KEY_SIZE, and the
       curve is chosen from NIST recommendations for field size */

    /*
     * Tags that should be semantically enforced by hardware if possible and will otherwise be
     * enforced by software (keystore).
     */

    /* Key validity period */
    KM_TAG_ACTIVE_DATETIME = KM_DATE | 400,         /* Start of validity */
    KM_TAG_PUBKEY_EXPIRE_DATETIME = KM_DATE | 401,  /* Public key expiration */
    KM_TAG_PRIVKEY_EXPIRE_DATETIME = KM_DATE | 402, /* Private/secret key expiration, in epoch
                                                      seconds. */

    /* User authentication */
    KM_TAG_USER_ID = KM_INT | 500,      /* ID of authorized user. Set to KM_ALL_USERS_AUTHORIZED to
                                           allow all users. */
    KM_TAG_USER_AUTH_ID = KM_INT | 501, /* ID of the authenticator to use (e.g. password,
                                           fingerprint, etc.).  Repeatable to support multi-factor
                                           auth.  Set to KM_NO_AUTHENTICATION_REQUIRED if no user
                                           authentication is desired. */
    KM_TAG_AUTH_TIMEOUT = KM_INT | 502, /* Required freshness of user authentication for
                                          private/secret key operations, in seconds.  Public key
                                          operations require no authentication.  If absent,
                                          authentication required for every use. */
    KM_TAG_RESCOPE_AUTH_TIMEOUT = KM_INT | 503, /* Required freshness of user authentication for key
                                                  rescoping operations, in seconds.  Public key
                                                  operations require no authentication.  If absent,
                                                  authentication required for every rescoping. */

    /* Application access control */
    KM_TAG_ALL_APPLICATIONS = KM_BOOL | 600, /* If key is usable by all applications. */
    KM_TAG_APPLICATION_ID = KM_INT | 601,    /* ID of authorized application. Disallowed if
                                                KM_TAG_ALL_APPLICATIONS is present. */

    /*
     * Semantically unenforceable tags, either because they have no specific meaning or because
     * they're informational only.
     */
    KM_TAG_APPLICATION_DATA = KM_BYTES | 700,  /* Data provided by authorized application. */
    KM_TAG_CREATION_DATETIME = KM_DATE | 701,  /* Key creation time */
    KM_TAG_ORIGIN = KM_ENUM | 702,             /* keymaster_key_origin_t. */
    KM_TAG_ROLLBACK_RESISTANT = KM_BOOL | 703, /* Whether key is rollback-resistant. */
    KM_TAG_ROOT_OF_TRUST = KM_BYTES | 704,     /* Root of trust ID.  Empty array means usable by all
                                                 roots. */

    /* Tags used only to provide data to operations */
    KM_TAG_ADDITIONAL_DATA = KM_BYTES | 1000, /* Used to provide additional data for AEAD modes. */
} keymaster_tag_t;

/**
 * Algorithms that may be provided by keymaster implementations.  Those that must be provided by all
 * implementations are tagged as "required".  Note that where the values in this enumeration overlap
 * with the values for the deprecated keymaster_keypair_t, the same algorithm must be
 * specified. This type is new in 0_4 and replaces the deprecated keymaster_keypair_t.
 */
typedef enum {
    /* Asymmetric algorithms. */
    KM_ALGORITHM_RSA = 1, /* required */
    KM_ALGORITHM_DSA = 2,
    KM_ALGORITHM_ECDSA = 3,
    KM_ALGORITHM_DH = 4, /* required */
    KM_ALGORITHM_ECDH = 5,
    KM_ALGORITHM_ECIES = 6,
    /* FIPS Approved Ciphers */
    KM_ALGORITHM_AES = 32, /* required */
    KM_ALGORITHM_3DES = 33,
    KM_ALGORITHM_SKIPJACK = 34,
    /* AES Finalists */
    KM_ALGORITHM_MARS = 48,
    KM_ALGORITHM_RC6 = 49,
    KM_ALGORITHM_SERPENT = 50,
    KM_ALGORITHM_TWOFISH = 51,
    /* Other common block ciphers */
    KM_ALGORITHM_IDEA = 52,
    KM_ALGORITHM_RC5 = 53,
    KM_ALGORITHM_CAST5 = 54,
    KM_ALGORITHM_BLOWFISH = 55,
    /* Common stream ciphers */
    KM_ALGORITHM_RC4 = 64,
    KM_ALGORITHM_CHACHA20 = 65,
    /* MAC algorithms */
    KM_ALGORITHM_HMAC = 128, /* required */
} keymaster_algorithm_t;

/**
 * Symmetric block cipher modes that may be provided by keymaster implementations.  Those that must
 * be provided by all implementations are tagged as "required".  This type is new in 0_4.
 */
typedef enum {
    /* Unauthenticated modes, usable only for encryption/decryption and not generally recommended
     * except for compatibility with existing other protocols. */
    KM_MODE_ECB,     /* required */
    KM_MODE_CBC,     /* required */
    KM_MODE_CBC_CTS, /* recommended */
    KM_MODE_CTR,     /* recommended */
    KM_MODE_OFB,
    KM_MODE_CFB,
    /* Authenticated modes, usable for encryption/decryption and signing/verification.  Recommended
     * over unauthenticated modes for all purposes.  One of KM_MODE_GCM and KM_MODE_OCB is
     * required. */
    KM_MODE_GCM,
    KM_MODE_OCB,
    /* MAC modes -- only for signing/verification */
    KM_MODE_CMAC,
    KM_MODE_POLY1305,
} keymaster_block_mode_t;

/**
 * Padding modes that may be applied to plaintext for encryption operations.  This list includes
 * padding modes for both symmetric and asymmetric algorithms.  Note that implementations should not
 * provide all possible combinations of algorithm and padding, only the
 * cryptographically-appropriate pairs.
 */
typedef enum {
    KM_PAD_RSA_OAEP, /* required */
    KM_PAD_RSA_PSS,  /* required */
    KM_PAD_RSA_PKCS1_1_5_ENCRYPT,
    KM_PAD_RSA_PKCS1_1_5_SIGN,
    KM_PAD_ANSI_X923,
    KM_PAD_ISO_10126,
    KM_PAD_ZERO,  /* required */
    KM_PAD_PKCS7, /* required */
    KM_PAD_ISO_7816_4,
} keymaster_padding_t;

/**
 * Digests that may be provided by keymaster implementations.  Those that must be provided by all
 * implementations are tagged as "required".  Those that have been added since version 0_2 of the
 * API are tagged as "new".
 */
typedef enum {
    KM_DIGEST_NONE,               /* new, required */
    DIGEST_NONE = KM_DIGEST_NONE, /* For 0_2 compatibility */
    KM_DIGEST_MD5,                /* new, for compatibility with old protocols only */
    KM_DIGEST_SHA1,               /* new */
    KM_DIGEST_SHA_2_224,          /* new */
    KM_DIGEST_SHA_2_256,          /* new, required */
    KM_DIGEST_SHA_2_384,          /* new, recommended */
    KM_DIGEST_SHA_2_512,          /* new, recommended */
    KM_DIGEST_SHA_3_256,          /* new */
    KM_DIGEST_SHA_3_384,          /* new */
    KM_DIGEST_SHA_3_512,          /* new */
} keymaster_digest_t;

/**
 * The origin of a key (or pair), i.e. where it was generated.  Origin and can be used together to
 * determine whether a key may have existed outside of secure hardware.  This type is new in 0_4.
 */
typedef enum {
    KM_ORIGIN_HARDWARE, /* Generated in secure hardware */
    KM_ORIGIN_SOFTWARE, /* Generated in non-secure software */
    KM_ORIGIN_IMPORTED, /* Imported, origin unknown */
} keymaster_key_origin_t;

/**
 * Usability requirements of key blobs.  This defines what system functionality must be available
 * for the key to function.  For example, key "blobs" which are actually handles referencing
 * encrypted key material stored in the file system cannot be used until the file system is
 * available, and should have BLOB_REQUIRES_FILE_SYSTEM.  Other requirements entries will be added
 * as needed for implementations.  This type is new in 0_4.
 */
typedef enum {
    KM_BLOB_STANDALONE = 0,
    KM_BLOB_REQUIRES_FILE_SYSTEM = 1,
} keymaster_key_blob_usage_requirements_t;

/**
 * Possible purposes of a key (or pair). This type is new in 0_4.
 */
typedef enum {
    KM_PURPOSE_ENCRYPT,
    KM_PURPOSE_DECRYPT,
    KM_PURPOSE_SIGN,
    KM_PURPOSE_VERIFY,
} keymaster_purpose_t;

typedef struct {
    uint8_t* data;
    size_t data_length;
} keymaster_blob_t;

typedef struct {
    uint32_t tag; /* Value from keymaster_tag_t. */
    union {
        uint32_t enumerated;
        bool boolean;
        uint32_t integer;
        time_t date_time;
        keymaster_blob_t bignum;
        keymaster_blob_t bytes;
    };
} keymaster_key_param_t;

/**
 * Parameters that define a key's characteristic, including authorized modes of usage, access
 * control restrictions and key security characteristics.  The parameters are divided into two
 * categories, those that are enforced by secure hardware, and those that are not.  For a
 * software-only keymaster implementation the enforced array must NULL.  Hardware implementations
 * must enforce everything in the enforced array.
 */
typedef struct {
    keymaster_key_param_t* enforced; /* NULL if enforced_length == 0 */
    size_t enforced_length;
    keymaster_key_param_t* unenforced; /* NULL if unenforced_length == 0 */
    size_t unenforced_length;
} keymaster_key_characteristics_t;

typedef struct {
    uint8_t* key_material;
    size_t key_material_size;
} keymaster_key_blob_t;

/**
 * Formats for key import and export.
 */
typedef enum {
    KM_KEY_FORMAT_X509,   /* for public key export, required */
    KM_KEY_FORMAT_PKCS8,  /* for asymmetric key pair import, required */
    KM_KEY_FORMAT_PKCS12, /* for asymmetric key pair import, not */
} keymaster_key_format_t;

/**
 * The keymaster operation API consists of begin, update, finish and abort. This is the type of the
 * handle used to tie the sequence of calls together.
 */
typedef uint32_t keymaster_operation_handle_t;

typedef enum {
    KM_ERROR_OK = 0,
    KM_ERROR_ROOT_OF_TRUST_ALREADY_SET = -1,
    KM_ERROR_UNSUPPORTED_PURPOSE = -2,
    KM_ERROR_INCOMPATIBLE_PURPOSE = -3,
    KM_ERROR_UNSUPPORTED_ALGORITHM = -4,
    KM_ERROR_INCOMPATIBLE_ALGORITHM = -5,
    KM_ERROR_UNSUPPORTED_KEY_SIZE = -6,
    KM_ERROR_UNSUPPORTED_BLOCK_MODE = -7,
    KM_ERROR_INCOMPATIBLE_BLOCK_MODE = -8,
    KM_ERROR_UNSUPPORTED_TAG_LENGTH = -9,
    KM_ERROR_UNSUPPORTED_PADDING_MODE = -10,
    KM_ERROR_INCOMPATIBLE_PADDING_MODE = -11,
    KM_ERROR_UNSUPPORTED_DIGEST = -12,
    KM_ERROR_INCOMPATIBLE_DIGEST = -13,
    KM_ERROR_INVALID_EXPIRATION_TIME = -14,
    KM_ERROR_INVALID_USER_ID = -15,
    KM_ERROR_INVALID_AUTHORIZATION_TIMEOUT = -16,
    KM_ERROR_UNSUPPORTED_KEY_FORMAT = -17,
    KM_ERROR_INCOMPATIBLE_KEY_FORMAT = -18,
    KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM = -19,   /* For PKCS8 & PKCS12 */
    KM_ERROR_UNSUPPORTED_KEY_VERIFICATION_ALGORITHM = -20, /* For PKCS8 & PKCS12 */
    KM_ERROR_KEY_EXPORT_OPTIONS_INVALID = -22,
    KM_ERROR_DELEGATION_NOT_ALLOWED = -23,
    KM_ERROR_KEY_NOT_YET_VALID = -24,
    KM_ERROR_KEY_EXPIRED = -25,
    KM_ERROR_KEY_USER_NOT_AUTHENTICATED = -26,
    KM_ERROR_OUTPUT_PARAMETER_NULL = -27,
    KM_ERROR_INVALID_OPERATION_HANDLE = -28,
    KM_ERROR_INSUFFICIENT_BUFFER_SPACE = -29,
    KM_ERROR_VERIFICATION_FAILED = -30,
    KM_ERROR_TOO_MANY_OPERATIONS = -31,
    KM_ERROR_UNEXPECTED_NULL_POINTER = -32,
    KM_ERROR_INVALID_KEY_BLOB = -33,
    KM_ERROR_IMPORTED_KEY_NOT_ENCRYPTED = -34,
    KM_ERROR_IMPORTED_KEY_DECRYPTION_FAILED = -35,
    KM_ERROR_IMPORTED_KEY_NOT_SIGNED = -36,
    KM_ERROR_IMPORTED_KEY_VERIFICATION_FAILED = -37,
    KM_ERROR_CLIENT_IV_DISALLOWED = -37,
    KM_ERROR_CLIENT_NONCE_DISALLOWED = -38,

    /* Additional error codes may be added by implementations, but implementers should coordinate
     * with Google to avoid code collision. */
    KM_ERROR_UNKNOWN_ERROR = -39,
} keymaster_error_t;

/**
 * \deprecated Parameters needed to generate an RSA key.
 */
typedef struct {
    uint32_t modulus_size; /* bits */
    uint64_t public_exponent;
} keymaster_rsa_keygen_params_t;

/**
 * \deprecated Parameters needed to generate a DSA key.
 */
typedef struct {
    uint32_t key_size; /* bits */
    uint32_t generator_len;
    uint32_t prime_p_len;
    uint32_t prime_q_len;
    const uint8_t* generator;
    const uint8_t* prime_p;
    const uint8_t* prime_q;
} keymaster_dsa_keygen_params_t;

/**
 * \deprecated Parameters needed to generate an EC key.
 *
 * Field size is the only parameter in version 4. The sizes correspond to these required curves:
 *
 * 192 = NIST P-192
 * 224 = NIST P-224
 * 256 = NIST P-256
 * 384 = NIST P-384
 * 521 = NIST P-521
 *
 * The parameters for these curves are available at: http://www.nsa.gov/ia/_files/nist-routines.pdf
 * in Chapter 4.
 */
typedef struct { uint32_t field_size; /* bits */ } keymaster_ec_keygen_params_t;

/**
 * \deprecated Type of padding used for RSA operations.
 */
typedef enum {
    PADDING_NONE,
} keymaster_rsa_padding_t;

/**
 * \deprecated
 */
typedef struct { keymaster_digest_t digest_type; } keymaster_dsa_sign_params_t;

/**
 * \deprecated
 */
typedef struct { keymaster_digest_t digest_type; } keymaster_ec_sign_params_t;

/**
 *\deprecated
 */
typedef struct {
    keymaster_digest_t digest_type;
    keymaster_rsa_padding_t padding_type;
} keymaster_rsa_sign_params_t;

/**
 * The parameters that can be set for a given keymaster implementation.
 */
struct keymaster_device {
    struct hw_device_t common;

    /**
     * THIS IS DEPRECATED. Use the new "module_api_version" and "hal_api_version"
     * fields in the keymaster_module initialization instead.
     */
    uint32_t client_version;

    /**
     * See flags defined for keymaster_device::flags above.
     */
    uint32_t flags;

    void* context;

    /**
     * Gets algorithms supported.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[out] algorithms Array of algorithms supported.  Caller assumes ownership of the
     * array and must free it.
     *
     * \param[out] algorithms_length Length of \p algorithms.
     */
    keymaster_error_t (*get_supported_algorithms)(const struct keymaster_device* dev,
                                                  keymaster_algorithm_t** algorithms,
                                                  size_t* algorithms_length);

    /**
     * Gets the block modes supported for the specified algorithm.  Caller assumes ownership of the
     * allocated array.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] algorithm The algorithm for which supported modes will be returned.
     *
     * \param[out] modes Array of modes supported.  Caller assumes ownership of array.
     *
     * \param[out] modes_length Length of \p modes.
     */
    keymaster_error_t (*get_supported_block_modes)(const struct keymaster_device* dev,
                                                   keymaster_algorithm_t algorithm,
                                                   keymaster_block_mode_t** modes,
                                                   size_t* modes_length);

    /**
     * Gets the padding modes supported for the specified algorithm.  Caller assumes ownership of
     * the allocated array.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] algorithm The algorithm for which supported padding modes will be returned.
     *
     * \param[out] modes Array of padding modes supported.  Caller assumes ownership of array.
     *
     * \param[out] modes_length Length of \p modes.
     */
    keymaster_error_t (*get_supported_padding_modes)(const struct keymaster_device* dev,
                                                     keymaster_algorithm_t algorithm,
                                                     keymaster_padding_t** modes,
                                                     size_t* modes_length);

    /**
     * Gets the digests supported for the specified algorithm.  Caller assumes ownership of the
     * allocated array.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] algorithm The algorithm for which supported digests will be returned.
     *
     * \param[out] digests Array of digests supported.  Caller assumes ownership of array.
     *
     * \param[out] digests_length Length of \p digests.
     */
    keymaster_error_t (*get_supported_digests)(const struct keymaster_device* dev,
                                               keymaster_algorithm_t algorithm,
                                               keymaster_digest_t** digests,
                                               size_t* digests_length);

    /**
     * Gets the key import formats supported for keys of the specified algorithm.  Caller assumes
     * ownership of the allocated array.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] algorithm The algorithm for which supported formats will be returned.
     *
     * \param[out] formats Array of formats supported.  Caller assumes ownership of array.
     *
     * \param[out] formats_length Length of \p formats.
     */
    keymaster_error_t (*get_supported_import_formats)(const struct keymaster_device* dev,
                                                      keymaster_algorithm_t algorithm,
                                                      keymaster_key_format_t** formats,
                                                      size_t* formats_length);

    /**
     * Gets the key export formats supported for keys of the specified algorithm.  Caller assumes
     * ownership of the allocated array.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] algorithm The algorithm for which supported formats will be returned.
     *
     * \param[out] formats Array of formats supported.  Caller assumes ownership of array.
     *
     * \param[out] formats_length Length of \p formats.
     */
    keymaster_error_t (*get_supported_export_formats)(const struct keymaster_device* dev,
                                                      keymaster_algorithm_t algorithm,
                                                      keymaster_key_format_t** formats,
                                                      size_t* formats_length);

    /**
     * Adds entropy to the RNG used by keymaster.  Entropy added through this method is guaranteed
     * not to be the only source of entropy used, and the mixing function is required to be secure,
     * in the sense that if the RNG is seeded (from any source) with any data the attacker cannot
     * predict (or control), then the RNG output is indistinguishable from random.  Thus, if the
     * entropy from any source is good, the output will be good.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] data Random data to be mixed in.
     *
     * \param[in] data_length Length of \p data.
     */
    keymaster_error_t (*add_rng_entropy)(uint8_t* data, size_t data_length);

    /**
     * Generates a key, or key pair, returning a key blob and/or a description of the key.
     *
     * Key generation parameters are defined as keymaster tag/value pairs, provided in \p params.
     * See keymaster_tag_t for the full list.  Some values that are always required for generation
     * of useful keys are:
     *
     * - KM_TAG_ALGORITHM;
     * - KM_TAG_KEY_SIZE;
     * - KM_TAG_PURPOSE;
     * - KM_TAG_USER_ID
     * - KM_TAG_USER_AUTH_ID;
     * - KM_TAG_APPLICATION_ID or KM_TAG_ALL_APPLICATIONS;
     * - KM_TAG_PRIVKEY_EXPIRE_DATETIME
     *
     * KM_TAG_AUTH_TIMEOUT should generally be specified. If unspecified, the user will have to
     * authenticate for every use.
     *
     * KM_TAG_BLOCK_MODE, KM_TAG_PADDING, KM_TAG_MAC_LENGTH and KM_TAG_DIGEST must be specified for
     * algorithms that require them.
     *
     * The following tags will take default values if unspecified:
     *
     * - KM_TAG_PUBKEY_EXPIRE_DATETIME will default to the value for
     *   KM_TAG_PRIVKEY_EXPIRE_DATETIME.
     * - KM_TAG_ACTIVE_DATETIME will default to the value of
     *   KM_TAG_CREATION_DATETIME
     * - KM_TAG_ROOT_OF_TRUST will default to the current root of trust.
     * - KM_TAG_{RSA|DSA|DH}_* will default to values appropriate for the
     *   specified key size.
     *
     * The following tags may not be specified; their values will be provided by the implementation.
     *
     * - KM_TAG_ORIGIN,
     * - KM_TAG_ROLLBACK_RESISTANT,
     * - KM_TAG_CREATION_DATETIME,
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] params Array of key generation parameters.
     *
     * \param[in] params_count Length of \p params.
     *
     * \param[out] key_blob returns the generated key. If \p key_blob is NULL, no key is generated,
     * but the characteristics of the key that would be generated are returned.  If non-NULL (and \p
     * params is valid), a key is generated and the \p key_blob contains opaque data that uniquely
     * identifies the key and must be provided for each use of the key.  The caller assumes
     * ownership of the key_material in \p key_blob.
     *
     * \param[out] characteristics returns the characteristics of the key that was, or would be,
     * generated, if non-NULL.  The caller assumes ownership, and the object must be freed with
     * free_characteristics().
     *
     * The caller assumes ownership of the allocated \p key_blob and \p characteristics objects. Use
     * free_characteristics() to deallocate the latter.
     */
    keymaster_error_t (*generate_key)(const struct keymaster_device* dev,
                                      const keymaster_key_param_t* params, size_t params_count,
                                      keymaster_key_blob_t* key_blob,
                                      keymaster_key_characteristics_t** characteristics);

    /**
     * Returns the characteristics of the specified key, or NULL if the key_blob is invalid
     * (implementations must fully validate the integrity of the key).  client_id and app_data must
     * be the ID and data provided when the key was generated or imported.  Those values are not
     * included in the returned characteristics.  Caller assumes ownership of the allocated
     * characteristics object, which must be deallocated with free_characteristics().
     *
     * Note that some tags are never returned. These include: TODO(swillden)
     */
    void (*get_key_characteristics)(const struct keymaster_device* dev,
                                    const keymaster_key_blob_t* key_blob,
                                    const keymaster_blob_t* client_id,
                                    const keymaster_blob_t* app_data,
                                    keymaster_key_characteristics_t** characteristics);

    /**
     * Deallocate a keymaster_key_characteristics_t object returned by get_key_characteristics or
     * another API function.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] p The characteristics structure to be deleted.
     */
    void (*free_characteristics)(const struct keymaster_device* dev,
                                 const keymaster_key_characteristics_t* p);

    /**
     * Imports a key, or key pair, returning a key blob and/or a description of the key.
     *
     * Most key import parameters are defined as keymaster tag/value pairs, provided in "params".
     * See keymaster_tag_t for the full list.  Some values that are always required for import of
     * useful keys are:
     *
     * - KM_TAG_PURPOSE;
     *
     * - KM_TAG_USER_ID
     *
     * - KM_TAG_USER_AUTH_ID;
     *
     * - KM_TAG_APPLICATION_ID or KM_TAG_ALL_APPLICATIONS;
     *
     * - KM_TAG_PRIVKEY_EXPIRE_DATETIME.
     *
     * KM_TAG_AUTH_TIMEOUT should generally be specified. If unspecified, the user will have to
     * authenticate for every use, unless KM_TAG_USER_AUTH_ID is set to
     * KM_NO_AUTHENTICATION_REQUIRED.
     *
     * The following tags will take default values if unspecified:
     *
     * - KM_TAG_PUBKEY_EXPIRE_DATETIME will default to the value for KM_TAG_PRIVKEY_EXPIRE_DATETIME.
     *
     * - KM_TAG_ACTIVE_DATETIME will default to the value of KM_TAG_CREATION_DATETIME
     *
     * - KM_TAG_ROOT_OF_TRUST will default to the current root of trust.
     *
     * The following tags may not be specified; their values will be provided by the implementation.
     *
     * - KM_TAG_ORIGIN,
     *
     * - KM_TAG_ROLLBACK_RESISTANT,
     *
     * - KM_TAG_CREATION_DATETIME,
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] params Parameters defining the imported key.
     *
     * \param[in] params_count The number of entries in \p params.
     *
     * \param[in] key_format specifies the format of the key data in key_data.
     *
     * \param[out] key_blob Used to return the opaque key blob.  Must be non-NULL.  The caller
     * assumes ownership of the contained key_material.
     *
     * \param[out] characteristics Used to return the characteristics of the imported key.  May be
     * NULL, in which case no characteristics will be returned.  If non-NULL, the caller assumes
     * ownership and must deallocate with free_characteristics().
     */
    keymaster_error_t (*import_key)(const struct keymaster_device* dev,
                                    const keymaster_key_param_t* params, size_t params_count,
                                    keymaster_key_format_t key_format, const uint8_t* key_data,
                                    size_t key_data_length, keymaster_key_blob_t* key_blob,
                                    keymaster_key_characteristics_t** characteristics);

    /**
     * Exports a public key, returning a byte array in the specified format.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] export_format The format to be used for exporting the key.
     *
     * \param[in] key_to_export The key to export.
     *
     * \param[out] export_data The exported key material.  The caller assumes ownership.
     *
     * \param[out] export_data_length The length of \p export_data.
     */
    keymaster_error_t (*export_key)(const struct keymaster_device* dev,
                                    keymaster_key_format_t export_format,
                                    const keymaster_key_blob_t* key_to_export,
                                    uint8_t** export_data, size_t* export_data_length);

    /**
     * Deletes the key, or key pair, associated with the key blob.  After calling this function it
     * will be impossible to use the key for any other operations (though rescoped versions may
     * exist, and if so will be usable).  May be applied to keys from foreign roots of trust (keys
     * not usable under the current root of trust).
     *
     * This function is optional and should be set to NULL if it is not implemented.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] key The key to be deleted.
     */
    keymaster_error_t (*delete_key)(const struct keymaster_device* dev,
                                    const keymaster_key_blob_t* key);

    /**
     * Deletes all keys in the hardware keystore. Used when keystore is reset completely.  After
     * calling this function it will be impossible to use any previously generated or imported key
     * blobs for any operations.
     *
     * This function is optional and should be set to NULL if it is not implemented.
     *
     * \param[in] dev The keymaster device structure.
     *
     * Returns 0 on success or an error code less than 0.
     */
    int (*delete_all_keys)(const struct keymaster_device* dev);

    /**
     * Begins a cryptographic operation using the specified key.  If all is well, begin() will
     * return KM_ERROR_OK and create an operation handle which must be passed to subsequent calls to
     * update(), finish() or abort().
     *
     * It is critical that each call to begin() be paired with a subsequent call to finish() or
     * abort(), to allow the keymaster implementation to clean up any internal operation state.
     * Failure to do this will leak internal state space or other internal resources and will
     * eventually cause begin() to return KM_ERROR_TOO_MANY_OPERATIONS when it runs out of space for
     * operations.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] purpose The purpose of the operation, one of KM_PURPOSE_ENCRYPT,
     * KM_PURPOSE_DECRYPT, KM_PURPOSE_SIGN or KM_PURPOSE_VERIFY. Note that for AEAD modes,
     * encryption and decryption imply signing and verification, respectively.
     *
     * \param[in] key The key to be used for the operation. \p key must have a purpose compatible
     * with \p purpose and all of its usage requirements must be satisfied, or begin() will return
     * an appropriate error code.
     *
     * \param[in] params Additional parameters for the operation.  This is typically used to provide
     * client ID information, with tags KM_TAG_APPLICATION_ID and KM_TAG_APPLICATION_DATA.  If the
     * client information associated with the key is not provided, begin() will fail and return
     * KM_ERROR_INVALID_KEY_BLOB.  Less commonly, \params can be used to provide AEAD additional
     * data and chunk size with KM_TAG_ADDITIONAL_DATA or KM_TAG_CHUNK_SIZE respectively.
     *
     * \param[in] params_count The number of entries in \p params.
     *
     * \param[in,out] operation_handle The newly-created operation handle which must be passed to
     * update(), finish() or abort().  Prior to calling begin(), *operation_handle must be set to 0,
     * unless set to a handle returned by generate_nonce().
     */
    keymaster_error_t (*begin)(const struct keymaster_device* dev, keymaster_purpose_t purpose,
                               const keymaster_key_blob_t* key, const keymaster_key_param_t* params,
                               size_t params_count, keymaster_operation_handle_t* operation_handle);

    /**
     * Provides data to, and possibly receives output from, an ongoing cryptographic operation begun
     * with begin().
     *
     * If operation_handle is invalid, update() will return KM_ERROR_INVALID_OPERATION_HANDLE.
     *
     * Not all of the data provided in the data buffer may be consumed.  update() will return the
     * amount consumed in *data_consumed.  The caller should provide the unconsumed data in a
     * subsequent call.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] operation_handle The operation handle returned by begin().
     *
     * \param[in] input Data to be processed, per the parameters established in the call to begin().
     * Note that update() may or may not consume all of the data provided.  See \p data_consumed.
     *
     * \param[in] input_length Length of \p data.
     *
     * \param[out] input_consumed Amount of data that was consumed by update().  If this is less
     * than the amount provided, the caller should provide the remainder in a subsequent call to
     * update().
     *
     * \param[in,out] output A pointer to the address of the buffer into which output data will be
     * written.  If \p *output is NULL, update() will dynamically allocate an output buffer
     * (ignoring \p output_length) of an appropriate size and point \p *output at it.  The caller
     * assumes ownership of the allocated buffer.  If \p *output is non-NULL, update() will write at
     * most \p output_length bytes to the referenced buffer.
     *
     * \param[in] output_length The length of the buffer referenced by \p *output, if non-NULL.  If
     * \p *output is non-NULL and output_length is too small to contain the data update() would
     * write, then update() will not write any output or consume any input and will return
     * KM_ERROR_INSUFFICIENT_BUFFER_SPACE.  The caller should try again with a larger buffer, or set
     * \p *output to NULL and allow update() to allocate the buffer.
     *
     * \param[out] output_written Returns the amount of data written to \p *output by update().
     *
     * If the caller sets *output to NULL, it assumes ownership of the returned buffer.
     *
     * Note that update() may not provide any output, in which case *output_written will contain
     * zero.
     */
    keymaster_error_t (*update)(const struct keymaster_device* dev,
                                keymaster_operation_handle_t operation_handle, const uint8_t* input,
                                size_t input_length, size_t* input_consumed, uint8_t** output,
                                size_t output_length, size_t* output_written);

    /**
     * Finalizes a cryptographic operation begun with begin() and invalidates operation_handle
     * (except in the insufficient buffer case, detailed below).
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] operation_handle The operation handle returned by begin().
     *
     * \param[in] signature The signature to be verified if the purpose specified in the begin()
     * call was KM_PURPOSE_VERIFY.
     *
     * \param[in] signature_length The length of \p signature.
     *
     * \param[in,out] output A pointer to the address of the buffer into which output data will be
     * written.  If \p *output is NULL, update() will dynamically allocate an output buffer
     * (ignoring \p output_length) of an appropriate size and point \p *output at it.  The caller
     * assumes ownership of the allocated buffer.  If \p *output is non-NULL, update() will write at
     * most \p output_length bytes to the referenced buffer.
     *
     * \param[in] output_length The length of the buffer referenced by \p *output, if non-NULL.  If
     * \p *output is non-NULL and output_length is too small to contain the data update() would
     * write, then update() will not write any output or consume any input and will return
     * KM_ERROR_INSUFFICIENT_BUFFER_SPACE.  The caller should try again with a larger buffer, or set
     * \p *output to NULL and allow update() to allocate the buffer.
     *
     * \param[out] output_written Returns the amount of data written to \p *output by update().
     *
     * If the operation being finished is a signature verification or an AEAD-mode decryption and
     * verification fails then finish() will return KM_ERROR_VERIFICATION_FAILED.  Note that in the
     * decryption case output may be incomplete.  operation_handle will be invalidated.
     */
    keymaster_error_t (*finish)(const struct keymaster_device* dev,
                                keymaster_operation_handle_t operation_handle,
                                const uint8_t* signature, size_t signature_length, uint8_t** output,
                                size_t output_length, size_t* output_written);

    /**
     * Aborts a cryptographic operation begun with begin(), freeing all internal resources and
     * invalidating operation_handle.
     */
    keymaster_error_t (*abort)(const struct keymaster_device* dev,
                               keymaster_operation_handle_t operation_handle);

    /**
     * \deprecated Generates a public and private key. The key-blob returned is opaque and must
     * subsequently provided for signing and verification.
     *
     * Returns: 0 on success or an error code less than 0.
     */
    int (*generate_keypair)(const struct keymaster_device* dev, const keymaster_keypair_t key_type,
                            const void* key_params, uint8_t** key_blob, size_t* key_blob_length);

    /**
     * \deprecated Imports a public and private key pair. The imported keys will be in PKCS#8 format
     * with DER encoding (Java standard). The key-blob returned is opaque and will be subsequently
     * provided for signing and verification.
     *
     * Returns: 0 on success or an error code less than 0.
     */
    int (*import_keypair)(const struct keymaster_device* dev, const uint8_t* key,
                          const size_t key_length, uint8_t** key_blob, size_t* key_blob_length);

    /**
     * \deprecated Gets the public key part of a key pair. The public key must be in X.509 format
     * (Java standard) encoded byte array.
     *
     * Returns: 0 on success or an error code less than 0.  On error, x509_data
     * should not be allocated.
     */
    int (*get_keypair_public)(const struct keymaster_device* dev, const uint8_t* key_blob,
                              const size_t key_blob_length, uint8_t** x509_data,
                              size_t* x509_data_length);

    /**
     * \deprecated Deletes the key pair associated with the key blob.
     *
     * This function is optional and should be set to NULL if it is not
     * implemented.
     *
     * Returns 0 on success or an error code less than 0.
     */
    int (*delete_keypair)(const struct keymaster_device* dev, const uint8_t* key_blob,
                          const size_t key_blob_length);

    /**
     * \deprecated Deletes all keys in the hardware keystore. Used when keystore is reset
     * completely.
     *
     * This function is optional and should be set to NULL if it is not
     * implemented.
     *
     * Returns 0 on success or an error code less than 0.
     */
    int (*delete_all)(const struct keymaster_device* dev);

    /**
     * \deprecated Signs data using a key-blob generated before. This can use either an asymmetric
     * key or a secret key.
     *
     * Returns: 0 on success or an error code less than 0.
     */
    int (*sign_data)(const struct keymaster_device* dev, const void* signing_params,
                     const uint8_t* key_blob, const size_t key_blob_length, const uint8_t* data,
                     const size_t data_length, uint8_t** signed_data, size_t* signed_data_length);

    /**
     * \deprecated Verifies data signed with a key-blob. This can use either an asymmetric key or a
     * secret key.
     *
     * Returns: 0 on successful verification or an error code less than 0.
     */
    int (*verify_data)(const struct keymaster_device* dev, const void* signing_params,
                       const uint8_t* key_blob, const size_t key_blob_length,
                       const uint8_t* signed_data, const size_t signed_data_length,
                       const uint8_t* signature, const size_t signature_length);
};
typedef struct keymaster_device keymaster_device_t;

/* Convenience API for opening and closing keymaster devices */

static inline int keymaster_open(const struct hw_module_t* module, keymaster_device_t** device) {
    return module->methods->open(module, KEYSTORE_KEYMASTER, (struct hw_device_t**)device);
}

static inline int keymaster_close(keymaster_device_t* device) {
    return device->common.close(&device->common);
}

__END_DECLS

#endif  // ANDROID_HARDWARE_KEYMASTER_H
