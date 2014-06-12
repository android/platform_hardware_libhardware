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
#include <hardware/keymaster_defs.h>

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
#define KEYMASTER_DEVICE_API_VERSION_0_2 \
    HARDWARE_DEVICE_API_VERSION_2(0, 2, KEYMASTER_HEADER_VERSION)

#define KEYMASTER_MODULE_API_VERSION_0_3 HARDWARE_MODULE_API_VERSION(0, 3)
#define KEYMASTER_DEVICE_API_VERSION_0_3 \
    HARDWARE_DEVICE_API_VERSION_2(0, 3, KEYMASTER_HEADER_VERSION)

#define KEYMASTER_MODULE_API_VERSION_0_4 HARDWARE_MODULE_API_VERSION(0, 4)
#define KEYMASTER_DEVICE_API_VERSION_0_4 \
    HARDWARE_DEVICE_API_VERSION_2(0, 4, KEYMASTER_HEADER_VERSION)

struct keystore_module {
    /**
     * Common methods of the keystore module.  This *must* be the first member of
     * keystore_module as users of this structure will cast a hw_module_t to
     * keystore_module pointer in contexts where it's known the hw_module_t references a
     * keystore_module.
     */
    hw_module_t common;
};

/**
 * The parameters that can be set for a given keymaster implementation.
 */
struct keymaster_device {
    /**
     * Common methods of the keymaster device.  This *must* be the first member of
     * keymaster_device as users of this structure will cast a hw_device_t to
     * keymaster_device pointer in contexts where it's known the hw_device_t references a
     * keymaster_device.
     */
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

    /**
     * Gets algorithms supported.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[out] algorithms Array of algorithms supported, if not NULL.
     *
     * \param[in,out] algorithms_length Length of \p algorithms.  The caller should set this to the
     * length of the allocated \p algorithms array, if not NULL.  If \p algorithms is NULL or too
     * small, will contain the required size upon return.  If \p algorithms is adequate, will
     * contain the number of entries written.
     *
     * \return KM_ERROR_INSUFFICIENT_BUFFER_SPACE if the buffer is too small or NULL. KM_ERROR_OK
     * otherwise.
     */
    keymaster_error_t (*get_supported_algorithms)(const struct keymaster_device* dev,
                                                  keymaster_algorithm_t* algorithms,
                                                  size_t* algorithms_length);

    /**
     * Gets the block modes supported for the specified algorithm.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] algorithm The algorithm for which supported modes will be returned.
     *
     * \param[out] modes Array of modes supported, if not NULL.
     *
     * \param[in,out] modes_length Length of \p modes.  The caller should set this to the length of
     * the allocated \p modes array, if not NULL.  If \p modes is NULL or too small, will contain
     * the required size upon return.  If \p modes is adequate, will contain the number of entries
     * written.
     *
     * \return KM_ERROR_INSUFFICIENT_BUFFER_SPACE if the buffer is too small or NULL. KM_ERROR_OK
     * otherwise.
     */
    keymaster_error_t (*get_supported_block_modes)(const struct keymaster_device* dev,
                                                   keymaster_algorithm_t algorithm,
                                                   keymaster_purpose_t purpose,
                                                   keymaster_block_mode_t* modes,
                                                   size_t* modes_length);

    /**
     * Gets the padding modes supported for the specified algorithm.  Caller assumes ownership of
     * the allocated array.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] algorithm The algorithm for which supported padding modes will be returned.
     *
     * \param[out] modes Array of padding modes supported, if not NULL.
     *
     * \param[in, out] modes_length Length of \p modes.  The caller should set this to the length of
     * the allocated \p modes array, if not NULL.  If \p modes is NULL or too small, will contain
     * the required size upon return.  If \p modes is adequate, will contain the number of entries
     * written.
     *
     * \return KM_ERROR_INSUFFICIENT_BUFFER_SPACE if the buffer is too small or NULL. KM_ERROR_OK
     * otherwise.
     */
    keymaster_error_t (*get_supported_padding_modes)(const struct keymaster_device* dev,
                                                     keymaster_algorithm_t algorithm,
                                                     keymaster_purpose_t purpose,
                                                     keymaster_padding_t* modes,
                                                     size_t* modes_length);

    /**
     * Gets the digests supported for the specified algorithm.  Caller assumes ownership of the
     * allocated array.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] algorithm The algorithm for which supported digests will be returned.
     *
     * \param[out] digests Array of digests supported, if not NULL.
     *
     * \param[in, out] digests_length Length of \p digests.  The caller should set this to the
     * length of the allocated \p digests array, if not NULL.  If \p digests is NULL or too small,
     * will contain the required size upon return.  If \p digests is adequate, will contain the
     * number of entries written.
     *
     * \return KM_ERROR_INSUFFICIENT_BUFFER_SPACE if the buffer is too small or NULL. KM_ERROR_OK
     * otherwise.
     */
    keymaster_error_t (*get_supported_digests)(const struct keymaster_device* dev,
                                               keymaster_algorithm_t algorithm,
                                               keymaster_purpose_t purpose,
                                               keymaster_digest_t* digests, size_t* digests_length);

    /**
     * Gets the key import formats supported for keys of the specified algorithm.  Caller assumes
     * ownership of the allocated array.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] algorithm The algorithm for which supported formats will be returned.
     *
     * \param[out] formats Array of formats supported, if not NULL.
     *
     * \param[in,out] formats_length Length of \p formats.  The caller should set this to the length
     * of the allocated \p formats array, if not NULL.  If \p formats is NULL or too small, will
     * contain the required size upon return.  If \p formats is adequate, will contain the number of
     * entries written.
     *
     * \return KM_ERROR_INSUFFICIENT_BUFFER_SPACE if the buffer is too small or NULL. KM_ERROR_OK
     * otherwise.
     */
    keymaster_error_t (*get_supported_import_formats)(const struct keymaster_device* dev,
                                                      keymaster_algorithm_t algorithm,
                                                      keymaster_key_format_t* formats,
                                                      size_t* formats_length);

    /**
     * Gets the key export formats supported for keys of the specified algorithm.  Caller assumes
     * ownership of the allocated array.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] algorithm The algorithm for which supported formats will be returned.
     *
     * \param[out] formats Array of formats supported, if not NULL.
     *
     * \param[in, out] formats_length Length of \p formats.  The caller should set this to the
     * length of the allocated \p formats array, if not NULL.  If \p formats is NULL or too small,
     * will contain the required size upon return.  If \p formats is adequate, will contain the
     * number of entries written.
     *
     * \return KM_ERROR_INSUFFICIENT_BUFFER_SPACE if the buffer is too small or NULL. KM_ERROR_OK
     * otherwise.
     */
    keymaster_error_t (*get_supported_export_formats)(const struct keymaster_device* dev,
                                                      keymaster_algorithm_t algorithm,
                                                      keymaster_key_format_t* formats,
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
     * - KM_TAG_PURPOSE;
     * - KM_TAG_USER_ID or KM_TAG_ALL_USERS;
     * - KM_TAG_USER_AUTH_ID or KM_TAG_NO_AUTH_REQUIRED;
     * - KM_TAG_APPLICATION_ID or KM_TAG_ALL_APPLICATIONS; and
     * - KM_TAG_ORIGINATION_EXPIRE_DATETIME
     *
     * KM_TAG_AUTH_TIMEOUT should generally be specified unless KM_TAG_NO_AUTH_REQUIRED is present,
     * or the user will have to authenticate for every use.
     *
     * KM_TAG_BLOCK_MODE, KM_TAG_PADDING, KM_TAG_MAC_LENGTH and KM_TAG_DIGEST must be specified for
     * algorithms that require them.
     *
     * The following tags will take default values if unspecified:
     *
     * - KM_TAG_KEY_SIZE defaults to a recommended key size for the  specified algorithm.
     *
     * - KM_TAG_USAGE_EXPIRE_DATETIME defaults to the value of KM_TAG_ORIGINATION_EXPIRE_DATETIME.
     *
     * - KM_TAG_ACTIVE_DATETIME will default to the value of KM_TAG_CREATION_DATETIME
     *
     * - KM_TAG_ROOT_OF_TRUST will default to the current root of trust.
     *
     * - KM_TAG_{RSA|DSA|DH}_* will default to values appropriate for the specified key size.
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
     * \param[in] params Array of key generation parameters.
     *
     * \param[in] params_count Length of \p params.
     *
     * \param[out] key_blob returns the generated key. If \p key_blob is NULL, no key is generated,
     * but the characteristics of the key that would be generated are returned.  To generate a key,
     * the caller must allocate a sufficiently-large data array in key_blob->key_material,
     * specifying its length in key_blob->key_material_size.  If key_blob->key_material is NULL, or
     * too small, generate key will return KM_ERROR_INSUFFICIENT_BUFFER_SPACE and place the required
     * size in key_blob->key_material_size.  If key_blob->key_material is adequate, generate_key
     * will place the number of bytes written in key_blob->key_material_size.
     *
     * \param[out] characteristics returns the characteristics of the key that was, or would be,
     * generated, if non-NULL.  The caller assumes ownership, and the object must be freed with
     * free_characteristics().  Note that KM_TAG_ROOT_OF_TRUST, KM_TAG_APPLICATION_ID and
     * KM_TAG_APPLICATION_DATA are never returned.
     *
     * The caller assumes ownership of the allocated \p characteristics object. Use
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
     * Note that KM_TAG_ROOT_OF_TRUST, KM_TAG_APPLICATION_ID and KM_TAG_APPLICATION_DATA are never
     * returned.
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
     * Change a key's authorizations.
     *
     * Update the authorizations associated with key_blob to the list specified in new_params, which
     * must contain the complete set of authorizations desired (enforced and unenforced).  Tags will
     * be added, removed and/or updated only if the appropriate KM_TAG_RESCOPING_ADD and
     * KM_TAG_RESCOPING_DEL tags exist in the key's authorizations, otherwise
     * KM_ERROR_INVALID_RESCOPING will be returned and no changes will be made.
     *
     * \param[in] dev The keymaster device structure.
     *
     * \param[in] new_params The new authorization list to be associated with the key.
     *
     * \param[in] new_params_count The number of entries in \p new_params.
     *
     * \param[in,out] key_blob The key to update.  Upon return (if successful), will contain the
     * updated key blob associated with the new authorizations.
     *
     * \param[out] characteristics If not null will contain the new key authorizations, divided into
     * enforced and unenforced lists.  The caller takes ownership and must call free_characteristics
     * to free.
     */
    void (*rescope)(const struct keymaster_device* dev, const keymaster_key_param_t* new_params,
                    size_t new_params_count, keymaster_key_blob_t* key_blob,
                    const keymaster_blob_t* client_id, const keymaster_blob_t* app_data,
                    keymaster_key_characteristics_t** characteristics);

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
                                    const keymaster_blob_t* client_id,
                                    const keymaster_blob_t* app_data, uint8_t** export_data,
                                    size_t* export_data_length);

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
     * \param[out] operation_handle The newly-created operation handle which must be passed to
     * update(), finish() or abort().
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
     * \param[in,out] output_length The length of the buffer referenced by \p *output, if non-NULL.
     * If \p *output is non-NULL and output_length is too small to contain the data update() would
     * write, then update() will not write any output or consume any input, will return
     * KM_ERROR_INSUFFICIENT_BUFFER_SPACE and will set \p *output_length to the amount of space
     * required.  The caller should try again with a larger buffer, or set \p *output to NULL and
     * allow update() to allocate the buffer.
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
                                size_t input_length, size_t* input_consumed, uint8_t* output,
                                size_t* output_length, size_t* output_written);

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
     * \param[in, out] output_length The length of the buffer referenced by \p *output, if non-NULL.
     * If \p *output is non-NULL and output_length is too small to contain the data update() would
     * write, then update() will not write any output or consume any input, will return
     * KM_ERROR_INSUFFICIENT_BUFFER_SPACE and will set *output_length to the length required.  The
     * caller should try again with a larger buffer, or set \p *output to NULL and allow update() to
     * allocate the buffer.
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
                                size_t* output_length, size_t* output_written);

    /**
     * Aborts a cryptographic operation begun with begin(), freeing all internal resources and
     * invalidating operation_handle.
     */
    keymaster_error_t (*abort)(const struct keymaster_device* dev,
                               keymaster_operation_handle_t operation_handle);
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
