/*
 * Copyright (C) 2016 The Android Open Source Project
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
#include <errno.h>
#include <string.h>

#include <hardware/nvram.h>

namespace {

nvram_result_t get_total_size_in_bytes(const struct nvram_device* device,
                                       uint64_t* total_size) {
    return NV_RESULT_OPERATION_DISABLED;
}

nvram_result_t get_available_size_in_bytes(const struct nvram_device* device,
                                           uint64_t* available_size) {
    return NV_RESULT_OPERATION_DISABLED;
}

nvram_result_t get_max_spaces(const struct nvram_device* device,
                              uint32_t* num_spaces) {
    return NV_RESULT_OPERATION_DISABLED;
}

nvram_result_t get_space_list(const struct nvram_device* device,
                              uint32_t max_list_size,
                              uint32_t* space_index_list, uint32_t* list_size) {
    return NV_RESULT_OPERATION_DISABLED;
}

nvram_result_t get_space_size(const struct nvram_device* device, uint32_t index,
                              uint64_t* size) {
    return NV_RESULT_OPERATION_DISABLED;
}

nvram_result_t get_space_controls(const struct nvram_device* device,
                                  uint32_t index, uint32_t max_list_size,
                                  nvram_control_t* control_list,
                                  uint32_t* list_size) {
    return NV_RESULT_OPERATION_DISABLED;
}

nvram_result_t is_space_locked(const struct nvram_device* device,
                               uint32_t index, int* write_lock_enabled,
                               int* read_lock_enabled) {
    return NV_RESULT_OPERATION_DISABLED;
}

nvram_result_t create_space(const struct nvram_device* device, uint32_t index,
                            uint64_t size_in_bytes,
                            nvram_control_t* control_list, uint32_t list_size,
                            uint8_t* authorization_value,
                            uint32_t authorization_value_size) {
    return NV_RESULT_OPERATION_DISABLED;
}

nvram_result_t delete_space(const struct nvram_device* device, uint32_t index,
                            uint8_t* authorization_value,
                            uint32_t authorization_value_size) {
    return NV_RESULT_OPERATION_DISABLED;
}

nvram_result_t disable_create(const struct nvram_device* device) {
    return NV_RESULT_OPERATION_DISABLED;
}

nvram_result_t write_space(const struct nvram_device* device, uint32_t index,
                           const uint8_t* buffer, uint64_t buffer_size,
                           uint8_t* authorization_value,
                           uint32_t authorization_value_size) {
    return NV_RESULT_OPERATION_DISABLED;
}

nvram_result_t read_space(const struct nvram_device* device, uint32_t index,
                          uint64_t num_bytes_to_read,
                          uint8_t* authorization_value,
                          uint32_t authorization_value_size, uint8_t* buffer,
                          uint64_t* bytes_read) {
    return NV_RESULT_OPERATION_DISABLED;
}

nvram_result_t enable_write_lock(const struct nvram_device* device,
                                 uint32_t index, uint8_t* authorization_value,
                                 uint32_t authorization_value_size) {
    return NV_RESULT_OPERATION_DISABLED;
}

nvram_result_t enable_read_lock(const struct nvram_device* device,
                                uint32_t index, uint8_t* authorization_value,
                                uint32_t authorization_value_size) {
    return NV_RESULT_OPERATION_DISABLED;
}

int nvram_device_close(struct hw_device_t* device) {
    nvram_device_t* tmp = reinterpret_cast<nvram_device_t*>(device);
    delete tmp;
    return 0;
}

int nvram_device_open(const struct hw_module_t* module, const char* name,
                      struct hw_device_t** device) {
    if (strcmp(name, NVRAM_HARDWARE_DEVICE_ID)) {
        return -EINVAL;
    }
    nvram_device_t* new_device{new nvram_device_t{
        .common = {
            .tag = HARDWARE_DEVICE_TAG,
            .version = NVRAM_DEVICE_API_VERSION_0_1,
            .module = const_cast<hw_module_t*>(module),
            .close = nvram_device_close,
        },
        .get_total_size_in_bytes = get_total_size_in_bytes,
        .get_available_size_in_bytes = get_available_size_in_bytes,
        .get_max_spaces = get_max_spaces,
        .get_space_list = get_space_list,
        .get_space_size = get_space_size,
        .get_space_controls = get_space_controls,
        .is_space_locked = is_space_locked,
        .create_space = create_space,
        .delete_space = delete_space,
        .disable_create = disable_create,
        .write_space = write_space,
        .read_space = read_space,
        .enable_write_lock = enable_write_lock,
        .enable_read_lock = enable_read_lock,
    }};

    *device = reinterpret_cast<hw_device_t*>(new_device);
    return 0;
}

static struct hw_module_methods_t nvram_module_methods = {
    .open = nvram_device_open
};

}  // namespace

struct nvram_module HAL_MODULE_INFO_SYM = {
    .common = {
        .tag = HARDWARE_MODULE_TAG,
        .module_api_version = NVRAM_MODULE_API_VERSION_0_1,
        .hal_api_version = HARDWARE_HAL_API_VERSION,
        .id = NVRAM_HARDWARE_MODULE_ID,
        .name = "Sample NVRAM HAL",
        .author = "The Android Open Source Project",
        .methods = &nvram_module_methods,
    }
};
