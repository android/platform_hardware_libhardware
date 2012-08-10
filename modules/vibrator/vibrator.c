/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <cutils/log.h>

#include <hardware/hardware.h>
#include <hardware/vibrator.h>

static const char THE_DEVICE[] = "/sys/class/timed_output/vibrator/enable";
// Size of an int in bits and on base-2 system + 1 for precision
// + 1 for end of string \0 char +1 for \n in snprintf
static const int MAX_CHAR_SIZE = 13;

static int vibra_exists() {
    int fd;

    fd = open(THE_DEVICE, O_RDWR);
    if(fd < 0) {
        ALOGE("Vibrator file does not exist : %d", fd);
        return 0;
    }

    close(fd);
    return 1;
}

static int sendit(int timeout_ms)
{
    int nwr, ret, fd;

    char value[MAX_CHAR_SIZE];

    fd = open(THE_DEVICE, O_RDWR);
    if(fd < 0) {
        return errno;
    }

    nwr = snprintf(value, sizeof(value), "%d\n", timeout_ms);
    ret = write(fd, value, nwr);

    close(fd);

    return (ret == nwr) ? 0 : -1;
}

static int vibra_on(vibra_device_t* vibradev, int timeout_ms)
{
    /* constant on, up to maximum allowed time */
    return sendit(timeout_ms);
}

static int vibra_off(vibra_device_t* vibradev)
{
    return sendit(0);
}

static int vibra_close(hw_device_t *device)
{
    free(device);
    return 0;
}

static int vibra_open(const hw_module_t* module, const char* id,
                      hw_device_t** device) {
    if (!vibra_exists()) {
        ALOGE("Vibrator device does not exist. Can not start vibrator");
        return -ENODEV;
    }

    vibra_device_t *vibradev = calloc(1, sizeof(vibra_device_t));

    if (!vibradev) {
        ALOGE("Can not allocate memory for the vibrator device");
        return -ENOMEM;
    }

    vibradev->common.tag = HARDWARE_DEVICE_TAG;
    vibradev->common.module = (hw_module_t *) module;
    vibradev->common.version = 0;
    vibradev->common.close = vibra_close;

    vibradev->vibrator_on = vibra_on;
    vibradev->vibrator_off = vibra_off;

    *device = (hw_device_t *) vibradev;

    return 0;
}

/*===========================================================================*/
/* Default vibrator HW module interface definition                           */
/*===========================================================================*/

static struct hw_module_methods_t vibra_module_methods = {
    .open = vibra_open,
};

struct hw_module_t HAL_MODULE_INFO_SYM = {
    .tag = HARDWARE_MODULE_TAG,
    .module_api_version = 1,
    .hal_api_version = 0,
    .id = VIBRATOR_HARDWARE_MODULE_ID,
    .name = "Default vibrator HAL",
    .author = "The Android Open Source Project",
    .methods = &vibra_module_methods,
};
