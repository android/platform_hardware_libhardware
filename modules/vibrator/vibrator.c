/*
 * Copyright (C) 2012 The Android Open Source Project
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
#include <math.h>

#include <qemu.h>
#include <hardware/hardware.h>
#include <hardware/vibrator.h>

static const char THE_DEVICE[] = "/sys/class/timed_output/vibrator/enable";

static int vibraExists() {
    int fd;

#ifdef QEMU_HARDWARE
    if (qemu_check()) {
        return 1;
    }
#endif

    fd = open(THE_DEVICE, O_RDWR);
    if(fd < 0) {
      ALOGE("Vibrator file does not exists : %d", fd);
      return 0;
    }

    close(fd);
    return 1;
}

static int sendit(int timeout_ms)
{
    int nwr, ret, fd;
    // Size of an int in bits and on base-2 system + 1 for precision + 1 for end of string \0 char
    uint32_t MAX_CHAR_SIZE = sizeof(int) * 8 * log (2) +1 +1;

    char value[MAX_CHAR_SIZE];

#ifdef QEMU_HARDWARE
    if (qemu_check()) {
        return qemu_control_command( "vibrator:%d", timeout_ms );
    }
#endif

    fd = open(THE_DEVICE, O_RDWR);
    if(fd < 0) {
        return errno;
    }

    nwr = snprintf(value, sizeof(value), "%d\n", timeout_ms);
    ret = write(fd, value, nwr);

    close(fd);

    return (ret == nwr) ? 0 : -1;
}

int vibraOn(int timeout_ms)
{
    /* constant on, up to maximum allowed time */
    return sendit(timeout_ms);
}

int vibraOff()
{
    return sendit(0);
}

/*===========================================================================*/
/* Default vibrator HW module interface definition                           */
/*===========================================================================*/

static struct hw_module_methods_t vibra_module_methods = {
    .open = NULL,
};

struct vibrator_module HAL_MODULE_INFO_SYM = {
    .common = {
        .tag = HARDWARE_MODULE_TAG,
        .version_major = 1,
        .version_minor = 0,
        .id = VIBRATOR_HARDWARE_MODULE_ID,
        .name = "Default vibrator HAL",
        .author = "The Android Open Source Project",
        .methods = &vibra_module_methods,
  },
    .vibrator_exists = vibraExists,
    .vibrator_on = vibraOn,
    .vibrator_off = vibraOff,
};
