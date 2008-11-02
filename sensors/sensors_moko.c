/*
 * Copyright 2008, Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <hardware/sensors.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <strings.h>
#include <sys/poll.h>

#include <linux/input.h>

#define LOG_TAG "Sensors"
#include <utils/Log.h>

#include <hardware/sensors.h>

struct accelData {
    int x;
    int y;
    int z;
    int mask;
    int changed;
};

static struct accelData accel;
static int t_accel[3];

static uint32_t sActiveSensors = 0;

#define SUPPORTED_SENSORS  (SENSORS_ACCELERATION)

#define EVENT_TYPE_ACCEL_X          0
#define EVENT_TYPE_ACCEL_Y          1
#define EVENT_TYPE_ACCEL_Z          2

#define EVENT_MASK_ACCEL_X          (1 << EVENT_TYPE_ACCEL_X)
#define EVENT_MASK_ACCEL_Y          (1 << EVENT_TYPE_ACCEL_Y)
#define EVENT_MASK_ACCEL_Z          (1 << EVENT_TYPE_ACCEL_Z)

#define EVENT_MASK_ACCEL_ALL        (EVENT_MASK_ACCEL_X | EVENT_MASK_ACCEL_Y | EVENT_MASK_ACCEL_Z)

#define INPUT_DIR "/dev/input"

// 980 LSG = 1G
#define LSG                         (980.0f)

// conversion to SI units (m/s^2)
#define CONVERT                     (GRAVITY_EARTH / LSG)
#define CONVERT_X                   (CONVERT)
#define CONVERT_Y                   (CONVERT)
#define CONVERT_Z                   (CONVERT)

static int open_input (void)
{
    char devname[PATH_MAX];
    char *filename;
    int fd;
    int res;
    uint8_t bits[4];
    ssize_t bits_size = 8;
    DIR *dir;
    struct dirent *de;

    dir = opendir(INPUT_DIR);
    if(dir == NULL)
        return sActiveSensors;

    strcpy(devname, INPUT_DIR);
    filename = devname + strlen(devname);
    *filename++ = '/';

    while((de = readdir(dir))) {
        if(de->d_name[0] == '.' &&
           (de->d_name[1] == '\0' ||
            (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue;
        strcpy(filename, de->d_name);
        fd = open(devname, O_RDONLY);
        if (fd < 0) {
            LOGE("Couldn't open %s, error = %d", devname, fd);
            continue;
        }
        res = ioctl(fd, EVIOCGBIT(EV_REL, 4), bits);
		if (res <= 0 || bits[0] != EVENT_MASK_ACCEL_ALL) {
            close(fd);
            continue;
        }
        closedir(dir);
        return fd;
    }
    closedir(dir);
    return -1;
}

/*****************************************************************************/

uint32_t sensors_control_init()
{
    return SUPPORTED_SENSORS;
}

int sensors_control_delay(int32_t ms)
{
    return -1;
}

int sensors_control_open()
{
    return open_input();
}

uint32_t sensors_control_activate(uint32_t sensors, uint32_t mask)
{
    mask &= SUPPORTED_SENSORS;
    uint32_t new_sensors = (sActiveSensors & ~mask) | (sensors & mask);
    sActiveSensors = new_sensors;
    LOGD("sensors=%08x\n", sActiveSensors);
    return sActiveSensors;
}

/*****************************************************************************/

static int sInputFD = -1;

int sensors_data_open(int fd)
{
    sInputFD = dup(fd);
    LOGD("sensors_data_open: fd = %d", sInputFD);
    return 0;
}

int sensors_data_close()
{
    close(sInputFD);
    sInputFD = -1;
    return 0;
}

/* returns a bitmask indicating which sensors have changed */
int sensors_data_poll(sensors_data_t* data, uint32_t sensors_of_interest)
{
    struct input_event event;
    int res;

    if ((sensors_of_interest & SENSORS_ACCELERATION) == 0)
        return 0;

    if (sInputFD < 0)
        return 0;

    while(1) {
        res = read(sInputFD, &event, sizeof(event));
        if(res < (int)sizeof(event))
            break;

        if (event.type == EV_REL) {
            // orientation or acceleration
            switch (event.code) {
                case EVENT_TYPE_ACCEL_X:
                    if (accel.x != event.value)
                        accel.changed = 1;
                    accel.x = event.value;
                    accel.mask |= EVENT_MASK_ACCEL_X;
                    break;
                case EVENT_TYPE_ACCEL_Y:
                    if (accel.y != event.value)
                        accel.changed = 1;
                    accel.y = event.value;
                    accel.mask |= EVENT_MASK_ACCEL_Y;
                    break;
                case EVENT_TYPE_ACCEL_Z:
                    if (accel.z != event.value)
                        accel.changed = 1;
                    accel.z = event.value;
                    accel.mask |= EVENT_MASK_ACCEL_Z;
                    break;
            }
        } else if (event.type == EV_SYN &&
                   accel.changed &&
                   accel.mask == EVENT_MASK_ACCEL_ALL) {
            int64_t t = event.time.tv_sec * 1000000000LL +
                        event.time.tv_usec * 1000;
            t_accel[0] = (t_accel[0] + accel.x) / 2;
			t_accel[1] = (t_accel[1] + accel.y) / 2;
			t_accel[2] = (t_accel[2] + accel.z) / 2;
            accel.mask = accel.changed = 0;
            data->time = t;
            data->sensor = SENSORS_ACCELERATION;
            data->acceleration.status = SENSOR_STATUS_ACCURACY_HIGH;
            data->acceleration.x = t_accel[0] * CONVERT_X;
            data->acceleration.y = t_accel[1] * CONVERT_Y;
            data->acceleration.z = t_accel[2] * CONVERT_Z;
            return SENSORS_ACCELERATION;
        }
    }
    return 0;
}

/* returns available sensors */
uint32_t sensors_data_get_sensors()
{
    return SENSORS_ACCELERATION;
}
