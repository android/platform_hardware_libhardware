/*
 * Copyright (C) 2017 The Android Open Source Project
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
#include "EvdevDevice.h"
#include "Utils.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <set>

/* this macro is used to tell if "bit" is set in "array"
 * it selects a byte from the array, and does a boolean AND
 * operation with a byte that only has the relevant bit set.
 * eg. to check for the 12th bit, we do (array[1] & 1<<4)
 */
#define TEST_BIT(bit, array)    ((array)[(bit)/8] & (1<<((bit)%8)))

namespace android {
namespace SensorHalExt {

EvdevDevice::EvdevDevice(
        const std::string &devName, const std::unordered_set<uint32_t> &usageSet)
        : mDevFd(-1), mDevName(devName), mValid(false) {
    // open device
    mDevFd = ::open(devName.c_str(), O_RDONLY); // read-only
    if (mDevFd < 0) {
        ALOGE("Error in open device node: %d (%s)", errno, ::strerror(errno));
        return;
    }

    // get device information
    if (!populateDeviceInfo()) {
        ALOGE("Error obtaining Evdev device information");
        return;
    }

    if (!generateDigest(usageSet)) {
        ALOGE("Cannot find sensor axis");
        return;
    }

    int32_t grab = -1;
    int32_t ret = ::ioctl(mDevFd, EVIOCGRAB, &grab);
    if (ret != 0) {
        ::ioctl(mDevFd, EVIOCGRAB, nullptr);
        ::close(mDevFd);
        mDevFd = -1;
        ALOGE("Cannot grab device");
        return;
    }

    mValid = true;
}

EvdevDevice::~EvdevDevice() {
    if (mDevFd > 0) {
        ::ioctl(mDevFd, EVIOCGRAB, NULL);
        ::close(mDevFd);
        mDevFd = -1;
    }
}

bool EvdevDevice::populateDeviceInfo() {
    EvdevDeviceInfo info = {};
    // name field is limited to 128 characters in hid_device
    char buffer[128];

    if (mDevFd < 0) {
        return false;
    }

    // name
    if (::ioctl(mDevFd, EVIOCGNAME(sizeof(buffer) - 1), buffer) < 0) {
        ALOGE("could not get device name for %s, %s", mDevName.c_str(), strerror(errno));
        return false;
    }
    buffer[sizeof(buffer) - 1] = '\0';
    info.name = buffer;

    // property
    if (::ioctl(mDevFd, EVIOCGPROP(sizeof(info.propBitmask)), info.propBitmask) < 0) {
        ALOGE("could not get device property for %s, %s", mDevName.c_str(), strerror(errno));
        return false;
    }

    // INPUT_PROP_ACCELEROMETER indicates devices with accelerometer data
    // and/or gyroscope data
    // https://www.kernel.org/doc/Documentation/input/event-codes.rst
    if (!TEST_BIT(INPUT_PROP_ACCELEROMETER, info.propBitmask)) {
        ALOGD("%s is not a sensor device", mDevName.c_str());
        return false;
    }

    // TODO: check for other non-accelerometer input properties

    // ABS axis
    if (::ioctl(mDevFd, EVIOCGBIT(EV_ABS, sizeof(info.absBitmask)), info.absBitmask) < 0) {
        ALOGE("could not get device ABS axis for %s, %s", mDevName.c_str(), strerror(errno));
        return false;
    }

    // TODO: get EV_REL bitmask if necessary

    // device identifier
    struct input_id inputId;
    if(::ioctl(mDevFd, EVIOCGID, &inputId) < 0) {
        ALOGE("could not get device input id for %s, %s", mDevName.c_str(), strerror(errno));
        return false;
    }
    switch (inputId.bustype) {
    case BUS_USB:
        info.busType = "USB";
        break;
    case BUS_HIL:
        info.busType = "HIL";
        break;
    case BUS_BLUETOOTH:
        info.busType = "Bluetooth";
        break;
    case BUS_VIRTUAL:
        info.busType = "Virtual";
        break;
    default:
        info.busType = "Other";
        break;
    }
    info.product = inputId.product;
    info.vendor = inputId.vendor;
    info.version = inputId.version;

    // physical path
    if (::ioctl(mDevFd, EVIOCGPHYS(sizeof(buffer) - 1), buffer) < 1) {
        ALOGE("could not get device location for %s, %s", mDevName.c_str(), strerror(errno));
        return false;
    }
    buffer[sizeof(buffer) - 1] = '\0';
    info.physicalPath = buffer;

    // unique id
    if(::ioctl(mDevFd, EVIOCGUNIQ(sizeof(buffer) - 1), &buffer) < 1) {
        ALOGE("could not get device unique id for %s, %s", mDevName.c_str(), strerror(errno));
        return false;
    }
    buffer[sizeof(buffer) - 1] = '\0';
    info.uniqueId = buffer;

    mDeviceInfo = info;

    return true;
}

bool EvdevDevice::generateDigest(const std::unordered_set<uint32_t> &usageSet) {
    using namespace EvdevSensorTypeUsage;
    using namespace EvdevSensorAxis;
    for (const auto &usage : usageSet) { // for each usage
        switch (usage) {
            case ACCELEROMETER_3D:
                if (TEST_BIT(ACCELERATION_X_AXIS, mDeviceInfo.absBitmask)
                        || TEST_BIT(ACCELERATION_Y_AXIS, mDeviceInfo.absBitmask)
                        || TEST_BIT(ACCELERATION_Z_AXIS, mDeviceInfo.absBitmask)) {
                    mDigestVector.emplace_back(usage);
                }
                break;
            case GYROMETER_3D:
                if (TEST_BIT(ANGULAR_VELOCITY_X_AXIS, mDeviceInfo.absBitmask)
                        || TEST_BIT(ANGULAR_VELOCITY_Y_AXIS, mDeviceInfo.absBitmask)
                        || TEST_BIT(ANGULAR_VELOCITY_Z_AXIS, mDeviceInfo.absBitmask)) {
                    mDigestVector.emplace_back(usage);
                }
                break;
            default:
                ALOGV("unsupported usage %d", usage);
        }
    }
    mDigestVector.shrink_to_fit();

    return mDigestVector.size() > 0;
}

bool EvdevDevice::isValid() {
    return mValid;
}

bool EvdevDevice::getAbsoluteAxisInfo(uint8_t axis, input_absinfo* outAxisInfo) const {
    if (mDevFd < 0) {
        return false;
    }

    memset(outAxisInfo, 0, sizeof(outAxisInfo));

    if (axis < 0 || axis > ABS_MAX) {
        return false;
    }

    if(::ioctl(mDevFd, EVIOCGABS(axis), outAxisInfo)) {
        ALOGE("EvdevDevice::getAbsoluteAxisInfo: "
                "get axis info %d error for device %s, errno=%d",
                axis, mDeviceInfo.name.c_str(), errno);
        return false;
    }

    return true;
}

int EvdevDevice::hasEvent(uint16_t timeoutMs)
{
    fd_set fd;
    FD_ZERO(&fd);
    FD_SET(mDevFd, &fd);
    int nfds = mDevFd + 1;

    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000)*1000;

    int result = ::select(nfds, &fd, NULL, NULL, &tv);

    return result;
}

int EvdevDevice::receiveEvent(struct input_event *event, size_t eventSize) {
    if (mDevFd < 0) {
        return -1;
    }

    // Wait for event up to 17ms, to be roughly aligned with 60fps
    const uint16_t timeOutInMs = 17;
    int eventPending = hasEvent(timeOutInMs);

    int32_t ret = 0;
    if (eventPending <= 0)
        return 0;

    ret = ::read(mDevFd, event, eventSize);

    if (ret < 0) {
        if (errno == EAGAIN) {
            // This does not really mean a disconnect, so just return true
            return 0;
        } else {
            ALOGE("Error in reading device node: %d (%s)", errno, ::strerror(errno));
            // This usually means a disconnect, return false
            return -1;
        }
    }

    return ret;
}

} // namespace SensorHalExt
} // namespace android
