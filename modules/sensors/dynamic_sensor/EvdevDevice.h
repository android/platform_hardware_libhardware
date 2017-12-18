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
#ifndef ANDROID_SENSORHAL_EXT_EVDEV_DEVICE_H
#define ANDROID_SENSORHAL_EXT_EVDEV_DEVICE_H

#include "Utils.h"

#include <linux/input.h>
#include <string>
#include <unordered_set>
#include <utils/Log.h>
#include <vector>

namespace android {
namespace SensorHalExt {

namespace EvdevSensorTypeUsage {
enum {
    ACCELEROMETER_3D = 0x200073,
    GYROMETER_3D = 0x200076,
};
} // namespace EvdevSensorTypeUsage

namespace EvdevSensorAxis {
enum {
    ACCELERATION_X_AXIS = ABS_X,
    ACCELERATION_Y_AXIS = ABS_Y,
    ACCELERATION_Z_AXIS = ABS_Z,
    ANGULAR_VELOCITY_X_AXIS = ABS_RX,
    ANGULAR_VELOCITY_Y_AXIS = ABS_RY,
    ANGULAR_VELOCITY_Z_AXIS = ABS_RZ,
};
} // namespace EvdevSensorAxis

class EvdevDevice : virtual public REF_BASE(EvdevDevice) {
    friend class EvdevDeviceTest;
public:
    EvdevDevice(const std::string &devName, const std::unordered_set<uint32_t> &usageSet);

    ~EvdevDevice();

    struct EvdevDeviceInfo {
        std::string name;
        std::string physicalPath;
        std::string uniqueId;
        std::string busType;
        uint16_t vendor;
        uint16_t product;
        uint16_t version;
        uint8_t propBitmask[(INPUT_PROP_MAX + 1) / 8];
        uint8_t absBitmask[(ABS_MAX + 1) / 8];
    };

    const EvdevDeviceInfo& getDeviceInfo() { return mDeviceInfo; }

    bool getAbsoluteAxisInfo(uint8_t axis, input_absinfo* outAxisInfo) const;

    // receive from default input endpoint
    int hasEvent(uint16_t timeout);
    int receiveEvent(struct input_event *event, size_t eventSize);

    // test if the device initialized successfully
    bool isValid();

protected:
    bool populateDeviceInfo();
    bool generateDigest(const std::unordered_set<uint32_t> &usage);

    std::vector<unsigned int> mDigestVector;
private:
    int mDevFd;
    std::string mDevName;
    EvdevDeviceInfo mDeviceInfo;
    int mValid;

    EvdevDevice(const EvdevDevice &) = delete;
    void operator=(const EvdevDevice &) = delete;
};

} // namespace SensorHalExt
} // namespace android

#endif // ANDROID_SENSORHAL_EXT_EVDEV_DEVICE_H
