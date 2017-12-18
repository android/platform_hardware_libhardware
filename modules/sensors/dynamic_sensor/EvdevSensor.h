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
#ifndef ANDROID_SENSORHAL_EXT_EVDEV_SENSOR_H
#define ANDROID_SENSORHAL_EXT_EVDEV_SENSOR_H

#include "BaseSensorObject.h"
#include "EvdevDevice.h"
#include "Utils.h"

#include <hardware/sensors.h>

#include <unordered_map>

namespace android {
namespace SensorHalExt {

class EvdevSensor : public BaseSensorObject {
    friend class EvdevSensorTest;
    friend class EvdevDeviceTest;
public:
    EvdevSensor(SP(EvdevDevice) device, uint32_t usage, input_absinfo &axisInfo);

    // implements BaseSensorObject
    virtual const sensor_t* getSensor() const;
    virtual void getUuid(uint8_t* uuid) const;
    virtual int enable(bool enable);
    virtual int batch(int64_t samplePeriod, int64_t batchPeriod); // unit nano-seconds

    // store and handle input event received
    void storeInput(const uint16_t code, const int32_t value);
    void handleInput(const bool timestampValid, const int32_t timestamp);

    // indicate if the EvdevSensor is a valid one
    bool isValid() const { return mValid; };

private:

    // structure used for holding descriptor parse result for each report field
    enum {
        TYPE_FLOAT,
        TYPE_INT64,
        TYPE_ACCURACY
    };
    struct EventTranslateRecord {
        int type;
        int index;
        int64_t maxValue;
        int64_t minValue;
        double a;
        int64_t b;
        int16_t eventCode;
    };

    // sensor related information parsed from HID descriptor
    struct FeatureValue {
        // information needed to furnish sensor_t structure (see hardware/sensors.h)
        std::string name;
        std::string vendor;
        std::string permission;
        std::string typeString;
        int32_t type;
        int version;
        int64_t maxValue;
        int64_t minValue;
        float maxRange;
        float resolution;
        float power;
        int32_t minDelay;
        int64_t maxDelay;
        size_t fifoSize;
        size_t fifoMaxSize;
        uint32_t reportModeFlag;
        bool isWakeUp;

        // dynamic sensor specific
        std::string uniqueId;
        uint8_t uuid[16];

        // if the device is custom sensor HID device that furnished android specific descriptors
        bool isAndroidCustom;
    };

    // initialize default feature values default based on hid device info
    static void initFeatureValueFromEvdevDeviceInfo(
            FeatureValue *featureValue, const EvdevDevice::EvdevDeviceInfo &info,
            input_absinfo &axisInfo);

    // validate feature values and construct sensor_t structure if values are ok.
    bool validateFeatureValueAndBuildSensor();

    // process three axis sensors usages: accel, gyro.
    void processTriAxisUsage(uint16_t axis0, uint16_t axis1, uint16_t axis2,
            double defaultScaling = 1);

    // dump data for test/debug purpose
    std::string dump() const;

    // Input data <eventCode, value>
    std::unordered_map<int16_t, int32_t> mData;

    // Input data translate table
    std::vector<EventTranslateRecord> mTranslateTable;
    uint32_t mUsage;

    FeatureValue mFeatureInfo;
    sensor_t mSensor;

    // runtime states variable
    bool mEnabled;

    WP(EvdevDevice) mDevice;
    bool mValid;
};

} // namespace SensorHalExt
} // namespace android
#endif // ANDROID_SENSORHAL_EXT_EVDEV_SENSOR_H
