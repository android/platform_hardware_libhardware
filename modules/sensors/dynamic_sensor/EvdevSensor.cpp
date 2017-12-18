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
#include "EvdevSensor.h"

#include <utils/Errors.h>

#include <algorithm>
#include <cfloat>
#include <codecvt>
#include <iomanip>
#include <sstream>

namespace android {
namespace SensorHalExt {

namespace {
const std::string CUSTOM_TYPE_PREFIX("com.google.hardware.sensor.evdev_dynamic.");
}

EvdevSensor::EvdevSensor(
        SP(EvdevDevice) device, uint32_t usage, input_absinfo &axisInfo)
        : mUsage(-1), mEnabled(false), mDevice(device), mValid(false) {
    if (device == nullptr) {
        return;
    }
    memset(&mSensor, 0, sizeof(mSensor));

    const EvdevDevice::EvdevDeviceInfo &info = device->getDeviceInfo();
    initFeatureValueFromEvdevDeviceInfo(&mFeatureInfo, info, axisInfo);

    // build translation table
    mUsage = usage;
    using namespace EvdevSensorTypeUsage;
    using namespace EvdevSensorAxis;
    switch (usage) {
        case ACCELEROMETER_3D:
            // Hid unit default g
            // Android unit m/s^2
            // 1g = 9.81 m/s^2
            mFeatureInfo.typeString = SENSOR_STRING_TYPE_ACCELEROMETER;
            mFeatureInfo.type = SENSOR_TYPE_ACCELEROMETER;
            mFeatureInfo.isWakeUp = false;

            processTriAxisUsage(ACCELERATION_X_AXIS,
                                ACCELERATION_Y_AXIS,
                                ACCELERATION_Z_AXIS, 9.81);
            break;
        case GYROMETER_3D:
            // Hid unit default degree/s
            // Android unit rad/s
            // 1 degree/s = pi/180 rad/s
            mFeatureInfo.typeString = SENSOR_STRING_TYPE_GYROSCOPE;
            mFeatureInfo.type = SENSOR_TYPE_GYROSCOPE;
            mFeatureInfo.isWakeUp = false;

            processTriAxisUsage(ANGULAR_VELOCITY_X_AXIS,
                                ANGULAR_VELOCITY_Y_AXIS,
                                ANGULAR_VELOCITY_Z_AXIS, M_PI/180);
            break;
        default:
            ALOGI("unsupported sensor usage %d", usage);
    }

    mValid = validateFeatureValueAndBuildSensor();
    ALOGV("EvdevSensor init, mValid: %s", (mValid ? "true" : "false"));
}

void EvdevSensor::processTriAxisUsage(uint16_t axis0, uint16_t axis1, uint16_t axis2,
            double defaultScaling) {
    // scale resolution
    mFeatureInfo.resolution = mFeatureInfo.resolution * defaultScaling;

    EventTranslateRecord record = {
        .minValue = mFeatureInfo.minValue,
        .maxValue = mFeatureInfo.maxValue,
        .type = TYPE_FLOAT
    };

    mData.emplace(axis0, 0);
    mData.emplace(axis1, 0);
    mData.emplace(axis2, 0);

    //
    // It is assumed all Evdev sensors already follow a right-handed coordinate system.
    // If a user is facing a device, report values should increase as controls are
    // moved from left to right (X), from far to near (Y) and from high to low (Z).
    //

    record.index = 0;
    record.eventCode = axis0;
    record.a = mFeatureInfo.resolution;
    record.b = 0;
    mTranslateTable.push_back(record);

    record.index = 1;
    record.eventCode = axis1;
    record.a = mFeatureInfo.resolution;
    record.b = 0;
    mTranslateTable.push_back(record);

    record.index = 2;
    record.eventCode = axis2;
    record.a = mFeatureInfo.resolution;
    record.b = 0;
    mTranslateTable.push_back(record);

    mTranslateTable.shrink_to_fit();
}

void EvdevSensor::initFeatureValueFromEvdevDeviceInfo(
        FeatureValue *featureValue, const EvdevDevice::EvdevDeviceInfo &info,
        input_absinfo &axisInfo) {
    featureValue->name = info.name;

    std::ostringstream ss;
    ss << info.busType << " "
       << std::hex << std::setfill('0') << std::setw(4) << info.vendor
       << ":" << std::setw(4) << info.product;
    featureValue->vendor = ss.str();

    featureValue->permission = "";
    featureValue->typeString = "";
    featureValue->type = -1; // invalid type
    featureValue->version = info.version;

    featureValue->minValue = axisInfo.minimum;
    featureValue->maxValue = axisInfo.maximum;
    featureValue->maxRange = std::max(std::abs(axisInfo.maximum), std::abs(axisInfo.minimum));
    featureValue->resolution = 1.f/(float)axisInfo.resolution;
    featureValue->power = 1.f; // default value, does not have a valid source yet

    featureValue->minDelay = 0;
    featureValue->maxDelay = 0;

    featureValue->fifoSize = 0;
    featureValue->fifoMaxSize = 0;

    featureValue->reportModeFlag = SENSOR_FLAG_ON_CHANGE_MODE;
    featureValue->isWakeUp = true;

    featureValue->uniqueId = info.uniqueId;
    memset(featureValue->uuid, 0, sizeof(featureValue->uuid));
    featureValue->isAndroidCustom = false;
}

bool EvdevSensor::validateFeatureValueAndBuildSensor() {
    if (mFeatureInfo.name.empty() || mFeatureInfo.vendor.empty() || mFeatureInfo.typeString.empty()
            || mFeatureInfo.type <= 0 || mFeatureInfo.maxRange <= 0
            || mFeatureInfo.resolution <= 0) {
        return false;
    }

    if (mFeatureInfo.maxValue < mFeatureInfo.minValue) {
        return false;
    }

    switch (mFeatureInfo.reportModeFlag) {
        case SENSOR_FLAG_CONTINUOUS_MODE:
        case SENSOR_FLAG_ON_CHANGE_MODE:
            if (mFeatureInfo.minDelay < 0) {
                return false;
            }
            if (mFeatureInfo.maxDelay != 0 && mFeatureInfo.maxDelay < mFeatureInfo.minDelay) {
                return false;
            }
            break;
        case SENSOR_FLAG_ONE_SHOT_MODE:
            if (mFeatureInfo.minDelay != -1 && mFeatureInfo.maxDelay != 0) {
                return false;
            }
            break;
        case SENSOR_FLAG_SPECIAL_REPORTING_MODE:
            if (mFeatureInfo.minDelay != -1 && mFeatureInfo.maxDelay != 0) {
                return false;
            }
            break;
        default:
            break;
    }

    if (mFeatureInfo.fifoMaxSize != 0
            && mFeatureInfo.fifoMaxSize < mFeatureInfo.fifoSize) {
        return false;
    }

    // initialize uuid field, use name, vendor and uniqueId
    if (mFeatureInfo.name.size() >= 4
            && mFeatureInfo.vendor.size() >= 4
            && mFeatureInfo.typeString.size() >= 4
            && mFeatureInfo.uniqueId.size() >= 4) {
        uint32_t tmp[4], h;
        std::hash<std::string> stringHash;
        h = stringHash(mFeatureInfo.uniqueId);
        tmp[0] = stringHash(mFeatureInfo.name) ^ h;
        tmp[1] = stringHash(mFeatureInfo.vendor) ^ h;
        tmp[2] = stringHash(mFeatureInfo.typeString) ^ h;
        tmp[3] = tmp[0] ^ tmp[1] ^ tmp[2];
        memcpy(mFeatureInfo.uuid, tmp, sizeof(mFeatureInfo.uuid));
    }

    mSensor = (sensor_t) {
        mFeatureInfo.name.c_str(),                 // name
        mFeatureInfo.vendor.c_str(),               // vendor
        mFeatureInfo.version,                      // version
        -1,                                        // handle, dummy number here
        mFeatureInfo.type,
        mFeatureInfo.maxRange,                     // maxRange
        mFeatureInfo.resolution,                   // resolution
        mFeatureInfo.power,                        // power
        mFeatureInfo.minDelay,                     // minDelay
        (uint32_t)mFeatureInfo.fifoSize,           // fifoReservedEventCount
        (uint32_t)mFeatureInfo.fifoMaxSize,        // fifoMaxEventCount
        mFeatureInfo.typeString.c_str(),           // type string
        mFeatureInfo.permission.c_str(),           // requiredPermission
        (long)mFeatureInfo.maxDelay,               // maxDelay
        mFeatureInfo.reportModeFlag | (mFeatureInfo.isWakeUp ? 1 : 0),
        { NULL, NULL }
    };
    return true;
}

const sensor_t* EvdevSensor::getSensor() const {
    return &mSensor;
}

void EvdevSensor::getUuid(uint8_t* uuid) const {
    memcpy(uuid, mFeatureInfo.uuid, sizeof(mFeatureInfo.uuid));
}

int EvdevSensor::enable(bool enable) {
    SP(EvdevDevice) device = PROMOTE(mDevice);

    if (device == nullptr) {
        return NO_INIT;
    }

    mEnabled = enable;
    return NO_ERROR;
}

int EvdevSensor::batch(int64_t /*samplingPeriod*/, int64_t /*batchingPeriod*/) {
    // EvdevSensor does not support changing rate and batching. But return successful anyway.
    return 0;
}

void EvdevSensor::storeInput(const uint16_t code, const int32_t value) {
    using namespace EvdevSensorTypeUsage;
    switch (mUsage) {
        case ACCELEROMETER_3D:
        case GYROMETER_3D:
            mData[code] = value;
            break;
    }
}

void EvdevSensor::handleInput(const bool timestampValid, const int32_t timestamp) {
    sensors_event_t event = {
        .version = sizeof(event),
        .sensor = -1,
        .type = mSensor.type
    };
    bool valid = true;

    for (auto &rec : mTranslateTable) {
        int32_t v = mData[rec.eventCode];
        switch (rec.type) {
            case TYPE_FLOAT:
                if (v > rec.maxValue || v < rec.minValue) {
                    valid = false;
                }
                event.data[rec.index] = rec.a * (v + rec.b);
                break;
            case TYPE_INT64: // currently not used
                if (v > rec.maxValue || v < rec.minValue) {
                    valid = false;
                }
                event.u64.data[rec.index] = v + rec.b;
                break;
            case TYPE_ACCURACY: // currently not used
                event.magnetic.status = (v & 0xFF) + rec.b;
                break;
        }
    }

    if (!valid) {
        ALOGV("Range error observed in decoding, discard");
    }

    if (timestampValid) {
        event.timestamp = timestamp;
    } else {
        event.timestamp = -1;
    }
    generateEvent(event);
}

std::string EvdevSensor::dump() const {
    std::ostringstream ss;
    ss << "Feature Values " << std::endl
          << "  name: " << mFeatureInfo.name << std::endl
          << "  vendor: " << mFeatureInfo.vendor << std::endl
          << "  permission: " << mFeatureInfo.permission << std::endl
          << "  typeString: " << mFeatureInfo.typeString << std::endl
          << "  type: " << mFeatureInfo.type << std::endl
          << "  maxRange: " << mFeatureInfo.maxRange << std::endl
          << "  resolution: " << mFeatureInfo.resolution << std::endl
          << "  power: " << mFeatureInfo.power << std::endl
          << "  minDelay: " << mFeatureInfo.minDelay << std::endl
          << "  maxDelay: " << mFeatureInfo.maxDelay << std::endl
          << "  fifoSize: " << mFeatureInfo.fifoSize << std::endl
          << "  fifoMaxSize: " << mFeatureInfo.fifoMaxSize << std::endl
          << "  reportModeFlag: " << mFeatureInfo.reportModeFlag << std::endl
          << "  isWakeUp: " << (mFeatureInfo.isWakeUp ? "true" : "false") << std::endl
          << "  uniqueId: " << mFeatureInfo.uniqueId << std::endl
          << "  uuid: ";

    ss << std::hex << std::setfill('0');
    for (auto d : mFeatureInfo.uuid) {
          ss << std::setw(2) << static_cast<int>(d) << " ";
    }
    ss << std::dec << std::setfill(' ') << std::endl;

    ss << "Usage: " << mUsage << std::endl;
    for (const auto &t : mTranslateTable) {
        ss << "  type, index: " << t.type << ", " << t.index
              << "; min,max: " << t.minValue << ", " << t.maxValue
              << "; scaling,bias: " << t.a << ", " << t.b
              << "; code: " << t.eventCode << std::endl;
    }

    return ss.str();
}

} // namespace SensorHalExt
} // namespace android
