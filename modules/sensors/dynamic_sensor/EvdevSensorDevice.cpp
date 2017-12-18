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

#include "EvdevSensorDevice.h"
#include "EvdevSensor.h"

#include <utils/Log.h>
#include <utils/SystemClock.h>
#include <fcntl.h>
#include <linux/input.h>

#include <set>

namespace android {
namespace SensorHalExt {

using namespace EvdevSensorTypeUsage;
using namespace EvdevSensorAxis;

const std::unordered_set<uint32_t> EvdevSensorDevice::sInterested{
        ACCELEROMETER_3D, GYROMETER_3D};

sp<EvdevSensorDevice> EvdevSensorDevice::create(const std::string &devName) {
    sp<EvdevSensorDevice> device(new EvdevSensorDevice(devName));
    // offset +1 strong count added by constructor
    device->decStrong(device.get());

    if (device->mValid) {
        return device;
    } else {
        return nullptr;
    }
}

EvdevSensorDevice::EvdevSensorDevice(const std::string &devName)
        : RefBase(), EvdevDevice(devName, sInterested),
          Thread(false /*canCallJava*/), mValid(false) {
    // create EvdevSensor objects from digest
    // EvdevSensor object will take sp<EvdevSensorDevice> as parameter, so increment strong count
    // to prevent "this" being destructed.
    this->incStrong(this);

    if (!EvdevDevice::isValid()) {
        return;
    }

    for (const auto &digest : mDigestVector) { // for each usage
        input_absinfo axisInfo;
        memset(&axisInfo, 0, sizeof(axisInfo));
        switch (digest) {
            case ACCELEROMETER_3D:
                if (getTriAbsoluteAxisInfo(&axisInfo,
                        ACCELERATION_X_AXIS,
                        ACCELERATION_Y_AXIS,
                        ACCELERATION_Z_AXIS)) {
                    sp<EvdevSensor> s(new EvdevSensor(this, digest, axisInfo));
                    if (s->isValid()) {
                        mSensors.emplace(digest, s);
                    }
                }
                break;
            case GYROMETER_3D:
                if (getTriAbsoluteAxisInfo(&axisInfo,
                        ANGULAR_VELOCITY_X_AXIS,
                        ANGULAR_VELOCITY_Y_AXIS,
                        ANGULAR_VELOCITY_Z_AXIS)) {
                    sp<EvdevSensor> s(new EvdevSensor(this, digest, axisInfo));
                    if (s->isValid()) {
                        mSensors.emplace(digest, s);
                    }
                }
                break;
            default:
                ALOGV("unsupported sensor usage %d", digest);
        }
    }

    if (mSensors.size() == 0) {
        ALOGV("No sensors found");
        return;
    }

    run("EvdevSensor");
    mValid = true;
}

EvdevSensorDevice::~EvdevSensorDevice() {
    ALOGV("~EvdevSensorDevice %p", this);
    requestExitAndWait();
    ALOGV("~EvdevSensorDevice %p, thread exited", this);
}

bool EvdevSensorDevice::threadLoop() {
    ALOGV("Evdev Device thread started %p", this);
    int ret;

    struct input_event event[32];
    uint32_t prevMscTimestamp = 0;
    bool timestampValid = false;
    int64_t timestamp = 0;
    while(!Thread::exitPending()) {
        ret = receiveEvent(event, sizeof(event));
        if (ret < 0) {
            break;
        } else if (ret == 0) {
            continue;
        }

        // Process each event
        const int numEvents = ret / sizeof(struct input_event);
        for (int idx = 0; idx < numEvents; ++idx) {
            const input_event& inputEvent = event[idx];

            if (inputEvent.type == EV_ABS) {
                switch (inputEvent.code) {
                    case ACCELERATION_X_AXIS:
                    case ACCELERATION_Y_AXIS:
                    case ACCELERATION_Z_AXIS:
                        {
                            //store value
                            auto s = mSensors.find(ACCELEROMETER_3D);
                            if (s == mSensors.end()) {
                                ALOGW("Input of unknown input event code %u received",
                                        inputEvent.code);
                                continue;
                            }
                            s->second->storeInput(inputEvent.code, inputEvent.value);
                        }
                        break;
                    case ANGULAR_VELOCITY_X_AXIS:
                    case ANGULAR_VELOCITY_Y_AXIS:
                    case ANGULAR_VELOCITY_Z_AXIS:
                        {
                            //store value
                            auto s = mSensors.find(GYROMETER_3D);
                            if (s == mSensors.end()) {
                                ALOGW("Input of unknown input event code %u received",
                                        inputEvent.code);
                                continue;
                            }
                            s->second->storeInput(inputEvent.code, inputEvent.value);
                        }
                        break;
                    default:
                        // do not care about others
                        break;
                }
            // Some input devices have a better concept of the time when an input event
            // was actually generated, compared to the Android framework or kernel
            // which simply timestamps all events on entry.
            } else if (inputEvent.type == EV_MSC && inputEvent.code == MSC_TIMESTAMP) {
                if (!timestampValid) {
                    timestamp = elapsedRealtimeNano();
                    timestampValid = true;
                } else {
                    // add MSC_TIMESTAMP delta (in us) to real time (in ns)
                    uint32_t dt = (prevMscTimestamp > (uint32_t)inputEvent.value) ?
                                  (UINT32_MAX - prevMscTimestamp + (uint32_t)inputEvent.value + 1) :
                                  ((uint32_t)inputEvent.value - prevMscTimestamp);
                    timestamp += dt * 1000;
                }
                prevMscTimestamp = (uint32_t)inputEvent.value;
            } else if (inputEvent.type == EV_SYN && inputEvent.code == SYN_REPORT) {
                //TODO: need to handle SYN_DROPPED
                // go through all mSensors
                for (const auto &s : mSensors) {
                    s.second->handleInput(timestampValid, timestamp);
                }
            } else {
                // omit the rest
            }
        }
    }

    ALOGI("Evdev Device thread ended for %p", this);
    return false;
}

bool EvdevSensorDevice::getTriAbsoluteAxisInfo(input_absinfo* outAxisInfo,
        uint8_t axis1, uint8_t axis2, uint8_t axis3) const {
    bool axis1Valid = getAbsoluteAxisInfo(axis1, outAxisInfo);
    input_absinfo axis2Info;
    bool axis2Valid = getAbsoluteAxisInfo(axis2, &axis2Info);
    input_absinfo axis3Info;
    bool axis3Valid = getAbsoluteAxisInfo(axis3, &axis3Info);

    if (!axis1Valid || !axis2Valid || !axis3Valid) {
        ALOGE("Three axis sensor does not find all 3 axis");
        return false;
    }

    if (outAxisInfo->minimum >= outAxisInfo->maximum
            || outAxisInfo->minimum != axis2Info.minimum
            || outAxisInfo->maximum != axis2Info.maximum
            || axis2Info.minimum != axis3Info.minimum
            || axis2Info.maximum != axis3Info.maximum) {
        ALOGE("All 3 axis should have same min and max value and min must < max");
        return false;
    }

    if (outAxisInfo->resolution != axis2Info.resolution
            || axis2Info.resolution != axis3Info.resolution) {
        ALOGE("All 3 axis should have same resolution");
        return false;
    }

    return true;
}

BaseSensorVector EvdevSensorDevice::getSensors() const {
    BaseSensorVector ret;
    std::set<sp<BaseSensorObject>> set;
    for (const auto &s : mSensors) {
        if (set.find(s.second) == set.end()) {
            ret.push_back(s.second);
            set.insert(s.second);
        }
    }
    return ret;
}

} // namespace SensorHalExt
} // namespace android
