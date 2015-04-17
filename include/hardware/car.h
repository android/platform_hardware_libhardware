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

#ifndef ANDROID_CAR_INTERFACE_H
#define ANDROID_CAR_INTERFACE_H

#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>

#include <hardware/hardware.h>
#include <cutils/native_handle.h>

__BEGIN_DECLS

/*****************************************************************************/

#define CAR_HEADER_VERSION          1
#define CAR_MODULE_API_VERSION_0_1  HARDWARE_MODULE_API_VERSION(0, 1)
#define CAR_DEVICE_API_VERSION_0_1  HARDWARE_DEVICE_API_VERSION_2(0, 1, CAR_HEADER_VERSION)


// ***** TODO:  CAR HAL wants a spiffy developer webpage too! *****
/*
 * Please see the Sensors section of source.android.com for an
 * introduction to and detailed descriptions of Android sensor types:
 * http://source.android.com/devices/sensors/index.html
 */

/*
 * The id of this module
 */
#define CAR_HARDWARE_MODULE_ID  "car"

/*
 *  Name of the car device to open
 */
#define CAR_HARDWARE_DEVICE     "car_device"

/*
 * Availability: CAR_DEVICE_API_VERSION_0_1
 * Car flags used in subscribe().
 */
enum {
    /*
     * Reporting modes for various sensors.  Each sensor will have exactly one
     * of these modes set.
     */
    CAR_FLAG_CONTINUOUS_MODE        = 0x1,
    CAR_FLAG_ONE_SHOT_MODE          = 0x2,
    CAR_FLAG_TRIGGER_MODE           = 0x4,
    CAR_FLAG_MODE_MASK              = 0x7,

    /*
     * Format of property
     */
    CAR_FLAG_FORMAT_STRING          = 0x00,
    CAR_FLAG_FORMAT_FLOAT           = 0x08,
    CAR_FLAG_FORMAT_SIGNED_INT      = 0x10,
    CAR_FLAG_FORMAT_UNSIGNED_INT    = 0x18,
    CAR_FLAG_FORMAT_MASK            = 0x18,

    /*
     * Access flag.  All properties have read access, only some are writable.
     */
    CAR_FLAG_ACCESS_WRITE           = 0x20

} car_subscribe_flag;

typedef union {
    float    f;
    char     *s;
#ifdef __LP64__
    int64_t  i;
    uint64_t u;
#else
    int32_t  i;
    uint32_t u;
#endif
} car_value_t;


/*
 * Vehicle Information
 */
#define CAR_PROPERTY_INFO_VIN                                   (0x00000100)
#define CAR_PROPERTY_INFO_VIN_STRING                            "android.car.info.vin"
#define CAR_PROPERTY_INFO_MAKE                                  (0x00000101)
#define CAR_PROPERTY_INFO_MAKE_STRING                           "android.car.info.make"
#define CAR_PROPERTY_INFO_MODEL                                 (0x00000102)
#define CAR_PROPERTY_INFO_MODEL_STRING                          "android.car.info.model"
#define CAR_PROPERTY_INFO_MANUFACTURE_DATE                      (0x00000103)
#define CAR_PROPERTY_INFO_MANUFACTURE_DATE_STRING               "android.car.info.manufacture_date"
#define CAR_PROPERTY_INFO_FUEL_CAPACITY                         (0x00000104)
#define CAR_PROPERTY_INFO_FUEL_CAPACITY_STRING                  "android.car.info.fuel_capacity"

/*
 * Vehicle Performance Sensors
 */
#define CAR_PROPERTY_PERF_AVERAGE_FUEL_ECONOMY                  (0x00000200)
#define CAR_PROPERTY_PERF_AVERAGE_FUEL_ECONOMY_STRING           "android.car.perf.avg_fuel_economy"
#define CAR_PROPERTY_PERF_ESTIMATED_RANGE                       (0x00000201)
#define CAR_PROPERTY_PERF_ESTIMATED_RANGE_STRING                "android.car.perf.estimated_range"
#define CAR_PROPERTY_PERF_FUEL_LEVEL                            (0x00000202)
#define CAR_PROPERTY_PERF_FUEL_LEVEL_STRING                     "android.car.perf.fuel_level"
#define CAR_PROPERTY_PERF_INSTANTANEOUS_FUEL_ECONOMY            (0x00000203)
#define CAR_PROPERTY_PERF_INSTANTANEOUS_FUEL_ECONOMY_STRING     "android.car.perf.instantaneous_fuel_economy"
#define CAR_PROPERTY_PERF_ODOMETER                              (0x00000204)
#define CAR_PROPERTY_PERF_ODOMETER_STRING                       "android.car.perf.odometer"
#define CAR_PROPERTY_PERF_STEERING_ANGLE                        (0x00000205)
#define CAR_PROPERTY_PERF_STEERING_ANGLE_STRING                 "android.car.perf.steering_angle"
#define CAR_PROPERTY_PERF_TIME_TO_NEXT_SERVICE                  (0x00000206)
#define CAR_PROPERTY_PERF_TIME_TO_NEXT_SERVICE_STRING           "android.car.perf.time_to_next_service"
#define CAR_PROPERTY_PERF_VEHICLE_SPEED                         (0x00000207)
#define CAR_PROPERTY_PERF_VEHICLE_SPEED_STRING                  "android.car.perf.vehicle_speed"
#define CAR_PROPERTY_PERF_WHEEL_SLIP                            (0x00000208)
#define CAR_PROPERTY_PERF_WHEEL_SLIP_STRING                     "android.car.perf.wheel_slip"

/*
 * Engine Sensors
 */
#define CAR_PROPERTY_ENGINE_COOLANT_LEVEL                       (0x00000300)
#define CAR_PROPERTY_ENGINE_COOLANT_LEVEL_STRING                "android.car.engine.coolant_level"
#define CAR_PROPERTY_ENGINE_COOLANT_TEMP                        (0x00000301)
#define CAR_PROPERTY_ENGINE_COOLANT_TEMP_STRING                 "android.car.engine.coolant_temp"
#define CAR_PROPERTY_ENGINE_OIL_LEVEL                           (0x00000302)
#define CAR_PROPERTY_ENGINE_OIL_LEVEL_STRING                    "android.car.engine.oil_level"
#define CAR_PROPERTY_ENGINE_OIL_PRESSURE                        (0x00000303)
#define CAR_PROPERTY_ENGINE_OIL_PRESSURE_STRING                 "android.car.engine.oil_pressure"
#define CAR_PROPERTY_ENGINE_OIL_TEMP                            (0x00000304)
#define CAR_PROPERTY_ENGINE_OIL_TEMP_STRING                     "android.car.engine.oil_temp"
#define CAR_PROPERTY_ENGINE_RPM                                 (0x00000305)
#define CAR_PROPERTY_ENGINE_RPM_STRING                          "android.car.engine.rpm"

/*
 * Event Sensors
 */
#define CAR_PROPERTY_GEAR_SELECTION                             (0x00000400)
#define CAR_PROPERTY_GEAR_SELECTION_STRING                      "android.car.property.gear_selection"
#define CAR_PROPERTY_CURRENT_GEAR                               (0x00000401)
#define CAR_PROPERTY_CURRENT_GEAR_STRING                        "android.car.property.current_gear"
#define CAR_PROPERTY_PARKING_BRAKE_SET                          (0x00000402)
#define CAR_PROPERTY_PARKING_BRAKE_SET_STRING                   "android.car.property.parking_brake_set"
#define CAR_PROPERTY_CRUISE_CONTROL_STATUS                      (0x00000403)
#define CAR_PROPERTY_CRUISE_CONTROL_STATUS_STRING               "android.car.property.cruise_control_status"
#define CAR_PROPERTY_CRUISE_CONTROL_SET_SPEED                   (0x00000404)
#define CAR_PROPERTY_CRUISE_CONTROL_SET_SPEED_STRING            "android.car.property.cruise_control_set_speed"
#define CAR_PROPERTY_FUEL_LEVEL_LOW                             (0x00000405)
#define CAR_PROPERTY_FUEL_LEVEL_LOW_STRING                      "android.car.property.fuel_level_low"
#define CAR_PROPERTY_HEAD_LIGHT_MODE                            (0x00000406)
#define CAR_PROPERTY_HEAD_LIGHT_MODE_STRING                     "android.car.property.head_light_mode"
#define CAR_PROPERTY_NIGHT_MODE                                 (0x00000407)
#define CAR_PROPERTY_NIGHT_MODE_STRING                          "android.car.property.night_mode"
#define CAR_PROPERTY_TURN_SIGNALS                               (0x00000408)
#define CAR_PROPERTY_TURN_SIGNALS_STRING                        "android.car.property.turn_signals"
#define CAR_PROPERTY_WIPER_STATE                                (0x00000409)
#define CAR_PROPERTY_WIPER_STATE_STRING                         "android.car.property.wiper_state"
#define CAR_PROPERTY_ENGINE_ON                                  (0x0000040A)
#define CAR_PROPERTY_ENGINE_ON_STRING                           "android.car.property.engine_on"
#define CAR_PROPERTY_DTC_CODES                                  (0x0000040B)
#define CAR_PROPERTY_DTC_CODES_STRING                           "android.car.property.dtc_codes"
#define CAR_PROPERTY_CABIN_LIGHTS_ON                            (0x0000040C)
#define CAR_PROPERTY_CABIN_LIGHTS_ON_STRING                     "android.car.property.cabin_lights_on"

/*
 * HVAC Properties
 */
#define CAR_PROPERTY_HVAC_DRIVER_CURRENT_TEMP                   (0x00000500)
#define CAR_PROPERTY_HVAC_DRIVER_CURRENT_TEMP_STRING            "android.car.hvac.driver.current_temp"
#define CAR_PROPERTY_HVAC_DRIVER_FAN_SPEED                      (0x00000501)
#define CAR_PROPERTY_HVAC_DRIVER_FAN_SPEED_STRING               "android.car.hvac.driver.fan_speed"
#define CAR_PROPERTY_HVAC_DRIVER_SET_TEMP                       (0x00000502)
#define CAR_PROPERTY_HVAC_DRIVER_SET_TEMP_STRING                "android.car.hvac.driver.set_temp"
#define CAR_PROPERTY_HVAC_DRIVER_VENT_POSITION                  (0x00000503)
#define CAR_PROPERTY_HVAC_DRIVER_VENT_POSITION_STRING           "android.car.hvac.driver.vent_position"
#define CAR_PROPERTY_HVAC_DEFROSTER_FRONT                       (0x00000504)
#define CAR_PROPERTY_HVAC_DEFROSTER_FRONT_STRING                "android.car.hvac.defroster_front"
#define CAR_PROPERTY_HVAC_DEFROSTER_REAR                        (0x00000505)
#define CAR_PROPERTY_HVAC_DEFROSTER_REAR_STRING                 "android.car.hvac.defroster_rear"
#define CAR_PROPERTY_HVAC_PASSENGER_CURRENT_TEMP                (0x00000506)
#define CAR_PROPERTY_HVAC_PASSENGER_CURRENT_TEMP_STRING         "android.car.hvac.passenger.current_temp"
#define CAR_PROPERTY_HVAC_PASSENGER_FAN_SPEED                   (0x00000507)
#define CAR_PROPERTY_HVAC_PASSENGER_FAN_SPEED_STRING            "android.car.hvac.passenger.fan_speed"
#define CAR_PROPERTY_HVAC_PASSENGER_SET_TEMP                    (0x00000508)
#define CAR_PROPERTY_HVAC_PASSENGER_SET_TEMP_STRING             "android.car.hvac.passenger.set_temp"
#define CAR_PROPERTY_HVAC_PASSENGER_VENT_POSITION               (0x00000509)
#define CAR_PROPERTY_HVAC_PASSENGER_VENT_POSITION_STRING        "android.car.hvac.passenger.vent_position"
#define CAR_PROPERTY_HVAC_REAR_CURRENT_TEMP                     (0x0000050A)
#define CAR_PROPERTY_HVAC_REAR_CURRENT_TEMP_STRING              "android.car.hvac.rear.current_temp"
#define CAR_PROPERTY_HVAC_REAR_FAN_SPEED                        (0x0000050B)
#define CAR_PROPERTY_HVAC_REAR_FAN_SPEED_STRING                 "android.car.hvac.rear.fan_speed"
#define CAR_PROPERTY_HVAC_REAR_SET_TEMP                         (0x0000050C)
#define CAR_PROPERTY_HVAC_REAR_SET_TEMP_STRING                  "android.car.hvac.rear.set_temp"
#define CAR_PROPERTY_HVAC_REAR_VENT_POSITION                    (0x0000050D)
#define CAR_PROPERTY_HVAC_REAR_VENT_POSITION_STRING             "android.car.hvac.rear.vent_position"

/*
 * Seating Position
 */
#define CAR_PROPERTY_SEAT_DRIVER_BACKREST_ANGLE                 (0x00000600)
#define CAR_PROPERTY_SEAT_DRIVER_BACKREST_ANGLE_STRING          "android.car.seat.driver.backrest_angle"
#define CAR_PROPERTY_SEAT_DRIVER_BELT_HEIGHT                    (0x00000601)
#define CAR_PROPERTY_SEAT_DRIVER_BELT_HEIGHT_STRING             "android.car.seat.driver.belt_height"
#define CAR_PROPERTY_SEAT_DRIVER_FORE_AFT                       (0x00000602)
#define CAR_PROPERTY_SEAT_DRIVER_FORE_AFT_STRING                "android.car.seat.driver.fore_aft"
#define CAR_PROPERTY_SEAT_DRIVER_HEADREST_ANGLE                 (0x00000603)
#define CAR_PROPERTY_SEAT_DRIVER_HEADREST_ANGLE_STRING          "android.car.seat.driver.headrest_angle"
#define CAR_PROPERTY_SEAT_DRIVER_HEADREST_LEVEL                 (0x00000604)
#define CAR_PROPERTY_SEAT_DRIVER_HEADREST_LEVEL_STRING          "android.car.seat.driver.headrest_level"
#define CAR_PROPERTY_SEAT_DRIVER_HEAT                           (0x00000605)
#define CAR_PROPERTY_SEAT_DRIVER_HEAT_STRING                    "android.car.seat.driver.heat"
#define CAR_PROPERTY_SEAT_DRIVER_HEIGHT                         (0x00000606)
#define CAR_PROPERTY_SEAT_DRIVER_HEIGHT_STRING                  "android.car.seat.driver.height"
#define CAR_PROPERTY_SEAT_DRIVER_LUMBAR_POSITION                (0x00000607)
#define CAR_PROPERTY_SEAT_DRIVER_LUMBAR_POSITION_STRING         "android.car.seat.driver.lumbar_position"
#define CAR_PROPERTY_SEAT_PASSENGER_BACKREST_ANGLE              (0x00000608)
#define CAR_PROPERTY_SEAT_PASSENGER_BACKREST_ANGLE_STRING       "android.car.seat.passenger.backrest_angle"
#define CAR_PROPERTY_SEAT_PASSENGER_BELT_HEIGHT                 (0x00000609)
#define CAR_PROPERTY_SEAT_PASSENGER_BELT_HEIGHT_STRING          "android.car.seat.passenger.belt_height"
#define CAR_PROPERTY_SEAT_PASSENGER_FORE_AFT                    (0x0000060A)
#define CAR_PROPERTY_SEAT_PASSENGER_FORE_AFT_STRING             "android.car.seat.passenger.fore_aft"
#define CAR_PROPERTY_SEAT_PASSENGER_HEADREST_ANGLE              (0x0000060B)
#define CAR_PROPERTY_SEAT_PASSENGER_HEADREST_ANGLE_STRING       "android.car.seat.passenger.headrest_angle"
#define CAR_PROPERTY_SEAT_PASSENGER_HEADREST_LEVEL              (0x0000060C)
#define CAR_PROPERTY_SEAT_PASSENGER_HEADREST_LEVEL_STRING       "android.car.seat.passenger.headrest_level"
#define CAR_PROPERTY_SEAT_PASSENGER_HEAT                        (0x0000060D)
#define CAR_PROPERTY_SEAT_PASSENGER_HEAT_STRING                 "android.car.seat.passenger.heat"
#define CAR_PROPERTY_SEAT_PASSENGER_HEIGHT                      (0x0000060E)
#define CAR_PROPERTY_SEAT_PASSENGER_HEIGHT_STRING               "android.car.seat.passenger.height"
#define CAR_PROPERTY_SEAT_PASSENGER_LUMBAR_POSITION             (0x0000060F)
#define CAR_PROPERTY_SEAT_PASSENGER_LUMBAR_POSITION_STRING      "android.car.seat.passenger.lumbar_position"

/*
 * Environment Sensors
 */
#define CAR_PROPERTY_ENV_AIR_QUALITY_SENSOR                     (0x00000700)
#define CAR_PROPERTY_ENV_AIR_QUALITY_SENSOR_STRING              "android.car.environment.air_quality_sensor"
#define CAR_PROPERTY_ENV_OUTSIDE_HUMIDITY                       (0x00000701)
#define CAR_PROPERTY_ENV_OUTSIDE_HUMIDITY_STRING                "android.car.environment.outside_humidity"
#define CAR_PROPERTY_ENV_OUTSIDE_PRESSURE                       (0x00000702)
#define CAR_PROPERTY_ENV_OUTSIDE_PRESSURE_STRING                "android.car.environment.outside_pressure"
#define CAR_PROPERTY_ENV_OUTSIDE_TEMP                           (0x00000703)
#define CAR_PROPERTY_ENV_OUTSIDE_TEMP_STRING                    "android.car.environment.outside_temp"

/*
 * Safety Sensors
 */
#define CAR_PROPERTY_SHORT_RANGE_RADAR                          (0x00000800)
#define CAR_PROPERTY_SHORT_RANGE_RADAR_STRING                   "android.car.safety.short_range_radar"
#define CAR_PROPERTY_LONG_RANGE_RADAR                           (0x00000801)
#define CAR_PROPERTY_LONG_RANGE_RADAR_STRING                    "android.car.safety.long_range_radar"
#define CAR_PROPERTY_LIDAR                                      (0x00000802)
#define CAR_PROPERTY_LIDAR_STRING                               "android.car.safety.lidar"
#define CAR_PROPERTY_DRIVER_ATTENTION                           (0x00000803)
#define CAR_PROPERTY_DRIVER_ATTENTION_STRING                    "android.car.safety.driver_attention"
#define CAR_PROPERTY_DRIVER_BIO                                 (0x00000804)
#define CAR_PROPERTY_DRIVER_BIO_STRING                          "android.car.safety.driver_bio"



/*
 * Base for device manufacturers private sensor types.
 * These sensor types can't be exposed in the SDK.
 */
#define CAR_PROPERTY_VENDOR_SPECIFIC_BASE               (0x10000)


/*
 * Union of the various properties that may be returned.
 */
typedef struct car_event_t {
    /* property identifier */
    uint32_t    prop;

    /* flags for internal use */
    uint32_t    flags;

    /* time is in nanosecond */
    int64_t     timestamp;

    car_value_t value;
} car_event_t;


typedef int (*act_callback_fxn)(int action, void *data, unsigned int len);
typedef int (*event_callback_fxn)(car_event_t *event_data, unsigned int num_events);

struct car_property_t {

    /*
     * Name of this property.
     */
    const char*     name;

    /*
     * handle that identifies this property. This handle is used to reference
     * the property throughout the HAL API.
     */
    int             handle;

#ifdef __LP64__
    uint64_t        latency;
    uint64_t        sample_rate;
#else
    uint32_t        latency;
    uint32_t        sample_rate;
#endif

    uint32_t        flags;

    /* range of this property */
    car_value_t     minRange;
    car_value_t     maxRange;

    /* trigger ranges (if enabled) */
    car_value_t     trigger_max;
    car_value_t     trigger_min;
} car_property_t;

/*
 * Every hardware module must have a data structure named HAL_MODULE_INFO_SYM
 * and the fields of this data structure must begin with hw_module_t
 * followed by module specific information.
 */
struct car_module_t {
    struct hw_module_t common;

    /*
     * Enumerate all available properties. The list is returned in "list".
     * @return number of sensors in the list
     */
    int (*list_properties)(struct car_module_t* module,
            struct car_property_t const** list);

    int (*register_act_callback)(act_callback_fxn cb_func);

    int (*register_event_callback)(event_callback_fxn cb_func);
} car_module_t;


/*
 * struct sensors_poll_device_1 is used in HAL versions >= SENSORS_DEVICE_API_VERSION_1_0
 */
typedef struct car_device {
    struct hw_device_t common;

    /* Perform an action */
    int (*act)(struct car_device, int handle, void *data, unsigned int len);

    /* get a car property value immediately */
    int (*get)(struct car_device, int handle, car_event_t *data);

    /* set a car property value */
    int (*set)(struct car_device, int handle, car_event_t *data);

    /* subscribe to events */
#ifdef __LP64__
    int (*subscribe)(struct car_device, int handle, uint32_t flags,
                  uint64_t latency, uint64_t sample_rate,
                  car_value_t trigger_min, car_value_t trigger_max);
#else
    int (*subscribe)(struct car_device, int handle, uint32_t flags,
                  uint32_t latency, uint32_t sample_rate,
                  car_value_t trigger_min, car_value_t trigger_max);
#endif

    /* cancel subscription on a property */
    int (*unsubscribe)(struct car_device, int handle);
} car_device_t;


/* convenience API for opening and closing a device */

static inline int car_open(const struct hw_module_t* module,
        struct car_device_t** device) {
    return module->methods->open(module,
            CAR_HARDWARE_DEVICE, (struct hw_device_t**)device);
}

static inline int car_close(struct car_device_t* device) {
    return device->common.close(&device->common);
}

__END_DECLS

#endif  // ANDROID_CAR_INTERFACE_H
