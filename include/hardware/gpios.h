/*
 * Copyright (C) 2015 Intel Corporation
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

#ifndef ANDROID_GPIOS_INTERFACE_H
#define ANDROID_GPIOS_INTERFACE_H

#include <hardware/hardware.h>

__BEGIN_DECLS

/**
 * The id of this module
 */
#define GPIOS_HARDWARE_MODULE_ID "gpios"


/**
 * Data structure for describing an exposed GPIO
 */
struct gpio_t {
    int pin;
    int physical_pin;
};

/**
 * Gpio modes
 */
typedef enum {
    GPIO_STRONG = 0,   /**< Default. Strong high and low */
    GPIO_PULLUP = 1,   /**< Resistive High */
    GPIO_PULLDOWN = 2, /**< Resistive Low */
    GPIO_HIZ = 3       /**< High Z State */
} gpio_mode_t;

/**
 * Gpio Direction options
 */
typedef enum {
    GPIO_OUT = 0,      /**< Output. A Mode can also be set */
    GPIO_IN = 1,       /**< Input */
    GPIO_OUT_HIGH = 2, /**< Output. Init High */
    GPIO_OUT_LOW = 3   /**< Output. Init Low */
} gpio_dir_t;

/**
 * Gpio Edge types for interupts
 */
typedef enum {
    GPIO_EDGE_NONE = 0,   /**< No interrupt on Gpio */
    GPIO_EDGE_BOTH = 1,   /**< Interupt on rising & falling */
    GPIO_EDGE_RISING = 2, /**< Interupt on rising only */
    GPIO_EDGE_FALLING = 3 /**< Interupt on falling only */
} gpio_edge_t;


struct gpio_device_t {
    struct hw_device_t common;

    /**
     * Enumerate all available gpios. The list is returned in "list".
     * @param list where to store the pointer of the list
     * @return number of gpios in the list
     */
    int (*get_gpios_list)(struct gpio_t const** list);

    /**
     * Open a GPIO
     * @param pin GPIO identifier
     * @return 0 if no error, <0 otherwise
     */
    int (*open_gpio)(int pin);

    /**
     * Close a GPIO
     * @param pin GPIO identifier
     * @return 0 if no error, <0 otherwise
     */
    int (*close_gpio)(int pin);

    /**
     * Get GPIO value
     * @param pin GPIO identifier
     * @return value (>= 0) if no error, <0 otherwise
     */
    int (*get_gpio_value)(int pin);

    /**
     * Set GPIO value
     * @param pin GPIO identifier
     * @param value what to write
     * @return 0 if no error, <0 otherwise
     */
    int (*set_gpio_value)(int pin, int value);

    /**
     * Set GPIO direction
     * @param pin GPIO identifier
     * @param dir direction to set
     * @return 0 if no error, <0 otherwise
     */
    int (*set_gpio_dir)(int pin, gpio_dir_t dir);

    /**
     * Set GPIO edge mode
     * @param pin GPIO identifier
     * @param mode edge mode to set
     * @return 0 if no error, <0 otherwise
     */
    int (*set_gpio_edge_mode)(int pin, gpio_edge_t mode);

    /**
     * Set GPIO edge mode
     * @param pin GPIO identifier
     * @param mode mode to set
     * @return 0 if no error, <0 otherwise
     */
    int (*set_gpio_mode)(int pin, gpio_mode_t mode);

    /**
     * Set GPIO interrupt service routine
     * @param pin GPIO identifier
     * @param edge at which transition to run the routine
     * @param func interrupt service routine
     * @param args interrupt service routine arguments
     * @return 0 if no error, <0 otherwise
     */
    int (*set_gpio_isr)(int pin, gpio_edge_t edge, void (*func)(void *), void *args);

    /**
     * Cancel GPIO Interrupt service routine
     * @param pin GPIO identifier
     * @return 0 if no error, <0 otherwise
     */
    int (*cancel_gpio_isr)(int pin);
};


__END_DECLS

#endif  // ANDROID_GPIOS_INTERFACE_H
