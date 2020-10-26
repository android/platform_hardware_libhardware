/*
 *  FASTBOOT
 *
 *  Copyright (c) 2020 ID TECH.
 *  Author: Owen Wen <owen.wen@idtechproducts.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#ifndef ANDROID_INCLUDE_FASTBOOT_H
#define ANDROID_INCLUDE_FASTBOOT_H

#include <hardware/hardware.h>

/*
 * Add C declare to fix below error message
 * hardware/interfaces/fastboot/1.0/default/Fastboot.h:32:14: error: unknown type name 'fastboot_module_t'
 *     Fastboot(fastboot_module_t* module);
 *              ^
 */
__BEGIN_DECLS

/**
 * The id of this module
 */
#define FASTBOOT_MODULE_ID "fastboot"

/**
 * Every hardware module must have a data structure named HAL_MODULE_INFO_SYM
 * and the fields of this data structure must begin with hw_module_t
 * followed by module specific information.
 */
typedef struct fastboot_module {
    struct hw_module_t common;

    int (*getPartitionType)(struct fastboot_module *module, const char*);

    void (*doOemCommand)(struct fastboot_module *module);

    void (*getVariant)(struct fastboot_module *module);

    void (*getOffModeChargeState)(struct fastboot_module *module);

    void (*getBatteryVoltageFlashingThreshold)(struct fastboot_module *module);

} fastboot_module_t;

__END_DECLS

#endif // ANDROID_INCLUDE_FASTBOOT_H
