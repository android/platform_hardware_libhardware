# Copyright 2008 The Android Open Source Project

ifeq ($(USE_SENSOR_TYPE),)
USE_SENSOR_TYPE := stub
endif

ifeq ($(TARGET_PRODUCT),dream)
USE_SENSOR_TYPE := trout
endif

LOCAL_SRC_FILES += sensors/sensors_$(USE_SENSOR_TYPE).c

