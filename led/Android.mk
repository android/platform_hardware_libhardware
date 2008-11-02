# Copyright 2006 The Android Open Source Project

ifeq ($(USE_LED_TYPE),)
USE_LED_TYPE := stub
endif

ifeq ($(TARGET_PRODUCT),sooner)
USE_LED_TYPE := sardine
endif

ifeq ($(TARGET_PRODUCT),dream)
USE_LED_TYPE := trout
endif

LOCAL_SRC_FILES += led/led_$(USE_LED_TYPE).c

