# Copyright 2006 The Android Open Source Project

ifeq ($(USE_VIBRATOR_TYPE),)
LOCAL_SRC_FILES += vibrator/vibrator.c
else
LOCAL_SRC_FILES += vibrator/vibrator_$(USE_VIBRATOR_TYPE).c
endif
