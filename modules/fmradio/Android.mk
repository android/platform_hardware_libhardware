LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	    v4l2_fm.c \
	    v4l2_ioctl.c \

#LOCAL_C_INCLUDES := 

LOCAL_SHARED_LIBRARIES := \
    libcutils libutils

LOCAL_MODULE:= libfmradio.v4l2_rx
LOCAL_PRELINK_MODULE := false
LOCAL_MODULE_TAGS := samples

include $(BUILD_SHARED_LIBRARY)
