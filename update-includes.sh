#!/bin/bash

set +ex

if [ ! "$ANDROID_BUILD_TOP" ]; then
	echo "lunch?"
	exit 1
fi

find -L "$ANDROID_BUILD_TOP/hardware/libhardware/include/hardware" -maxdepth 1 -xtype l -exec rm {} \;

for f in $ANDROID_BUILD_TOP/hardware/libhardware/include_all/hardware/*; do
    ln -s $f "$ANDROID_BUILD_TOP/hardware/libhardware/include/hardware/$(basename $f)"
done
