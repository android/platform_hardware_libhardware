
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#define LOG_TAG "LED"
#include <utils/Log.h>

#include <cutils/properties.h>
#include <hardware/led.h>

static int
write_brightness(const char *prop, int brightness)
{
    char ledName[PROPERTY_VALUE_MAX];
    char devName[255];
    char value[16];
    int len, ret, fd;

    bzero(ledName, sizeof(ledName));
    property_get (prop, ledName, "");

    if (strlen (ledName) == 0)
        return -1;

    sprintf (devName, "/sys/class/leds/%s/brightness", ledName);

    fd = open(devName, O_RDWR);
    if (fd < 0) {
        ret = errno;
        goto done;
    }

    len = sprintf(value, "%d", brightness);
    ret = write(fd, value, len);

    close(fd);

    ret = (ret == len) ? 0 : -1;

done:
    return ret;
}

static int
write_delays(const char *prop, int on, int off)
{
    char ledName[PROPERTY_VALUE_MAX];
    char devName[255];
    char value[16];
    int len, ret, fd;

    bzero(ledName, sizeof(ledName));
    property_get (prop, ledName, "");

    if (strlen (ledName) == 0)
        return -1;

    sprintf (devName, "/sys/class/leds/%s/delay_off", ledName);

    fd = open(devName, O_RDWR);
    if (fd < 0) {
        ret = errno;
        goto done;
    }

    len = sprintf(value, "%d", off);
    ret = write(fd, value, len);

    close(fd);

    if (ret != len) {
        ret = -1;
        goto done;
    }

    sprintf (devName, "/sys/class/leds/%s/delay_on", ledName);

    fd = open(devName, O_RDWR);
    if (fd < 0) {
        ret = errno;
        goto done;
    }

    len = sprintf(value, "%d", on);
    ret = write(fd, value, len);

    close(fd);

    ret = (ret == len) ? 0 : -1;

done:
    return ret;
}

int set_led_state(unsigned int colorARGB, int onMS, int offMS)
{
    int red, green, blue;

    red   = (colorARGB >> 16) & 0xFF;
    green = (colorARGB >>  8) & 0xFF;
    blue  =  colorARGB        & 0xFF;

	LOGI ("set_led_state: Red: %d, Green: %d, Blue: %d, on: %d, off: %d",
			red, green, blue, onMS, offMS);

	/*
	 * First, turn everything off.
	 * NOTICE: Newer kernel removes trigger on LED off and this is bad.
	 * Patch the kernel to make sure that doesn't happen or you'll lose
	 * permission on delay_off/delay_on!!!!
	 */
    write_brightness("led.red",   0);
    write_brightness("led.green", 0);
    write_brightness("led.blue",  0);

   	write_delays("led.red", 0, 0);
   	write_delays("led.green", 0, 0);
   	write_delays("led.blue", 0, 0);

	/*
	 * Now, set them according to the request
	 */
    write_brightness("led.red",   red);
    write_brightness("led.green", green);
    write_brightness("led.blue",  blue);

	if (red && offMS)
    	write_delays("led.red", onMS, offMS);

	if (green && offMS)
	    write_delays("led.green", onMS, offMS);

	if (blue && offMS)
	    write_delays("led.blue", onMS, offMS);

    return 0;
}

int set_bt_wifi_led_state(int enable)
{
    if (enable) {
        write_brightness("led.blue", 255);
        write_delays("led.blue", 1000, 3000);
    } else {
        write_delays("led.blue", 0, 0);
        write_brightness("led.blue", 0);
    }
    return 0;
}
