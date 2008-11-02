
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <cutils/properties.h>
#include <hardware/vibrator.h>

static int write_brightness(int brightness)
{
    char ledName[PROPERTY_VALUE_MAX];
    char devName[255];
    char value[16];
    int len, ret, fd;

    bzero(ledName, sizeof(ledName));
    property_get ("led.vibrator", ledName, "");

    if (strlen (ledName) == 0)
        return -1;

    sprintf (devName, "/sys/class/leds/%s/brightness", ledName);

    fd = open(devName, O_RDWR);
    if(fd < 0)
        return errno;

    len = sprintf(value, "%d\n", brightness);
    ret = write(fd, value, len);

    close(fd);

    return (ret == len) ? 0 : -1;
}

int vibrator_on()
{
    return write_brightness(255);
}

int vibrator_off()
{
    return write_brightness(0);
}
