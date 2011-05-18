/*
 * Copyright (C) CSR plc 2011
 * Copyright 2010, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author: marco.sinigaglia@csr.com for CSR plc
 */

#include "linux/videodev2.h"

#define     DEFAULT_DEVICE     "/dev/radio0"
//SCAN PARAMETER
#define     SAMPLEDELAY         15000       /* wait 15ms between samples */
#define     TRIES               1           /* number of times of test signal */


int get_v4l2_tuner(int fd, struct v4l2_tuner *vt);
float get_fact(int fd, struct v4l2_tuner *vt);
int get_stereo(int fd, struct v4l2_tuner *vt);
int open_dev(char *dev);
int close_dev(int fd);
int set_freq(int fd, int freq);
int get_freq(int fd);
int set_volume(int fd, int vol);
int get_signal_strength(int fd, struct v4l2_tuner *vt);
int set_force_mono(int fd, struct v4l2_tuner *vt, int force_mono);
int get_RDS_cap(int fd);
int get_tun_radio_cap(int fd);
int set_mute(int fd, int value);
int set_volume(int fd, int vol);

