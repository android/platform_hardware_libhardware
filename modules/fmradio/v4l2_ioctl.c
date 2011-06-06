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

#define LOG_TAG "fm_api.cpp"

#ifdef LINUX
#define LOGI printf
#define LOGE printf
#else
#include "utils/Log.h"
#endif

#include "v4l2_ioctl.h"
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>


int get_v4l2_tuner(int fd, struct v4l2_tuner *vt){
	int ret; 
	
	vt->index=0;
	
	ret = ioctl(fd, VIDIOC_G_TUNER, vt);	
	if (ret < 0) {
		LOGE("ioctl VIDIOC_G_TUNER\n");
		return -1;
	}
	return 0;
}

int set_v4l2_tuner(int fd, struct v4l2_tuner *vt){
	int ret; 
	
	vt->index=0;		

	ret = ioctl(fd, VIDIOC_S_TUNER, vt);	
	if (ret < 0) {
		LOGE("ioctl VIDIOC_S_TUNER\n");
		return -1;
	}
	return 0;
}

float get_fact(int fd, struct v4l2_tuner *vt){
  
	if (get_v4l2_tuner(fd, vt)<0)
	    return -1;
			
	if ((vt->capability & V4L2_TUNER_CAP_LOW) == 0)
		return 0.00016; 
	else
		return 16.;
	
	return -1;
}

int get_stereo(int fd, struct v4l2_tuner *vt){
	 if (get_v4l2_tuner(fd, vt)<0)
	    return -1;
	 
	return ((vt->audmode & V4L2_TUNER_MODE_STEREO) ==1);	
}

int get_RDS_cap(int fd){
	int ret;
	struct v4l2_capability vc;
	
	ret = ioctl(fd, VIDIOC_QUERYCAP, &vc);	
	
	if (ret < 0) {
		LOGE("ioctl VIDIOC_QUERYCAP\n");
		return -1;
	}
	return (vc.capabilities & V4L2_CAP_RDS_CAPTURE);
}

int get_tun_radio_cap(int fd){
	int ret;
	struct v4l2_capability vc;
	
	ret = ioctl(fd, VIDIOC_QUERYCAP, &vc);	
	
	if (ret < 0) {
		LOGE("ioctl VIDIOC_QUERYCAP\n");
		return -1;
	}
	return ((vc.capabilities & V4L2_CAP_TUNER) && (vc.capabilities & V4L2_CAP_RADIO));
}

int open_dev(char *dev){
  	int fd; 
	
	LOGI("Open default device %s\n", dev);
	fd = open(dev, O_RDONLY | O_NONBLOCK); 
	if (fd < 0) {
		LOGE("Unable to open %s: %s\n", dev, strerror(errno));
		return -1;
	}	
	
	return fd;
}

int set_volume(int fd, int vol){        				
	int ret; 	
	struct	v4l2_control vc;
	
	vc.id = V4L2_CID_AUDIO_VOLUME;
	vc.value = vol;  
	
	ret = ioctl(fd, VIDIOC_S_CTRL, &vc);
	if (ret < 0) {	  
		LOGE("ioctl V4L2_CID_AUDIO_VOLUME \n");
		return -1;
	}		
	
	LOGI("Radio on at %2.2f%% volume\n", (vol / 655.36));
	
	return 0;  
}

int set_mute(int fd, int value){
        int ret; 	
	struct	v4l2_control vc;
	  
	vc.value = value;		
	vc.id = V4L2_CID_AUDIO_MUTE;
	
	ret = ioctl(fd, VIDIOC_S_CTRL, &vc);
	if (ret < 0) {	  
		LOGE("ioctl V4L2_CID_AUDIO_MUTE \n");
		return -1;
	}
	
	return 0;
}

int  set_freq(int fd, int freq){       
	int ret; 				
	struct v4l2_frequency vf;

	vf.tuner=0;
	vf.frequency=freq;	
	
	ret = ioctl(fd, VIDIOC_S_FREQUENCY, &vf);
	if (ret < 0) {
		LOGE("ioctl VIDIOC_S_FREQUENCY");
		return -1;
	}

	LOGI("Radio set freq to propretary %d\n", freq);	
	return freq;	
}

int get_freq(int fd){  
	int ret; 	
	struct v4l2_frequency vf;
	
	vf.tuner=0;
		
	ret = ioctl(fd, VIDIOC_G_FREQUENCY, &vf);
	if (ret < 0) {
		LOGE("ioctl VIDIOC_G_FREQUENCY");
		return -1;
	}  
		
	LOGI("Radio get frequency propretary %d \n", vf.frequency);
	return vf.frequency;
}

int get_signal_strength(int fd, struct v4l2_tuner *vt){ 
	int totsig, rate, i;
	float perc;	
	
	totsig=0;
	
	for (i = 0; i < TRIES; i++) {	  	  
	    
	    if (i>0)
	        usleep(SAMPLEDELAY);
	    
	    if (get_v4l2_tuner(fd, vt) < 0) {	    
		return -1;
	    }		
	    
	    totsig += vt->signal;	    
	    perc = (totsig / (65535.0 * i));				
	    //LOGI("checking: %3.1f%% (%d/%d), vt.signal %d  \n", perc * 100.0, i, TRIES,  vt->signal);             		      										
	    }		
		
	perc = (totsig / (65535.0 * TRIES));	
	rate = perc * 1000.0;   // changed in 0 - 1000 scale
		
	LOGI("signal strenght in SE scale %d \n", rate); 
		
	return rate;
}

int set_force_mono(int fd, struct v4l2_tuner *vt, int force_mono){
  
	if (force_mono ==1)
	    vt->audmode = V4L2_TUNER_MODE_MONO;
	else
	    vt->audmode = V4L2_TUNER_MODE_STEREO;
	
	return set_v4l2_tuner(fd, vt);	
}



