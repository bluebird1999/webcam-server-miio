/*
 * config_miio.c
 *
 *  Created on: Aug 16, 2020
 *      Author: ning
 */

/*
 * header
 */
//system header
#include <pthread.h>
#include <stdio.h>
#include <malloc.h>
#include <dmalloc.h>
//program header
#include "../../manager/manager_interface.h"
#include "../../tools/tools_interface.h"
//server header
#include "config.h"

/*
 * static
 */
//variable
static pthread_rwlock_t			lock;
static miio_config_t			miio_config;
static int						dirty;
/*
static config_map_t miio_config_iot_map[] = {
    {"camera_on",      					&(miio_config.iot.camera_on),      				cfg_u32, 1,0, 0,1,  	},
    {"camera_image_rollover",  			&(miio_config.iot.camera_image_rollover),  		cfg_u32, 0,0, 0,360,    },
    {"camera_night_shot", 				&(miio_config.iot.camera_night_shot), 			cfg_u32, 0,0, 0,10,    },
    {"camera_time_watermark",  			&(miio_config.iot.camera_time_watermark),  		cfg_u32, 1,0, 0,1,    },
    {"camera_wdr_mode",        			&(miio_config.iot.camera_wdr_mode),        		cfg_u32, 0,0, 0,1,	},
    {"camera_glimmer_full_color",     	&(miio_config.iot.camera_glimmer_full_color),   cfg_u32, 0,0, 0,1,  	},
    {"camera_recording_mode",       	&(miio_config.iot.camera_recording_mode),       cfg_u32, 0,0, 0,10,	},
    {"camera_motion_tracking",       	&(miio_config.iot.camera_motion_tracking),      cfg_u32, 0,0, 0,1,	},
    {"indicator_on",        			&(miio_config.iot.indicator_on),         		cfg_u32, 1,0, 0,1,	},
    {"indicator_mode",        			&(miio_config.iot.indicator_mode),        		cfg_u32, 0,0, 0,10,	},
    {"indicator_brightness",        	&(miio_config.iot.indicator_brightness),  		cfg_u32, 80,0, 1,100,    },
    {"indicator_color",        			&(miio_config.iot.indicator_color),   			cfg_u32, 255,0, 0,16777215,    },
    {"indicator_color_temperature",     &(miio_config.iot.indicator_color_temperature),	cfg_u32, 2000,0, 1000,10000,    },
	{"indicator_flow",     				&(miio_config.iot.indicator_flow),				cfg_u32, 0,0, 0,10,    },
    {"indicator_saturability",        	&(miio_config.iot.indicator_saturability),		cfg_u32, 80,0, 0,100,   },
    {"sdcard_status",        			&(miio_config.iot.sdcard_status),        		cfg_u32, 1,0, 0,10,	},
    {"sdcard_total_space",        		&(miio_config.iot.sdcard_total_space),       	cfg_u32, 10,0, 0,10,	},
    {"sdcard_free_space",        		&(miio_config.iot.sdcard_free_space),        	cfg_u32, 2,0, 0,10,	},
    {"sdcard_used_space",        		&(miio_config.iot.sdcard_used_space),        	cfg_u32, 8,0, 0,10,	},
    {"motion_on",        				&(miio_config.iot.motion_on),        			cfg_u32, 0,0, 0,1,	},
    {"motion_alarm_interval",        	&(miio_config.iot.motion_alarm_interval),    	cfg_u32, 1,0, 1,30,	},
    {"motion_sensitivity",        		&(miio_config.iot.motion_sensitivity),       	cfg_u32, 1,0, 0,10,	},
    {"motion_start_time",        		&(miio_config.iot.motion_start_time),        	cfg_string,"2020",0, 0,32,	},
    {"motion_end_time",        			&(miio_config.iot.motion_end_time),        		cfg_string,"2020",0, 0,32,	},
    {NULL,},
};
*/

//function
static int miio_config_device_read(void);
static int miio_config_device_write(void);
static int miio_config_save(void);
/*
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 */
static int miio_config_save(void)
{
	int ret = 0;
	message_t msg;
	ret = pthread_rwlock_wrlock(&lock);
	if(ret)	{
		log_err("add lock fail, ret = %d\n", ret);
		return ret;
	}
/*	if( misc_get_bit(dirty, CONFIG_MIIO_IOT) ) {
		ret = write_config_file(&miio_config_iot_map, CONFIG_MIIO_IOT_PATH);
		if(!ret)
			misc_set_bit(&dirty, CONFIG_MIIO_IOT, 0);
	}
	else
*/
	if( misc_get_bit(dirty, CONFIG_MIIO_DEVICE) )
	{
		ret = miio_config_device_write();
		if(!ret)
			misc_set_bit(&dirty, CONFIG_MIIO_DEVICE, 0);
	}
	if( !dirty ) {
		/********message body********/
		msg_init(&msg);
		msg.message = MSG_MANAGER_TIMER_REMOVE;
		msg.arg_in.handler = miio_config_save;
		/****************************/
		manager_message(&msg);
	}
	ret = pthread_rwlock_unlock(&lock);
	if (ret)
		log_err("add unlock fail, ret = %d\n", ret);

	return ret;
}

static int miio_config_device_read(void)
{
	FILE *fp = NULL;
	int pos = 0;
	int len = 0;
	char *data = NULL;
	int fileSize = 0;
	int ret;
    memset(&miio_config.device, 0, sizeof(miio_config_device_t));
	//read device.conf
	fp = fopen(CONFIG_MIIO_DEVICE_PATH, "rb");
	if (fp == NULL) {
		return -1;
	}
	if (0 != fseek(fp, 0, SEEK_END)) {
		fclose(fp);
		return -1;
	}
	fileSize = ftell(fp);
    if(fileSize > 0) {
    	data = malloc(fileSize);
    	if(!data) {
    		fclose(fp);
    		return -1;
    	}
    	memset(data, 0, fileSize);
    	if(0 != fseek(fp, 0, SEEK_SET)) {
    		free(data);
    		fclose(fp);
    		return -1;
    	}
    	if (fread(data, 1, fileSize, fp) != (fileSize)) {
    		free(data);
    		fclose(fp);
    		return -1;
    	}
    	fclose(fp);
    	char *ptr_did = 0;
    	char *ptr_key = 0;
    	char *ptr_mac = 0;
    	char *ptr_model = 0;
    	char *ptr_vendor = 0;
    	ptr_did = strstr(data, "did=");
    	ptr_key = strstr(data, "key=");
    	ptr_mac = strstr(data, "mac=");
    	ptr_model = strstr(data, "model=");
    	ptr_vendor = strstr(data, "vendor=");
    	char *p,*m;
    	if(ptr_did&&ptr_key&&ptr_mac) {
    		len = 9;//did length
    		memcpy(miio_config.device.did,ptr_did+4,len);
    		len = 16;//key length
    		memcpy(miio_config.device.key,ptr_key+4,len);
    		len = 17;//mac length
    		memcpy(miio_config.device.mac,ptr_mac+4,len);
    		p = ptr_model+6; m = miio_config.device.model;
    		while(*p!='\n' && *p!='\0') {
    			memcpy(m, p, 1);
    			m++;p++;
    		}
    		*m = '\0';
    		p = ptr_vendor+7; m = miio_config.device.vendor;
    		while(*p!='\n' && *p!='\0') {
    			memcpy(m, p, 1);
    			m++;p++;
    		}
    		*m = '\0';
    	}
    	free(data);
    }
	fileSize = 0;
	len = 0;
	//read device.token
	fp = fopen(CONFIG_MIIO_TOKEN_PATH, "rb");
	if (fp == NULL) {
		return -1;
	}
	if (0 != fseek(fp, 0, SEEK_END)) {
		fclose(fp);
		return -1;
	}
	fileSize = ftell(fp);
    if(fileSize > 0) {
    	data = malloc(fileSize);
    	if(!data) {
    		fclose(fp);
    		return -1;
    	}
    	memset(data, 0, fileSize);
    	if(0 != fseek(fp, 0, SEEK_SET)) {
    		free(data);
    		fclose(fp);
    		return -1;
    	}
    	if (fread(data, 1, fileSize, fp) != (fileSize)) {
    		free(data);
    		fclose(fp);
    		return -1;
    	}
    	fclose(fp);

	    if(data[strlen((char*)data) - 1] == 0xa)
            data[strlen((char*)data) - 1] = 0;
		memcpy(miio_config.device.miio_token,data,fileSize);
    	free(data);
    }
    else {
		log_err("device.token -->file date err!!!\n");
        return -1;
    }
	fileSize = 0;
	len = 0;
	//read os-release
	fp = fopen(CONFIG_MIIO_OSRELEASE_PATH, "rb");
	if (fp == NULL) {
		return -1;
	}
	if (0 != fseek(fp, 0, SEEK_END)) {
		fclose(fp);
		return -1;
	}
	fileSize = ftell(fp);
    if(fileSize > 0) {
    	char *ptr_version = 0;
    	data = malloc(fileSize);
    	if(!data) {
    		fclose(fp);
    		return -1;
    	}
    	memset(data, 0, fileSize);
    	if(0 != fseek(fp, 0, SEEK_SET)) {
    		free(data);
    		fclose(fp);
    		return -1;
    	}
    	if (fread(data, 1, fileSize, fp) != (fileSize)) {
    		free(data);
    		fclose(fp);
    		return -1;
    	}
    	fclose(fp);
    	ptr_version = strstr(data, "REALTEK_RTK_VERSION=");
    	len = fileSize-20;
    	if(ptr_version&&(len > 0)) {
    		memcpy(miio_config.device.version,ptr_version+20,len);
    	}
    	else {
    		log_err("os-release -->file date err!!!\n");
    	}
    	free(data);
    }
	fileSize = 0;
	len = 0;
	return 0;
}

static int miio_config_device_write(void)
{
	int ret=0;
	return ret;
}

/*
 * interface
 */
int config_miio_read(miio_config_t *mconfig)
{
	int ret,ret1=0;
	pthread_rwlock_init(&lock, NULL);
	ret = pthread_rwlock_wrlock(&lock);
	if(ret)	{
		log_err("add lock fail, ret = %d\n", ret);
		return ret;
	}
/*	ret = read_config_file(&miio_config_iot_map, CONFIG_MIIO_IOT_PATH);
	if(!ret)
		misc_set_bit(&miio_config.status, CONFIG_MIIO_IOT,1);
	else
		misc_set_bit(&miio_config.status, CONFIG_MIIO_IOT,0);
	ret1 |= ret;
*/
	ret = miio_config_device_read();
	if(!ret)
		misc_set_bit(&miio_config.status, CONFIG_MIIO_DEVICE,1);
	else
		misc_set_bit(&miio_config.status, CONFIG_MIIO_DEVICE,0);
	ret1 |= ret;
	ret = pthread_rwlock_unlock(&lock);
	if (ret)
		log_err("add unlock fail, ret = %d\n", ret);
	ret1 |= ret;
	memcpy(mconfig,&miio_config,sizeof(miio_config_t));
	return ret1;
}

int config_miio_set(int module, void *arg)
{
	int ret = 0;
	ret = pthread_rwlock_wrlock(&lock);
	if(ret)	{
		log_err("add lock fail, ret = %d\n", ret);
		return ret;
	}
	if(dirty==0) {
		message_t msg;
	    /********message body********/
		msg_init(&msg);
		msg.message = MSG_MANAGER_TIMER_ADD;
		msg.sender = SERVER_MIIO;
		msg.arg_in.cat = 60000;	//1min
		msg.arg_in.dog = 0;
		msg.arg_in.duck = 0;
		msg.arg_in.handler = &miio_config_save;
		/****************************/
		manager_message(&msg);
	}
	misc_set_bit(&dirty, module, 1);
/*	if( module == CONFIG_MIIO_IOT) {
		memcpy( (miio_config_iot_t*)(&miio_config.iot), arg, sizeof(miio_config_iot_t));
	}
	else
*/
	if ( module == CONFIG_MIIO_DEVICE ) {
		//nothing yet
	}
	ret = pthread_rwlock_unlock(&lock);
	if (ret)
		log_err("add unlock fail, ret = %d\n", ret);
	return ret;
}

int config_miio_get_config_status(int module)
{
	int st,ret=0;
	ret = pthread_rwlock_wrlock(&lock);
	if(ret)	{
		log_err("add lock fail, ret = %d\n", ret);
		return ret;
	}
	if(module==-1)
		st = miio_config.status;
	else
		st = misc_get_bit(miio_config.status, module);
	ret = pthread_rwlock_unlock(&lock);
	if (ret)
		log_err("add unlock fail, ret = %d\n", ret);
	return st;
}
