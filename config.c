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
//program header
#include "../../manager/manager_interface.h"
#include "../../tools/tools_interface.h"
#include "../../server/kernel/kernel_interface.h"
//server header
#include "config.h"

/*
 * static
 */
//variable
static miio_config_t			miio_config;
static int						dirty;

static config_map_t miio_config_iot_map[] = {
    {"board_type",      					&(miio_config.iot.board_type),      				cfg_u32, 1,0, 0,10,  	},
    {NULL,},
};

//function
static int miio_config_device_read(int);
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
	char fname[MAX_SYSTEM_STRING_SIZE*2];
	if( misc_get_bit(dirty, CONFIG_MIIO_IOT) ) {
		memset(fname,0,sizeof(fname));
		sprintf(fname,"%s%s",_config_.qcy_path, CONFIG_MIIO_IOT_PATH);
		ret = write_config_file(&miio_config_iot_map, fname);
		if(!ret)
			misc_set_bit(&dirty, CONFIG_MIIO_IOT, 0);
	}
	else if( misc_get_bit(dirty, CONFIG_MIIO_DEVICE) )
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
		manager_common_send_message(SERVER_MANAGER, &msg);
	}
	return ret;
}

static int miio_config_device_read(int board)
{
	FILE *fp = NULL;
	int pos = 0;
	int len = 0;
	char *data = NULL;
	int fileSize = 0;
	int ret;
	char fname[MAX_SYSTEM_STRING_SIZE*2];
    memset(&miio_config.device, 0, sizeof(miio_config_device_t));
	//read device.conf
	memset(fname,0,sizeof(fname));
	sprintf(fname,"%s%s",_config_.miio_path, CONFIG_MIIO_DEVICE_PATH);
	fp = fopen(fname, "rb");
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
    	char *p,*m;
    	if( !board ) {
			ptr_did = strstr(data, "did=");
			ptr_key = strstr(data, "key=");
			ptr_mac = strstr(data, "mac=");
    	}
    	ptr_model = strstr(data, "model=");
    	ptr_vendor = strstr(data, "vendor=");
    	if( !board && ptr_did && ptr_key && ptr_mac ) {
    		len = 9;//did length
    		memcpy(miio_config.device.did,ptr_did+4,len);
    		len = 16;//key length
    		memcpy(miio_config.device.key,ptr_key+4,len);
    		len = 17;//mac length
    		memcpy(miio_config.device.mac,ptr_mac+4,len);
    	}
    	if( ptr_model && ptr_vendor) {
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
	memset(fname,0,sizeof(fname));
	sprintf(fname,"%s%s",_config_.miio_path, CONFIG_MIIO_TOKEN_PATH);
	fp = fopen(fname, "rb");
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
		log_qcy(DEBUG_SERIOUS, "device.token -->file date err!!!\n");
        return -1;
    }
	fileSize = 0;
	len = 0;
	//read os-release
	memset(fname,0,sizeof(fname));
	sprintf(fname,"%s%s",_config_.miio_path, CONFIG_MIIO_OSRELEASE_PATH);
	fp = fopen(fname, "rb");
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
    	ptr_version = strstr(data, "QCY_VERSION=");
    	len = fileSize-12;
    	if(ptr_version&&(len > 0)) {
    		memcpy(miio_config.device.version,ptr_version+12,len);
    	}
    	else {
    		log_qcy(DEBUG_SERIOUS, "os-release -->file date err!!!\n");
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
	char fname[MAX_SYSTEM_STRING_SIZE*2];
	memset(fname,0,sizeof(fname));
	sprintf(fname,"%s%s",_config_.qcy_path, CONFIG_MIIO_IOT_PATH);
	ret = read_config_file(&miio_config_iot_map, fname);
	if(!ret)
		misc_set_bit(&miio_config.status, CONFIG_MIIO_IOT,1);
	else
		misc_set_bit(&miio_config.status, CONFIG_MIIO_IOT,0);
	ret1 |= ret;
	ret = miio_config_device_read( miio_config.iot.board_type );
	if(!ret)
		misc_set_bit(&miio_config.status, CONFIG_MIIO_DEVICE,1);
	else
		misc_set_bit(&miio_config.status, CONFIG_MIIO_DEVICE,0);
	ret1 |= ret;
	memcpy(mconfig,&miio_config,sizeof(miio_config_t));
	return ret1;
}

int config_miio_set(int module, void *arg)
{
	int ret = 0;
	if(dirty==0) {
		message_t msg;
	    /********message body********/
		msg_init(&msg);
		msg.message = MSG_MANAGER_TIMER_ADD;
		msg.sender = SERVER_MIIO;
		msg.arg_in.cat = FILE_FLUSH_TIME;	//1min
		msg.arg_in.dog = 0;
		msg.arg_in.duck = 0;
		msg.arg_in.handler = &miio_config_save;
		/****************************/
		manager_common_send_message(SERVER_MANAGER, &msg);
	}
	misc_set_bit(&dirty, module, 1);
	if( module == CONFIG_MIIO_IOT) {
		memcpy( (miio_config_iot_t*)(&miio_config.iot), arg, sizeof(miio_config_iot_t));
	}
	else
	if ( module == CONFIG_MIIO_DEVICE ) {
		//nothing yet
	}
	return ret;
}
