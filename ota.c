/*
 * ota.c
 *
 *  Created on: Oct 5, 2020
 *      Author: ning
 */



/*
 * header
 */
//system header
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/msg.h>
#include <stdbool.h>
#include <limits.h>
#include <time.h>
#include <json-c/json.h>
//program header
#include "../../manager/manager_interface.h"
#include "../../tools/tools_interface.h"
//server header
#include "miio_interface.h"
#include "miio.h"
#include "ota.h"


/*
 * static
 */
//variable
static ota_config_t	config;
static int			msg_id;
//function
static int ota_push_state(int state, int err_id);
static int ota_push_progress(int progress);
/*
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 */

/*
 * helper
 */
static int ota_push_state(int state, int err_id)
{
    cJSON *item_id,*item_method,*item_params,*item_state = NULL; //props
    int ret = -1, id = 0;
    cJSON *root_props= 0;
    char *propsbuf = NULL;

    char *ota_state[OTA_STATE_BUSY+1] = {"idle", "downloading", "dowloaded", "installing", "wait_install", "installed", "failed", "busy"};
    id =  misc_generate_random_id();
    root_props=cJSON_CreateObject();
    item_id = cJSON_CreateNumber(id);
    item_method = cJSON_CreateString("props");
    item_params = cJSON_CreateObject();
    if(err_id == 0) {
        item_state = cJSON_CreateString(ota_state[state]);
    }
    else {
        char err_msg[64];
        memset(err_msg, 0, sizeof(err_msg));
        char *ota_err_msg[OTA_ERR_UNKNOWN] = {"down error", "dns error", "connect error", "disconnect", "install error", "cancel", "low energy", "unknow"};
        int err_codeArray[OTA_ERR_UNKNOWN] = {
                OTA_ERR_DOWN_ERR,
                OTA_ERR_DNS_ERR,
                OTA_ERR_CONNECT_ERR,
                OTA_ERR_DICONNECT,
                OTA_ERR_INSTALL_ERR,
                OTA_ERR_CANCEL,
                OTA_ERR_LOW_ENERGY,
                OTA_ERR_UNKNOWN,
        };
        sprintf(err_msg, "%s|%d|%s", ota_state[state], err_codeArray[err_id-1], ota_err_msg[err_id-1]);
        item_state = cJSON_CreateString(err_msg);
    }
    cJSON_AddItemToObject(root_props, "id", item_id);
    cJSON_AddItemToObject(root_props, "method", item_method);
    cJSON_AddItemToObject(root_props, "params", item_params);
	cJSON_AddItemToObject(item_params,"ota_state", item_state);
    propsbuf = cJSON_Print(root_props);
    ret = miio_send_to_cloud(propsbuf, strlen(propsbuf));
    cJSON_Delete(root_props);
    return ret;
}

static int ota_push_progress(int progress)
{
    cJSON *item_id,*item_method,*item_params,*item_progress = NULL; //props
    int ret = -1, id = 0;
    cJSON *root_props= 0;
    char *propsbuf = NULL;
    id =  misc_generate_random_id();
    root_props=cJSON_CreateObject();
    item_id = cJSON_CreateNumber(id);
    item_method = cJSON_CreateString("props");
    item_params = cJSON_CreateObject();
    item_progress = cJSON_CreateNumber(progress);//����
    cJSON_AddItemToObject(root_props, "id", item_id);
    cJSON_AddItemToObject(root_props, "method", item_method);
    cJSON_AddItemToObject(root_props, "params", item_params);
	cJSON_AddItemToObject(item_params,"ota_progress", item_progress);
    propsbuf = cJSON_Print(root_props);
    ret = miio_send_to_cloud(propsbuf, strlen(propsbuf));
    cJSON_Delete(root_props);
    return ret;
}

/*
 * interface
 */
int ota_get_state_ack(int mid, int type, int status, int progress)
{
    cJSON *item_id,*item_result = NULL; //ack msg
    int ret = -1, id = 0;
    cJSON *root_ack= 0;
    char *ackbuf = NULL;
    char *ota_state[OTA_STATE_BUSY+1] = {"idle", "downloading", "dowloaded", "installing", "wait_install", "installed", "failed", "busy"};
    root_ack=cJSON_CreateObject();
    item_id = cJSON_CreateNumber(id);
    item_result = cJSON_CreateArray();
    cJSON_AddItemToObject(root_ack, "id", item_id);
    cJSON_AddItemToObject(root_ack, "result", item_result);
    switch( type ) {
		case OTA_INFO_STATUS:
			cJSON_AddStringToObject(item_result, "result", ota_state[status]);
			break;
		case OTA_INFO_PROGRESS:
			cJSON_AddNumberToObject(item_result, "result", progress);
			break;
    }
    ackbuf = cJSON_Print(root_ack);
    ret = miio_send_to_cloud(ackbuf, strlen(ackbuf));
    cJSON_Delete(root_ack);
    return ret;
}

int ota_get_state(const char *msg)
{
    int ret = -1, id = 0;
    log_info("method:miIO.get_ota_state\n");
    ret = json_verify_get_int(msg, "id", &id);
    if (ret < 0) {
        return ret;
    }
    /********message body********/
	message_t message;
	msg_init(&message);
	message.message = MSG_KERNEL_OTA_REQUEST;
	message.sender = message.receiver = SERVER_MIIO;
	message.arg_in.duck = id;
	message.arg_pass.cat = OTA_INFO_STATUS;
//	server_kernel_message(&message);
	/***************************/
    return ret;
}

int ota_get_progress(const char *msg)
{
    int ret = -1, id = 0;
    log_info("method:miIO.get_ota_progress\n");
    ret = json_verify_get_int(msg, "id", &id);
    if (ret < 0 ) {
        return ret;
    }
    /********message body********/
	message_t message;
	msg_init(&message);
	message.message = MSG_KERNEL_OTA_REQUEST;
	message.sender = message.receiver = SERVER_MIIO;
	message.arg_in.duck = id;
	message.arg_pass.cat = OTA_INFO_PROGRESS;
//	server_kernel_message(&message);
	/***************************/
    return ret;
}

int ota_proc(int status, int progress, int id)
{
    int ret = 0;
    if( msg_id != id ) {
    	ret = -1;
    }
    else {
		if( status == OTA_STATE_DOWNLOADED ) {
			config.status = OTA_STATE_DOWNLOADED;
			ota_push_state(config.status, OTA_ERR_NONE);
		}
		else if( status == OTA_STATE_INSTALLING ) {
			config.status = OTA_STATE_INSTALLING;
			ota_push_state(config.status, OTA_ERR_NONE);
		}
		else if (status == OTA_STATE_WAIT_INSTALL) {
			config.status = OTA_STATE_WAIT_INSTALL;
			ota_push_state(config.status, OTA_ERR_NONE);
		}
		else if (status == OTA_STATE_INSTALLED) {
			config.status = OTA_STATE_INSTALLED;
			ota_push_state(config.status, OTA_ERR_NONE);
		}
		else if (status == OTA_STATE_FAILED) {
			config.status = OTA_STATE_FAILED;
			ota_push_state(config.status, OTA_ERR_INSTALL_ERR);
		}
		else if (status == OTA_STATE_BUSY) {
			config.status = OTA_STATE_BUSY;
			ota_push_state(config.status, OTA_ERR_INSTALL_ERR);
		}
    }
    /********message body********/
	message_t message;
	msg_init(&message);
	message.message = MSG_KERNEL_OTA_REPORT_ACK;
	message.sender = message.receiver = SERVER_MIIO;
	message.arg_in.duck = id;
	message.result = ret;
//	server_kernel_message(&message);
	/***************************/
    return ret;
}

int ota_init(const char *msg)
{
	ota_config_t	config;
    cJSON *json,*object = NULL;
    cJSON *item_id,*item_result = NULL;
    char proc[32] = {0};
    char mode[32] = {0};
    int ret = -1, id = 0;
    cJSON *root_ack= 0;
    char *ackbuf = NULL;
    char *ptr = NULL;
    int ota_mode = 0;
    int ota_proc = 0;
    log_info("method:miIO.ota\n");
    ret = json_verify_get_int(msg, "id", &id);
    json=cJSON_Parse(msg);
    object = cJSON_GetObjectItem(json,"params");
    if(object) {
        cJSON *item_app_url = cJSON_GetObjectItem(object,"app_url");
        if(item_app_url) {
            sprintf(config.url,"%s",item_app_url->valuestring);
        }
        cJSON *item_file_md5 = cJSON_GetObjectItem(object,"file_md5");
        if(item_file_md5) {
            sprintf(config.md5,"%s",item_file_md5->valuestring);
        }
        cJSON *item_proc = cJSON_GetObjectItem(object,"proc");
        if(item_proc) {
            sprintf(proc,"%s",item_proc->valuestring);
        }
        cJSON *item_mode = cJSON_GetObjectItem(object,"mode");
        if(item_mode) {
            sprintf(mode,"%s",item_mode->valuestring);
        }
        log_info("params: app_url:%s, file_md5:%s, proc:%s, mode:%s\n",config.url,config.md5,proc,mode);
    }
    if(strlen(mode) != 0) {
        ptr = strstr(mode, "silent");
        if(ptr) {
            config.mode = OTA_MODE_SILENT;
        }
        else {
            config.mode = OTA_MODE_NORMAL;
        }
    }
    else {
    	config.mode = OTA_MODE_NORMAL;
    }
    log_info("mode is %s/%d\n",mode,config.mode);
    if(strlen(proc) != 0) {
        ptr = strstr(proc, "dnld");
        if(ptr) {
            ptr = strstr(proc, "install");
            if(ptr) {
            	config.proc = OTA_PROC_DNLD_INSTALL;
            }
            else {
            	config.proc = OTA_PROC_DNLD;
            }
        }
        else {
            ptr = strstr(proc, "install");
            if(ptr) {
            	config.proc = OTA_PROC_INSTALL;
            }
        }
    }
    else {
    	config.proc = OTA_PROC_DNLD_INSTALL;
    }
    log_info("proc is %s/%d\n",proc,config.proc);
//
	msg_id = misc_generate_random_id();
    /********message body********/
	message_t message;
	msg_init(&message);
	message.message = MSG_KERNEL_OTA_DOWNLOAD;
	message.sender = message.receiver = SERVER_MIIO;
	message.arg_in.cat = OTA_TYPE_APPLICATION;
	message.arg_in.dog = config.mode;
	message.arg_in.chick = config.proc;
	message.arg_in.duck = msg_id;
	message.arg = config.url;
	message.arg_size = strlen(config.url);
	message.extra = config.md5;
	message.extra_size = strlen(config.md5);
//	server_kernel_message(&message);
	/***************************/
    root_ack=cJSON_CreateObject();
    item_id = cJSON_CreateNumber(id);
    item_result = cJSON_CreateArray();
    cJSON_AddItemToObject(root_ack, "id", item_id);
    cJSON_AddItemToObject(root_ack, "result", item_result);
    cJSON_AddStringToObject(item_result, "result", "OK");
    ackbuf = cJSON_Print(root_ack);
    ret = miio_send_to_cloud(ackbuf, strlen(ackbuf));
    cJSON_Delete(root_ack);
    cJSON_Delete(json);
    return ret;
}
