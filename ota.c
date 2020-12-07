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
#include "../../server/kernel/kernel_interface.h"
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
    log_qcy(DEBUG_INFO,"-----into ----ota_report_state---\n");
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
        		-33001,
				-33002,
				-33003,
				-33004,
				-33005,
				-33006,
				-33007,
				-33020,
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
    //log_qcy(DEBUG_INFO,"ota_push_state-----propsbuf=%s\n",propsbuf);
    cJSON_Delete(root_props);
    return ret;
}

static int ota_push_progress(int progress)
{
    log_qcy(DEBUG_INFO,"-----into ----ota_report_progress---\n");
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
    //log_qcy(DEBUG_INFO,"propsbuf-----propsbuf=%s\n",propsbuf);
    cJSON_Delete(root_props);
    return ret;
}

/*
 * interface
 */
int ota_get_state_ack(int did, int type, int status, int progress)
{
    //log_qcy(DEBUG_INFO,"---ota_get_state_ack-  status=%d -- progress=%d  --did=%d---type-%d\n",status,progress,did,type);
    cJSON *item_id,*item_result = NULL; //ack msg
    int ret = -1;
    cJSON *root_ack= 0;
    char *ackbuf = NULL;
    char *ota_state[OTA_STATE_BUSY+1] = {"idle", "downloading", "dowloaded", "installing", "wait_install", "installed", "failed", "busy"};
    root_ack=cJSON_CreateObject();
    item_id = cJSON_CreateNumber(did);
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
    //log_qcy(DEBUG_INFO,"ota_get_state and_progress ack-----ackbuf=%s\n",ackbuf);
    cJSON_Delete(root_ack);
    return ret;
}

int ota_get_state(const char *msg)
{
    int ret = -1, id = 0;
    log_qcy(DEBUG_SERIOUS, "method:miIO.get_ota_state");
    ret = json_verify_get_int(msg, "id", &id);
    if (ret < 0) {
        return ret;
    }
    /********message body********/
	message_t message;
	msg_init(&message);
	message.message = MSG_KERNEL_OTA_REQUEST;
	message.sender = message.receiver = SERVER_MIIO;
    message.arg_pass.cat = id;
	message.arg_in.cat = OTA_INFO_STATUS;
	message.arg_pass.chick = OTA_INFO_STATUS;
	manager_common_send_message(SERVER_KERNEL,  &message);
	/***************************/
	//log_qcy(DEBUG_INFO,"------send msg  ota_get_state end-----\n");
    return ret;
}

int ota_get_progress(const char *msg)
{
    int ret = -1, id = 0;
    log_qcy(DEBUG_SERIOUS, "method:miIO.get_ota_progress");
    ret = json_verify_get_int(msg, "id", &id);
    if (ret < 0 ) {
        return ret;
    }
    /********message body********/
	message_t message;
	msg_init(&message);
	message.message = MSG_KERNEL_OTA_REQUEST;
	message.sender = message.receiver = SERVER_MIIO;
    message.arg_pass.cat = id;
	message.arg_in.cat = OTA_INFO_PROGRESS;
	message.arg_pass.chick = OTA_INFO_PROGRESS;
	manager_common_send_message(SERVER_KERNEL,  &message);
//	log_qcy(DEBUG_INFO,"------send msg  ota_get_progress end-----\n");
	/***************************/
    return ret;
}

int ota_proc(int status, int progress, int err_id)
{
    int ret = 0;
    //log_qcy(DEBUG_INFO,"---ota_proc-func-  status=%d -- progress=%d  --err_id-%d\n",status,progress,err_id);
    	if( status == OTA_STATE_IDLE ) {
			config.status = OTA_STATE_IDLE;
			ret=ota_push_state(config.status, err_id);
			if(err_id != OTA_ERR_NONE)
			ret=ota_push_progress(progress);
		}

		if( status == OTA_STATE_DOWNLOADING ) {
			config.status = OTA_STATE_DOWNLOADING;
			ret=ota_push_state(config.status, err_id);
			if(err_id != OTA_ERR_NONE)
			ret=ota_push_progress(progress);
		}

		if( status == OTA_STATE_DOWNLOADED ) {
			config.status = OTA_STATE_DOWNLOADED;
			ret=ota_push_state(config.status, err_id);
			if(err_id != OTA_ERR_NONE)
			ret=ota_push_progress(progress);
		}
		else if( status == OTA_STATE_INSTALLING ) {
			config.status = OTA_STATE_INSTALLING;
			ret=ota_push_state(config.status, err_id);
			if(err_id != OTA_ERR_NONE)
			ret=ota_push_progress(progress);
		}
		else if (status == OTA_STATE_WAIT_INSTALL) {
			config.status = OTA_STATE_WAIT_INSTALL;
			ret=ota_push_state(config.status, err_id);
			if(err_id != OTA_ERR_NONE)
			ret=ota_push_progress(progress);
		}
		else if (status == OTA_STATE_INSTALLED) {
			config.status = OTA_STATE_INSTALLED;
			ret=ota_push_state(config.status, err_id);
			if(err_id != OTA_ERR_NONE)
			ret=ota_push_progress(progress);
		}
		else if (status == OTA_STATE_FAILED) {
			config.status = OTA_STATE_FAILED;
			ret=ota_push_state(config.status, err_id);
			if(err_id != OTA_ERR_NONE)
			ret=ota_push_progress(progress);
		}
		else if (status == OTA_STATE_BUSY) {
			config.status = OTA_STATE_BUSY;
			ret=ota_push_state(config.status, err_id);
			if(err_id != OTA_ERR_NONE)
			ret=ota_push_progress(progress);
		}

    return ret;
}

int ota_init(const char *msg)
{
	ota_config_t	config;
    cJSON *json,*object = NULL;
    char proc[32] = {0};
    char mode[32] = {0};
    int ret = -1, id = 0;
    char *ptr = NULL;
    log_qcy(DEBUG_SERIOUS, "method:miIO.ota");
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
        log_qcy(DEBUG_SERIOUS, "params: app_url:%s, file_md5:%s, proc:%s, mode:%s",config.url,config.md5,proc,mode);
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
    log_qcy(DEBUG_SERIOUS, "mode is %s/%d",mode,config.mode);
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
    log_qcy(DEBUG_SERIOUS, "proc is %s/%d",proc,config.proc);
//
	//msg_id = misc_generate_random_id();
    /********message body********/
	message_t message;
	msg_init(&message);
	message.message = MSG_KERNEL_OTA_DOWNLOAD;
	message.sender = message.receiver = SERVER_MIIO;
	message.arg_in.dog = config.mode;
	message.arg_in.chick = config.proc;
    message.arg_pass.cat = id;
	message.arg = config.url;
	message.arg_size = strlen(config.url);
	message.extra = config.md5;
	message.extra_size = strlen(config.md5);
	manager_common_send_message(SERVER_KERNEL,  &message);

	/***************************/
    cJSON_Delete(json);
    return ret;
}


int ota_down_ack(int id, int result)
{
    cJSON *item_id,*item_result = NULL;
    int ret = -1;
    cJSON *root_ack= 0;
    char *ackbuf = NULL;
    log_qcy(DEBUG_SERIOUS, "method:otadown ack");

	/*************sen to  cloud**************/
    root_ack=cJSON_CreateObject();
    item_id = cJSON_CreateNumber(id);
    item_result = cJSON_CreateArray();
    cJSON_AddItemToObject(root_ack, "id", item_id);
    cJSON_AddItemToObject(root_ack, "result", item_result);
    if(!result){
    cJSON_AddStringToObject(item_result, "result", "OK");
    }
    else
    {
        cJSON_AddStringToObject(item_result, "result", "ERROR");
    }
    ackbuf = cJSON_Print(root_ack);
    ret = miio_send_to_cloud(ackbuf, strlen(ackbuf));
    //log_qcy(DEBUG_INFO,"ota_init-----ackbuf=%s\n",ackbuf);
    cJSON_Delete(root_ack);
    return ret;
}



