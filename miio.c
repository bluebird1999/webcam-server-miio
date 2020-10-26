/*
 * mi.c
 *
 *  Created on: Aug 13, 2020
 *      Author: ning
 */

/*
 * header
 */
//system header
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bits/socket.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <pthread.h>
#include <json-c/json.h>
#include <miss.h>
#include <malloc.h>
#include <dmalloc.h>
//program header
#include "../../tools/tools_interface.h"
#include "../../server/miss/miss_local.h"
#include "../../server/miss/miss_interface.h"
#include "../../manager/manager_interface.h"
#include "../../server/video/video_interface.h"
#include "../../server/audio/audio_interface.h"
#include "../../server/recorder/recorder_interface.h"
#include "../../server/device/device_interface.h"
//server header
#include "mi.h"
#include "miio.h"
#include "miio_interface.h"
#include "miio_message.h"
#include "ntp.h"
#include "ota.h"
#include "config.h"

/*
 * static
 */
//variable
static message_buffer_t		message;
static server_info_t 		info;
static miio_config_t		config;
static miio_info_t			miio_info;
static int					message_id;
static struct msg_helper_t 	msg_helper;
static int					did_rpc_id;

//function
//common
static void *server_func(void);
static int server_message_proc(void);
static int server_release(void);
static int server_get_status(int type);
static int server_set_status(int type, int st);
static void server_thread_termination(void);
//specific
static int miio_socket_init(void);
static int miio_socket_send(char *buf, int size);
static void *miio_rsv_func(void *arg);
static void *miio_poll_func(void *arg);
static int miio_rsv_init(void *param);
static int miio_poll_init(void *param);
static void miio_close_retry(void);
static int miio_recv_handler_block(int sockfd, char *msg, int msg_len);
static int miio_recv_handler(int sockfd);
static int miio_message_dispatcher(const char *msg, int len);
static int miio_event(const char *msg);
static int miio_result_parse(const char *msg,int id);
static int miio_set_properties(const char *msg);
static int miio_get_properties(const char *msg);
static int miio_get_properties_vlaue(int id, char *did,int piid,int siid,cJSON *json);
static int miio_set_properties_vlaue(int id, char *did,int piid,int siid,cJSON *value_json,cJSON *result_json);
static void miio_request_local_status(void);
static int miio_routine_1000ms(void);
static int rpc_send_msg(int msg_id, const char *method, const char *params);
static int rpc_send_report(int msg_id, const char *method, const char *params);
static int miio_get_properties_callback(message_arg_t arg_pass, int result, int size, void *arg);
static int miio_set_properties_callback(message_arg_t arg_pass, int result, int size, void *arg);
static int send_complicate_request(message_t *msg, int message, int receiver, int id, int piid, int siid, int module, void *arg, int size, void* func);
static int miio_action(const char *msg);
static int miio_action_func(int id,char *did,int siid,int aiid,cJSON *json_in);
static int miio_action_func_ack(message_arg_t arg_pass, int result, int size, void *arg);
static int miot_properties_changed(int piid,int siid,int value, char* string);
static int miio_query_device_did(void);
static int miio_parse_did(char*);

/*
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 */

/*
 * helper
 */
static int send_complicate_request(message_t *msg, int message, int receiver, int id, int piid, int siid, int module, void *arg, int size, void* func)
{
	/********message body********/
	msg->message = message;
	msg->sender = msg->receiver = SERVER_MIIO;
	msg->arg_pass.cat = id;
	msg->arg_pass.dog = piid;
	msg->arg_pass.chick = siid;
	msg->arg_pass.handler = func;
	msg->arg_in.cat = module;
	msg->arg = arg;
	msg->arg_size = size;
	/****************************/
	switch(receiver) {
	case SERVER_DEVICE:
		server_device_message(msg);
		break;
	case SERVER_VIDEO:
		server_video_message(msg);
		break;
	case SERVER_KERNEL:
//		server_kernel_message(msg);
		break;
	case SERVER_RECORDER:
		server_recorder_message(msg);
		break;
	}
}

static int miio_routine_1000ms(void)
{
	int ret = 0;
	message_t msg;
	if( miio_info.miio_status != STATE_CLOUD_CONNECTED)
		miio_request_local_status();
	if( !miio_info.time_sync )
		ntp_get_local_time();
	if( config.iot.board_type && !miio_info.did_acquired )
		miio_query_device_did();
	if( miio_info.miio_status == STATE_CLOUD_CONNECTED
		&& miio_info.time_sync ) {
		if( config.iot.board_type && !miio_info.did_acquired)
			return ret;
		/********message body********/
		msg_init(&msg);
		msg.message = MSG_MANAGER_TIMER_REMOVE;
		msg.arg_in.handler = miio_routine_1000ms;
		msg.receiver = msg.sender = SERVER_MIIO;
		manager_message(&msg);
		/****************************/
	}
	return ret;
}

static int miio_socket_init(void)
{
	struct sockaddr_in serveraddr;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		log_err("Create socket error: %m\n");
		return -1;
	}
	bzero(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = inet_addr(MIIO_IP);
	serveraddr.sin_port = htons(MIIO_PORT);
	if (connect(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
		log_err("Connect to otd error: %s:%d\n", MIIO_IP, MIIO_PORT);
        close(sockfd);
		return -1;
	}
	return sockfd;
}

static int miio_socket_send(char *buf, int size)
{
	ssize_t sent = 0;
	ssize_t ret = 0;
	ret = pthread_rwlock_wrlock(&info.lock);
	if (ret) {
		log_err("add session wrlock fail, ret = %d\n", ret);
		return -1;
	}
	if (msg_helper.otd_sock <= 0) {
		log_warning("sock not ready: %d\n", msg_helper.otd_sock);
		goto end;
	}
	if (size == 0)
		goto end;
	log_err("send: %s\n",buf);
	while (size > 0) {
		ret = send(msg_helper.otd_sock, buf + sent, size, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (ret < 0) {
			// FIXME EAGAIN
			log_err("%s: send error: %s(%m)\n", __FILE__, __func__);
			goto end;
		}
		if (ret < size)
			log_warning("Partial written\n");
		sent += ret;
		size -= ret;
	}
end:
	ret = pthread_rwlock_unlock(&info.lock);
	if (ret) {
		log_err("add session unlock fail, ret = %d\n", ret);
	}
	return sent;
}

static int miio_query_device_did(void)
{
	int ret = 0;
  	did_rpc_id = misc_generate_random_id();
	char ackbuf[1024] = {0x00};
	struct json_object *send_object = json_object_new_object();
	json_object_object_add(send_object, "id", json_object_new_int(did_rpc_id));
	json_object_object_add(send_object, "method", json_object_new_string("local.query_did"));
	sprintf(ackbuf, "%s", json_object_to_json_string_ext(send_object, 1));
	json_object_put(send_object);
	ret = miio_socket_send(ackbuf, strlen(ackbuf));
	return ret;
}

static void miio_request_local_status(void)
{
	char buf[128];
	char *reg_template = "{\"id\":%d,\"method\":\"local.query_status\"}";
    int id = 0;
    id =  misc_generate_random_id();
	snprintf(buf, sizeof(buf) ,reg_template,id);
	miio_socket_send(buf, strlen(buf));
}

static int miio_get_properties_callback(message_arg_t arg_pass, int result, int size, void *arg)
{
    cJSON *item_id,*item_result = NULL,*item_result_param1 = NULL; //ack msg
    cJSON *root_ack = 0;
    int ret = -1;
	char *ackbuf = 0;
	cJSON *item = NULL;
    char did[32];
	//reply
    root_ack=cJSON_CreateObject();
    item = cJSON_CreateNumber(arg_pass.cat);
    cJSON_AddItemToObject(root_ack,"id",item);
    item_result = cJSON_CreateArray();
    item_result_param1 = cJSON_CreateObject();
    //result
	memset(did,0,MAX_SYSTEM_STRING_SIZE);
	sprintf(did, "%s", config.device.did);
	item = cJSON_CreateString(did);
    cJSON_AddItemToObject(item_result_param1,"did",item);
    item = cJSON_CreateNumber(arg_pass.chick);
    cJSON_AddItemToObject(item_result_param1,"siid",item);
    item = cJSON_CreateNumber(arg_pass.dog);
    cJSON_AddItemToObject(item_result_param1,"piid",item);
    //find property
    switch(arg_pass.chick) {
		case IID_2_CameraControl:
			if( !result ) {
				if( arg_pass.dog == IID_2_1_On ) item = cJSON_CreateNumber(((video_iot_config_t*)arg)->on);
				else if( arg_pass.dog == IID_2_2_ImageRollover) item = cJSON_CreateNumber(((video_iot_config_t*)arg)->image_roll);
				else if( arg_pass.dog == IID_2_3_NightShot) item = cJSON_CreateNumber(((video_iot_config_t*)arg)->night);
				else if( arg_pass.dog == IID_2_4_TimeWatermark) item = cJSON_CreateNumber(((video_iot_config_t*)arg)->watermark);
				else if( arg_pass.dog == IID_2_5_WdrMode) item = cJSON_CreateNumber(((video_iot_config_t*)arg)->wdr);
				else if( arg_pass.dog == IID_2_6_GlimmerFullColor) item = cJSON_CreateNumber(((video_iot_config_t*)arg)->glimmer);
				else if( arg_pass.dog == IID_2_7_RecordingMode) item = cJSON_CreateNumber(((recorder_iot_config_t*)arg)->recording_mode);
				cJSON_AddItemToObject(item_result_param1,"value",item);
				item = cJSON_CreateNumber(0);
				cJSON_AddItemToObject(item_result_param1,"code",item);
			}
			else {
				item = cJSON_CreateNumber(-4004);
				cJSON_AddItemToObject(item_result_param1,"code",item);
			}
			break;
		case IID_3_IndicatorLight:
			if( !result ) {
/*				tmp = (device_iot_config_t*)arg;
				if( arg_pass.dog == IID_3_1_On) item = cJSON_CreateNumber(tmp->on);
				cJSON_AddItemToObject(item_result_param1,"value",item);
				item = cJSON_CreateNumber(0);
				cJSON_AddItemToObject(item_result_param1,"code",item);
*/
			}
			else {
				item = cJSON_CreateNumber(-4004);
				cJSON_AddItemToObject(item_result_param1,"code",item);
			}
			break;
		case IID_4_MemoryCardManagement:
			if( !result ) {
				if( arg_pass.dog == IID_4_1_Status) item = cJSON_CreateNumber( ((device_iot_config_t*)arg)->sd_iot_info.plug );
				else if( arg_pass.dog == IID_4_2_StorageTotalSpace) item = cJSON_CreateNumber( ((device_iot_config_t*)arg)->sd_iot_info.totalBytes / 1024 );
				else if( arg_pass.dog == IID_4_3_StorageFreeSpace) item = cJSON_CreateNumber( ((device_iot_config_t*)arg)->sd_iot_info.freeBytes / 1024 );
				else if( arg_pass.dog == IID_4_4_StorageUsedSpace) item = cJSON_CreateNumber( ((device_iot_config_t*)arg)->sd_iot_info.usedBytes / 1024 );
				cJSON_AddItemToObject(item_result_param1,"value",item);
				item = cJSON_CreateNumber(0);
				cJSON_AddItemToObject(item_result_param1,"code",item);
			}
			else {
				item = cJSON_CreateNumber(-4004);
				cJSON_AddItemToObject(item_result_param1,"code",item);
			}
			break;
		case IID_5_MotionDetection:
			if( !result ) {
				if( arg_pass.dog == IID_5_1_MotionDetection) item = cJSON_CreateNumber(((video_iot_config_t*)arg)->motion_switch);
				else if( arg_pass.dog == IID_5_2_AlarmInterval) item = cJSON_CreateNumber(((video_iot_config_t*)arg)->motion_alarm);
				else if( arg_pass.dog == IID_5_3_DetectionSensitivity) item = cJSON_CreateNumber(((video_iot_config_t*)arg)->motion_sensitivity);
				else if( arg_pass.dog == IID_5_4_MotionDetectionStartTime) item = cJSON_CreateString(((video_iot_config_t*)arg)->motion_start);
				else if( arg_pass.dog == IID_5_5_MotionDetectionEndTime) item = cJSON_CreateString(((video_iot_config_t*)arg)->motion_end);
				cJSON_AddItemToObject(item_result_param1,"value",item);
				item = cJSON_CreateNumber(0);
				cJSON_AddItemToObject(item_result_param1,"code",item);
			}
			else {
				item = cJSON_CreateNumber(-4004);
				cJSON_AddItemToObject(item_result_param1,"code",item);
			}
			break;
		case IID_6_MoreSet:
			if( !result ) {
				if(arg_pass.dog == IID_6_1_Ipaddr) {
/*					tmp = (kernel_iot_config_t*)arg;
					item = cJSON_CreateNumber(tmp->custom_distortion);
*/
				}
				else if(arg_pass.dog == IID_6_2_MacAddr) {
/*					tmp = (kernel_iot_config_t*)arg;
					item = cJSON_CreateNumber(tmp->custom_distortion);
*/
				}
				else if(arg_pass.dog == IID_6_3_WifiName) {
/*					tmp = (kernel_iot_config_t*)arg;
					item = cJSON_CreateNumber(tmp->custom_distortion);
*/
				}
				else if(arg_pass.dog == IID_6_4_WifiRssi) {
/*					tmp = (kernel_iot_config_t*)arg;
					item = cJSON_CreateNumber(tmp->custom_distortion);
*/
				}
				else if(arg_pass.dog == IID_6_5_CurrentMode) {
/*					tmp = (kernel_iot_config_t*)arg;
					item = cJSON_CreateNumber(tmp->custom_distortion);
*/
				}
				else if(arg_pass.dog == IID_6_6_TimeZone) {
/*					tmp = (kernel_iot_config_t*)arg;
					item = cJSON_CreateNumber(tmp->custom_distortion);
*/
				}
				else if(arg_pass.dog == IID_6_7_StorageSwitch) {
					item = cJSON_CreateNumber(((recorder_iot_config_t*)arg)->local_save);
				}
				else if(arg_pass.dog == IID_6_8_CloudUploadEnable) {
//					tmp = (micloud_iot_config_t*)arg;
//					item = cJSON_CreateNumber(tmp->custom_cloud_save);
				}
				else if(arg_pass.dog == IID_6_9_MotionAlarmPush) item = cJSON_CreateNumber(((video_iot_config_t*)arg)->custom_warning_push);
				else if(arg_pass.dog == IID_6_10_DistortionSwitch) item = cJSON_CreateNumber(((video_iot_config_t*)arg)->custom_distortion);
				cJSON_AddItemToObject(item_result_param1,"value",item);
				item = cJSON_CreateNumber(0);
				cJSON_AddItemToObject(item_result_param1,"code",item);
			}
			else {
				item = cJSON_CreateNumber(-4004);
				cJSON_AddItemToObject(item_result_param1,"code",item);
			}
			break;
    }
    cJSON_AddItemToArray(item_result,item_result_param1);
    cJSON_AddItemToObject(root_ack,"result",item_result);
    //socket send
	ackbuf = cJSON_Print(root_ack);
    ret = miio_socket_send(ackbuf, strlen(ackbuf));
    free(ackbuf);
    cJSON_Delete(root_ack);
    return ret;
}

static int miio_get_properties_vlaue(int id,char *did,int piid,int siid,cJSON *json)
{
	int ret = -1;
	message_t msg;
	msg_init(&msg);
    cJSON *item = NULL;
    item = cJSON_CreateString(did);
    cJSON_AddItemToObject(json,"did",item);
    item = cJSON_CreateNumber(siid);
    cJSON_AddItemToObject(json,"siid",item);
    item = cJSON_CreateNumber(piid);
    cJSON_AddItemToObject(json,"piid",item);
    switch(siid){
		case IID_1_DeviceInformation: {
			if(piid == IID_1_1_Manufacturer) {
				char manufacturer[MAX_SYSTEM_STRING_SIZE];
				memset(manufacturer,0,MAX_SYSTEM_STRING_SIZE);
				sprintf(manufacturer, "%s", config.device.vendor);
				item = cJSON_CreateString(manufacturer);
				cJSON_AddItemToObject(json,"value",item);
			}
			else if(piid == IID_1_2_Model) {
				char model[MAX_SYSTEM_STRING_SIZE];
				memset(model,0,MAX_SYSTEM_STRING_SIZE);
				sprintf(model, "%s", config.device.model);
				item = cJSON_CreateString(model);
				cJSON_AddItemToObject(json,"value",item);
			}
			else if(piid == IID_1_3_SerialNumber) {
				char serial[MAX_SYSTEM_STRING_SIZE];
				memset(serial,0,MAX_SYSTEM_STRING_SIZE);
				if( config.iot.board_type == 0)
					sprintf(serial, "%s", config.device.key);
				else if( config.iot.board_type == 1)
					sprintf(serial, "%s", config.device.did);
				item = cJSON_CreateString(serial);
				cJSON_AddItemToObject(json,"value",item);
			}
			else if(piid == IID_1_4_FirmwareRevision) {
				char revision[MAX_SYSTEM_STRING_SIZE];
				memset(revision,0,MAX_SYSTEM_STRING_SIZE);
				sprintf(revision, "%s", APPLICATION_VERSION_STRING);
				item = cJSON_CreateString(revision);
				cJSON_AddItemToObject(json,"value",item);
			}
			break;
		}
		case IID_2_CameraControl:
		case IID_5_MotionDetection:
			send_complicate_request(&msg, MSG_VIDEO_GET_PARA, SERVER_VIDEO, id, piid, siid, 0, 0, 0, miio_get_properties_callback);
			return -1;
		case IID_3_IndicatorLight:
		case IID_4_MemoryCardManagement:
			send_complicate_request(&msg, MSG_DEVICE_GET_PARA, SERVER_DEVICE, id, piid, siid, DEVICE_CTRL_SD_INFO, 0, 0,miio_get_properties_callback);
			return -1;
		case IID_6_MoreSet:
			if(	(piid == IID_6_9_MotionAlarmPush) || (piid == IID_6_10_DistortionSwitch) ) {
				send_complicate_request(&msg, MSG_VIDEO_GET_PARA, SERVER_VIDEO, id, piid, siid, 0, 0, 0,miio_get_properties_callback);
				return -1;
			}
			else if( piid == IID_6_7_StorageSwitch ) {
				send_complicate_request(&msg, MSG_RECORDER_GET_PARA, SERVER_RECORDER, id, piid, siid, 0, 0, 0,miio_get_properties_callback);
				return -1;
			}
/* wait for other server
			else if( piid == IID_6_8_CloudUploadEnable ) {
				send_complicate_request(&msg, MSG_MICLOUD_GET_PARA, SERVER_MICLOUD, id, piid, siid, 0, 0, 0,miio_get_properties_callback);
				return -1;
			}
			else if( 	(piid == IID_6_1_Ipaddr) || (piid == IID_6_2_MacAddr) || (piid == IID_6_3_WifiName) ||
					(piid == IID_6_4_WifiRssi) || (piid == IID_6_5_CurrentMode) ) {
				send_complicate_request(&msg, MSG_KERNEL_GET_PARA, SERVER_KERNEL, id, piid, siid, 0, 0, 0,miio_get_properties_callback);
				return -1;
			}
			else if(piid == IID_6_6_TimeZone) {
				send_complicate_request(&msg, MSG_KERNEL_GET_PARA, SERVER_KERNEL, id, piid, siid, 0, 0, 0,miio_get_properties_callback);
				return -1;
			}
*/
			break;
		default:
			return -1;
	}
	item = cJSON_CreateNumber(0);
	cJSON_AddItemToObject(json,"code",item);
	ret = 0;
    return ret;
}

static int miio_get_properties(const char *msg)
{
    cJSON *json,*arrayItem,*object = NULL;
    cJSON *item_id,*item_result = NULL,*item_result_param1 = NULL; //ack msg
    int i = 0;
    char did[32];
    int piid = 0,siid = 0;
	int ret = -1, id = 0;
    cJSON *root_ack = 0;
	char *ackbuf = 0;
	log_info("----%s--------",msg);
	//get id
	ret = json_verify_get_int(msg, "id", &id);
	if (ret < 0) return ret;
    json=cJSON_Parse(msg);
    arrayItem = cJSON_GetObjectItem(json,"params");
    //add ack json msg
    root_ack=cJSON_CreateObject();
    item_id = cJSON_CreateNumber(id);
    cJSON_AddItemToObject(root_ack,"id",item_id);
    item_result = cJSON_CreateArray();//
    if(arrayItem) {
        object = cJSON_GetArrayItem(arrayItem,i);
        while(object) {
        	item_result_param1 = cJSON_CreateObject();
            cJSON *item_did = cJSON_GetObjectItem(object,"did");
            if(item_did) {
                sprintf(did,"%s",item_did->valuestring);
            }
            cJSON *item_piid = cJSON_GetObjectItem(object,"piid");
            if(item_piid) {
                piid = item_piid->valueint;
            }
            cJSON *item_siid = cJSON_GetObjectItem(object,"siid");
            if(item_siid) {
                siid = item_siid->valueint;
            }
            ret = miio_get_properties_vlaue(id,did,piid,siid,item_result_param1);
            if(ret == 0) {
            	cJSON_AddItemToArray(item_result,item_result_param1);
            }
            i++;
            object = cJSON_GetArrayItem(arrayItem,i);
        }
        if( cJSON_GetArraySize(item_result)>0 )
        	cJSON_AddItemToObject(root_ack,"result",item_result);
        else {
        	ret = 0;
        	goto exit;
        }
    }
    else {
        goto exit;
    }
	ackbuf = cJSON_Print(root_ack);
	ret = miio_socket_send(ackbuf, strlen(ackbuf));
    free(ackbuf);
exit:
    cJSON_Delete(root_ack);
    cJSON_Delete(json);
    return ret;
}

static int miio_set_properties_callback(message_arg_t arg_pass, int result, int size, void *arg)
{
    cJSON *item_id,*item_result = NULL,*item_result_param1 = NULL; //ack msg
	int ret = -1;
	message_t msg;
    cJSON *root_ack = 0;
	char *ackbuf = 0;
	cJSON *item = NULL;
    char did[32];
	//reply
    root_ack=cJSON_CreateObject();
    item = cJSON_CreateNumber(arg_pass.cat);
    cJSON_AddItemToObject(root_ack,"id",item);
    item_result = cJSON_CreateArray();
    item_result_param1 = cJSON_CreateObject();
    //result
	memset(did,0,MAX_SYSTEM_STRING_SIZE);
	sprintf(did, "%s", config.device.did);
	item = cJSON_CreateString(did);
    cJSON_AddItemToObject(item_result_param1,"did",item);
    item = cJSON_CreateNumber(arg_pass.chick);
    cJSON_AddItemToObject(item_result_param1,"siid",item);
    item = cJSON_CreateNumber(arg_pass.dog);
    cJSON_AddItemToObject(item_result_param1,"piid",item);
	if( !result ) {
		item = cJSON_CreateNumber(0);
		cJSON_AddItemToObject(item_result_param1,"code",item);
	}
	else {
		item = cJSON_CreateNumber(-4004);
		cJSON_AddItemToObject(item_result_param1,"code",item);
	}
    cJSON_AddItemToArray(item_result,item_result_param1);
    cJSON_AddItemToObject(root_ack,"result",item_result);
    //socket send
	ackbuf = cJSON_Print(root_ack);
    ret = miio_socket_send(ackbuf, strlen(ackbuf));
    free(ackbuf);
    cJSON_Delete(root_ack);
    return ret;
}

static int miio_set_properties_vlaue(int id, char *did, int piid, int siid, cJSON *value_json, cJSON *result_json)
{
	int ret = -1;
    cJSON *item = NULL;
    int	save = 0;
	message_t msg;
	msg_init(&msg);
    item = cJSON_CreateString(did);
    cJSON_AddItemToObject(result_json,"did",item);
    item = cJSON_CreateNumber(siid);
    cJSON_AddItemToObject(result_json,"siid",item);
    item = cJSON_CreateNumber(piid);
    cJSON_AddItemToObject(result_json,"piid",item);
    switch(siid){
	case IID_2_CameraControl:
		if(piid == IID_2_1_On) {
            log_info("IID_2_1_On:%d ",value_json->valueint);
            if( value_json->valueint == 1)
            	send_complicate_request(&msg, MSG_VIDEO_START, SERVER_VIDEO, id, piid, siid, 0, 0, 0,miio_set_properties_callback);
            else
    			send_complicate_request(&msg, MSG_VIDEO_STOP, SERVER_VIDEO, id, piid, siid, 0, 0, 0,miio_set_properties_callback);
			return -1;
		}
		else if(piid == IID_2_2_ImageRollover) {
            log_info("IID_2_2_ImageRollover:%d \n",value_json->valueint);
			send_complicate_request(&msg, MSG_VIDEO_CTRL_EXT, SERVER_VIDEO, id, piid, siid,
					VIDEO_CTRL_IMAGE_ROLLOVER, &(value_json->valueint), sizeof(int),miio_set_properties_callback);
			return -1;
		}
		else if(piid == IID_2_3_NightShot) {
			log_info("IID_2_3_NightShot:%d ",value_json->valueint);
			send_complicate_request(&msg, MSG_VIDEO_CTRL_DIRECT, SERVER_VIDEO, id, piid, siid,
					VIDEO_CTRL_NIGHT_SHOT, &(value_json->valueint), sizeof(int),miio_set_properties_callback);
			return -1;
		}
		else if(piid == IID_2_4_TimeWatermark) {
			log_info("IID_2_4_TimeWatermark:%d ",value_json->valueint);
    		send_complicate_request(&msg, MSG_VIDEO_CTRL_EXT, SERVER_VIDEO, id, piid, siid,
    				VIDEO_CTRL_TIME_WATERMARK, &(value_json->valueint), sizeof(int),miio_set_properties_callback);
    		return -1;
		}
		else if(piid == IID_2_5_WdrMode) {
			log_info("IID_2_5_WdrMode:%d ",value_json->valueint);
			send_complicate_request(&msg, MSG_VIDEO_CTRL_DIRECT, SERVER_VIDEO, id, piid, siid,
					VIDEO_CTRL_WDR_MODE, &(value_json->valueint), sizeof(int),miio_set_properties_callback);
			return -1;
		}
		else if(piid == IID_2_6_GlimmerFullColor) {
			log_info("IID_2_6_GlimmerFullColor:%d ",value_json->valueint);
			send_complicate_request(&msg, MSG_VIDEO_CTRL_DIRECT, SERVER_VIDEO, id, piid, siid,
					VIDEO_CTRL_GLIMMER_FULL_COLOR, &(value_json->valueint), sizeof(int),miio_set_properties_callback);
			return -1;
		}
		else if(piid == IID_2_7_RecordingMode) {
			log_info("IID_2_7_RecordingMode:%d ",value_json->valueint);
			send_complicate_request(&msg, MSG_RECORDER_CTRL_DIRECT, SERVER_RECORDER, id, piid, siid,
					RECORDER_CTRL_RECORDING_MODE, &(value_json->valueint), sizeof(int),miio_set_properties_callback);
			return -1;
		}

		return -1;
	case IID_3_IndicatorLight:
		if(piid == IID_3_1_On) {
			log_info("IID_3_1_On:%d ",value_json->valueint);
			device_iot_config_t tmp;
			memset(&tmp, 0, sizeof(device_iot_config_t));
			tmp.led1_onoff = value_json->valueint;
			tmp.led2_onoff = value_json->valueint;
			send_complicate_request(&msg, MSG_DEVICE_CTRL_DIRECT, SERVER_DEVICE, id, piid, siid,
					DEVICE_CTRL_LED, &tmp, sizeof(int),miio_set_properties_callback);

			return -1;
		}
		break;
	case IID_4_MemoryCardManagement:
		break;
	case IID_5_MotionDetection:
		if(piid == IID_5_1_MotionDetection) {
			log_info("IID_5_1_MotionDetection:%d ",value_json->valueint);
    		send_complicate_request(&msg, MSG_VIDEO_CTRL, SERVER_VIDEO, id, piid, siid,
    				VIDEO_CTRL_MOTION_SWITCH, &(value_json->valueint), sizeof(int) ,miio_set_properties_callback);
    		return -1;
		}
		else if(piid == IID_5_2_AlarmInterval) {
			log_info("IID_5_2_AlarmInterval:%d ",value_json->valueint);
    		send_complicate_request(&msg, MSG_VIDEO_CTRL, SERVER_VIDEO, id, piid, siid,
    				VIDEO_CTRL_MOTION_ALARM_INTERVAL, &(value_json->valueint), sizeof(int) ,miio_set_properties_callback);
    		return -1;
		}
		else if(piid == IID_5_3_DetectionSensitivity) {
			log_info("IID_5_3_DetectionSensitivity:%d ",value_json->valueint);
    		send_complicate_request(&msg, MSG_VIDEO_CTRL, SERVER_VIDEO, id, piid, siid,
    				VIDEO_CTRL_MOTION_SENSITIVITY, &(value_json->valueint), sizeof(int) ,miio_set_properties_callback);
    		return -1;
		}
		else if(piid == IID_5_4_MotionDetectionStartTime) {
			log_info("IID_5_4_MotionDetectionStartTime:%s ",value_json->valuestring);
    		send_complicate_request(&msg, MSG_VIDEO_CTRL_DIRECT, SERVER_VIDEO, id, piid, siid,
    				VIDEO_CTRL_MOTION_START, value_json->valuestring, strlen(value_json->valuestring)+1 ,miio_set_properties_callback);
    		return -1;
		}
		else if(piid == IID_5_5_MotionDetectionEndTime) {
			log_info("IID_5_4_MotionDetectionEndTime:%s ",value_json->valuestring);
    		send_complicate_request(&msg, MSG_VIDEO_CTRL, SERVER_VIDEO, id, piid, siid,
    				VIDEO_CTRL_MOTION_END, value_json->valuestring, strlen(value_json->valuestring)+1 ,miio_set_properties_callback);
    		return -1;
		}
		break;
	case IID_6_MoreSet:
		if(piid == IID_6_6_TimeZone) {
			log_info("IID_6_6_TimeZone:%d ",value_json->valueint);
/*			send_complicate_request(&msg, MSG_KERNEL_CTRL_DIRECT, SERVER_KERNEL, id, piid, siid,
					KERNEL_CTRL_TIMEZONE, &(value_json->valueint), sizeof(int),miio_set_properties_callback);
*/
			return -1;
		}
		else if(piid == IID_6_7_StorageSwitch) {
			log_info("IID_6_7_StorageSwitch:%d ",value_json->valueint);
			send_complicate_request(&msg, MSG_RECORDER_CTRL_DIRECT, SERVER_RECORDER, id, piid, siid,
					RECORDER_CTRL_LOCAL_SAVE, &(value_json->valueint), sizeof(int),miio_set_properties_callback);
			return -1;
		}
		else if(piid == IID_6_8_CloudUploadEnable) {
			log_info("IID_6_8_CloudUploadEnable:%d ",value_json->valueint);
//			send_complicate_request(&msg, MSG_MICLOUD_CTRL_DIRECT, SERVER_MICLOUD, id, piid, siid,
//					MICLOUD_CTRL_CLOUD_SAVE, &(value_json->valueint), sizeof(int),miio_set_properties_callback);
			return -1;
		}
		else if(piid == IID_6_9_MotionAlarmPush) {
			log_info("IID_6_9_MotionAlarmPush:%d ",value_json->valueint);
			send_complicate_request(&msg, MSG_VIDEO_CTRL, SERVER_VIDEO, id, piid, siid,
					VIDEO_CTRL_CUSTOM_WARNING_PUSH, &(value_json->valueint), sizeof(int),miio_set_properties_callback);
			return -1;
		}
		else if(piid == IID_6_10_DistortionSwitch) {
			log_info("IID_6_10_DistortionSwitch:%d ",value_json->valueint);
			send_complicate_request(&msg, MSG_VIDEO_CTRL_DIRECT, SERVER_VIDEO, id, piid, siid,
					VIDEO_CTRL_CUSTOM_DISTORTION, &(value_json->valueint), sizeof(int),miio_set_properties_callback);
			return -1;
		}
		break;
	default:
		return -1;
	}
	item = cJSON_CreateNumber(0);
    cJSON_AddItemToObject(result_json,"code",item);
    ret = 0;
    return ret;
}

static int miio_set_properties(const char *msg)
{
    cJSON *json,*arrayItem,*object = NULL,*item_result_param1 = NULL;
    cJSON *item_id,*item_result = NULL; //ack msg
    int i = 0;
    char did[32];
    int piid = 0,siid = 0;
	int ret = -1, id = 0;
    cJSON *root_ack = 0;
	char *ackbuf = 0;
	//get id
	ret = json_verify_get_int(msg, "id", &id);
	if (ret < 0) {
		return ret;
	}
    json=cJSON_Parse(msg);
    arrayItem = cJSON_GetObjectItem(json,"params");
    //add ack json msg
    root_ack=cJSON_CreateObject();
    item_id = cJSON_CreateNumber(id);
    cJSON_AddItemToObject(root_ack,"id",item_id);
    item_result = cJSON_CreateArray();//
    if(arrayItem) {
        object = cJSON_GetArrayItem(arrayItem,i);
        while(object) {
        	item_result_param1 = cJSON_CreateObject();
            cJSON *item_did = cJSON_GetObjectItem(object,"did");
            if(item_did) {
                sprintf(did,"%s",item_did->valuestring);
            }
            cJSON *item_piid = cJSON_GetObjectItem(object,"piid");
            if(item_piid) {
                piid = item_piid->valueint;
            }
            cJSON *item_siid = cJSON_GetObjectItem(object,"siid");
            if(item_siid) {
                siid = item_siid->valueint;
            }
            cJSON *item_value = cJSON_GetObjectItem(object,"value");
            if(item_value) {
                ret = miio_set_properties_vlaue(id, did,piid,siid,item_value,item_result_param1);
                if(ret == 0) {
					cJSON_AddItemToArray(item_result,item_result_param1);
                }
            }
            i++;
            object = cJSON_GetArrayItem(arrayItem,i);
        }
        if(cJSON_GetArraySize(item_result)>0 ) {
        	cJSON_AddItemToObject(root_ack,"result",item_result);
        }
        else {
        	ret = 0;
        	goto exit;
        }
    }
    else {
    	goto exit;
    }
    ackbuf = cJSON_Print(root_ack);
    ret = miio_socket_send(ackbuf, strlen(ackbuf));
    free(ackbuf);
exit:
	cJSON_Delete(root_ack);
    cJSON_Delete(json);
    return ret;
}

static int miot_properties_changed(int piid,int siid,int value, char* string)
{
	char ackbuf[ACK_MAX];
	int ret = -1, id = 0;
    id =  misc_generate_random_id();
    if(string) {
    	sprintf(ackbuf, OT_REG_STR_TEMPLATE,id,config.device.did,siid,piid,string);
    }
    else {
    	sprintf(ackbuf, OT_REG_INT_TEMPLATE,id,config.device.did,siid,piid,value);
    }
    ret = miio_socket_send(ackbuf, strlen(ackbuf));
    return ret;
}

static int miio_action_func_ack(message_arg_t arg_pass, int result, int size, void *arg)
{
	int ret = -1;
	char ackbuf[ACK_MAX];
    switch(arg_pass.chick) {
		case IID_4_MemoryCardManagement:
			if(arg_pass.dog == IID_4_1_Format) {
				if(!result) {
					sprintf(ackbuf, OT_REG_OK_TEMPLATE, arg_pass.cat);
//					miot_properties_changed(IID_4_1_Status,IID_4_MemoryCardManagement,SD_CARD_OK,0);
				}
				else {
					sprintf(ackbuf, OT_REG_ERR_TEMPLATE, arg_pass.cat);
				}

			}
			else if(arg_pass.dog == IID_4_2_PopUp) {
				if( !result ) {
					sprintf(ackbuf, OT_REG_OK_TEMPLATE, arg_pass.cat);
//					miot_properties_changed(IID_4_1_Status,IID_4_MemoryCardManagement,SD_CARD_POPUP,0);
				}
				else {
					sprintf(ackbuf, OT_REG_ERR_TEMPLATE, arg_pass.cat);

				}
			}

			miio_socket_send(ackbuf, strlen(ackbuf));
			break;
		case IID_6_MoreSet:
			if(arg_pass.dog == IID_6_1_Reboot) {
				if(!result) {
					sprintf(ackbuf, OT_REG_OK_TEMPLATE, arg_pass.cat);
				}
				else {
					sprintf(ackbuf, OT_REG_ERR_TEMPLATE, arg_pass.cat);
				}
			}
			miio_socket_send(ackbuf, strlen(ackbuf));
			break;
		case IID_3_IndicatorLight:
			if(arg_pass.dog == IID_3_1_On) {
				log_err("aaaaaaaa -----sss  IID_3_1_On");
				if(!result) {
					sprintf(ackbuf, OT_REG_OK_TEMPLATE, arg_pass.cat);
				}
				else {
					sprintf(ackbuf, OT_REG_ERR_TEMPLATE, arg_pass.cat);
				}
			}
			miio_socket_send(ackbuf, strlen(ackbuf));
			break;
		default:
			break;
    }
    return ret;
}

static int miio_action_func(int id,char *did,int siid,int aiid,cJSON *json_in)
{
	int ret = -1;
    int num = id;
    message_t msg;
    switch(siid) {
		case IID_4_MemoryCardManagement:
			if(aiid == IID_4_1_Format) {
				log_info("IID_4_1_Format");
				send_complicate_request(&msg, MSG_DEVICE_ACTION, SERVER_DEVICE, id, aiid, siid,
						DEVICE_ACTION_SD_FORMAT, 0, 0, miio_action_func_ack);
//				miot_properties_changed(IID_4_1_Status,IID_4_MemoryCardManagement,SD_CARD_FORMATING,0);
			}
			else if(aiid == IID_4_2_PopUp) {
				log_info("IID_4_2_PopUp");
				send_complicate_request(&msg, MSG_DEVICE_CTRL_DIRECT, SERVER_DEVICE, id, aiid, siid,
						DEVICE_ACTION_SD_UMOUNT, 0, 0, miio_action_func_ack);
			}

			break;
/*		case IID_6_MoreSet:
			if(aiid == IID_6_1_Reboot) {
				log_info("IID_6_1_Reboot");
				send_complicate_request(&msg, MSG_KERNEL_ACTION, SERVER_KERNEL, id, aiid, siid,
						KERNEL_ACTION_REBOOT, 0, 0);
			}
			break;
*/
		default:
			break;
      }
    return ret;
}

static int miio_action(const char *msg)
{
    cJSON *json,*object = NULL;
    char did[32];
    int siid = 0,aiid = 0;
	int ret = -1, id = 0;
	log_info("method:action\n");
	//get id
	ret = json_verify_get_int(msg, "id", &id);
	if (ret < 0) {
		return ret;
	}
    json=cJSON_Parse(msg);
    object = cJSON_GetObjectItem(json,"params");
    if(object)
    {
        cJSON *item_did = cJSON_GetObjectItem(object,"did");
        if(item_did) {
            sprintf(did,"%s",item_did->valuestring);
        }
        cJSON *item_siid = cJSON_GetObjectItem(object,"siid");
        if(item_siid) {
            siid = item_siid->valueint;
        }
        cJSON *item_aiid = cJSON_GetObjectItem(object,"aiid");
        if(item_aiid) {
            aiid = item_aiid->valueint;
        }
        cJSON *item_in = cJSON_GetObjectItem(object,"in");
        ret = miio_action_func(id,did,siid,aiid,item_in);
    }
    cJSON_Delete(json);
    return ret;
}


static int miio_result_parse(const char *msg,int id)
{
    log_info("msg: %s, strlen: %d",msg, (int)strlen(msg));
    return 0;
}

static int miio_event(const char *msg)
{
	struct json_object *new_obj, *params, *tmp_obj;
	int code;
	if (NULL == msg)
		return -1;
	new_obj = json_tokener_parse(msg);
	if (NULL == new_obj) {
		log_err("%s: Not in json format: %s\n", __func__, msg);
		return -1;
	}
	if (!json_object_object_get_ex(new_obj, "params", &params)) {
		log_err("%s: get params error\n", __func__);
		json_object_put(new_obj);
		return -1;
	}
	if (!json_object_object_get_ex(params, "code", &tmp_obj)) {
		log_err("%s: get code error\n", __func__);
		json_object_put(new_obj);
		return -1;
	}
	if (json_object_get_type(tmp_obj) != json_type_int) {
		log_err("%s: code not int: %s\n", __func__, msg);
		json_object_put(new_obj);
		return -1;
	}
	code = json_object_get_int(tmp_obj);
	if (!json_object_object_get_ex(params, "ts", &tmp_obj)) {
		log_err("%s: get ts error\n", __func__);
		json_object_put(new_obj);
		return -1;
	}
	if (json_object_get_type(tmp_obj) != json_type_int) {
		log_err("%s: ts not int: %s\n", __func__, msg);
		json_object_put(new_obj);
		return -1;
	}
	json_object_get_int(tmp_obj);
	if (code == -90) {
		log_err("TUTK bug: -90, ignore this because interval < 60s.\n");
	}
	json_object_put(new_obj);
	return 0;
}

int miio_parse_did(char *msg)
{
    int ret = 0;
    char local_did[32] = {0};
	char *pA = NULL, *pB = NULL, *pC = NULL;
	char buf[64] = {0};
	int len = 0;
	char key = "params";
	if (strlen(key) > 59) {
		log_err( "key(%s) len is too long(%d), max len(59)!\n", key, strlen(key));
		return -1;
	}
	sprintf(buf, "\"%s\":", key);
	pA = strstr(msg, buf);
	if (pA != NULL) {
		pA += strlen(buf);
		pB = strstr(pA, "}");
		pC = strstr(pA, "}");
		if (pC < pB)
			pB = pC;
		if (pB != NULL) {
			len = pB - pA;
			if (len > 32) {
				log_err( "value len is too long(%d), max len(32)!\n", len);
				return -1;
			}
			strncpy(local_did, pA, len);
		} else {
			log_err( "response url parse '%s' error!\n", key);
			return -1;
		}
	} else {
		log_err( "response url don't have '%s'!\n", key);
		return -1;
	}
    strcpy(config.device.did, local_did);
    return ret ;
}


static int miio_message_dispatcher(const char *msg, int len)
{
	int ret = -1, id = 0;
	bool sendack = false;
	message_t message;
    char ackbuf[MIIO_MAX_PAYLOAD];
    if( miio_info.miio_status == STATE_CLOUD_CONNECTED)
    	goto next_level;
	if ((json_verify_method_value(msg, "method", "local.status", json_type_string) == 0) \
        &&(json_verify_method_value(msg, "params", "wifi_ap_mode", json_type_string) == 0)) {
		miio_info.miio_status = STATE_WIFI_AP_MODE;
	}
    if( miio_info.miio_status == STATE_WIFI_AP_MODE ) {
    	if (json_verify_method_value(msg, "method", "local.bind", json_type_string) == 0) {
        	if (json_verify_method_value(msg, "result", "ok", json_type_string) == 0) {
        		miio_info.miio_status = STATE_WIFI_STA_MODE;
        	}
    	}
        return 0;
    }
	if ((json_verify_method_value(msg, "method", "local.status", json_type_string) == 0)) {
		if(json_verify_method_value(msg, "params", "internet_connected", json_type_string) == 0) {
			miio_info.miio_status = STATE_CLOUD_CONNECTED;
		}
		else if(json_verify_method_value(msg, "params", "cloud_connected", json_type_string) == 0) {
			//send message to miss server
			miio_info.miio_status = STATE_CLOUD_CONNECTED;
			/********message body********/
			message_t msg;
			msg_init(&msg);
			msg.message = MSG_MIIO_CLOUD_CONNECTED;
			server_miss_message(&msg);
			/****************************/
		}
		else {
			return 0;
		}
	}
next_level:
    ret = json_verify_get_int(msg, "id", &id);
    if (ret < 0) {
    	return ret;
    }
/*

	msg_id = miss_get_context_from_id(id);
	if (NULL != msg_id) {
		log_debug("miss_rpc_process id:%d\n",id);
		ret = miss_rpc_process(msg_id, msg, len);
		if (ret != MISS_NO_ERROR) {
			log_err("miss_rpc_process err:%d\n",ret);
//			server_miss_message(MSG_MIIO_MISSRPC_ERROR,NULL);
			ret = 0;
		}
	}
*/
	/********message body********/
	msg_init(&message);
	message.message = MSG_MISS_RPC_SEND;
	message.sender = message.receiver = SERVER_MIIO;
	message.arg_in.cat = id;
	message.arg = msg;
	message.arg_size = len + 1;
	ret = server_miss_message(&message);
	/********message body********/
    if ( id == ntp_get_rpc_id() ) {
       ret = ntp_time_parse(msg);
       if(ret < 0 ){
            log_err("http_jason_get_timeInt error\n");
       }
       else{
			miio_info.time_sync = 1;
			/********message body********/
			msg_init(&message);
			message.message = MSG_MIIO_TIME_SYNCHRONIZED;
			message.sender = message.receiver = SERVER_MIIO;
			for( char sent=0;(sent < MAX_ASYN_SEND_TRY) && server_video_message(&message);sent++ ) {};
			for( char sent=0;(sent < MAX_ASYN_SEND_TRY) && server_recorder_message(&message);sent++ ) {};
			for( char sent=0;(sent < MAX_ASYN_SEND_TRY) && server_player_message(&message);sent++ ) {};
			/********message body********/
       }
       return 0;
    }
    if ( config.iot.board_type && (id == did_rpc_id) ) {
       ret = miio_parse_did(msg);
       if(ret < 0 ){
            log_err("http_jason_get_device_did error\n");
       }
       else{
    	   miio_info.did_acquired = 1;
    	   	/********message body********/
			msg_init(&message);
			message.message = MSG_MIIO_DID_ACUIRED;
			message.arg = config.device.did;
			message.arg_size = strlen(config.device.did) + 1;
			message.sender = message.receiver = SERVER_MIIO;
			for( char sent=0;(sent < MAX_ASYN_SEND_TRY) && server_miss_message(&message);sent++ ) {};
			/********message body********/
       }
       return 0;
    }
	//result
	if (json_verify_method(msg, "result") == 0) {
        sendack = false;
		miio_result_parse(msg, id);
		return 0;
	}
	if (json_verify_method_value(msg, "method", "get_properties", json_type_string) == 0) {
        ret = miio_get_properties(msg);
	}
    else if (json_verify_method_value(msg, "method", "set_properties", json_type_string) == 0) {
        ret = miio_set_properties(msg);
	}
    else if (json_verify_method_value(msg, "method", "action", json_type_string) == 0) {
    	ret = miio_action(msg);
	}
	else if (json_verify_method_value(msg, "method", "miIO.ota", json_type_string) == 0) {
		ret = ota_init(msg);
	}
    else if (json_verify_method_value(msg, "method", "miIO.get_ota_state", json_type_string) == 0) {
        ret = ota_get_state(msg);
	}
    else if (json_verify_method_value(msg, "method", "miIO.get_ota_progress", json_type_string) == 0) {
        ret = ota_get_progress(msg);
	}
	else if (json_verify_method_value(msg, "method", "miIO.event", json_type_string) == 0) {
		log_info("miIO.event: %s\n", msg);
		sprintf(ackbuf, OT_ACK_SUC_TEMPLATE, id);
		ret = miio_socket_send(ackbuf, strlen(ackbuf));
		miio_event(msg);
	}
	else if (json_verify_method_value(msg, "method", "miss.set_vendor", json_type_string) == 0) {
		log_info("miss.set_vendor: %s\n", msg);
//		ret = miss_rpc_process(NULL, msg, len);
		/********message body********/
		msg_init(&message);
		message.message = MSG_MISS_RPC_SEND;
		message.sender = message.receiver = SERVER_MIIO;
		message.arg_in.cat = -1;
		message.arg = msg;
		message.arg_size = len + 1;
		ret = server_miss_message(&message);
		/********message body********/
	}
	else if (json_verify_method_value(msg, "method", "miIO.reboot", json_type_string) == 0) {
//		ret = iot_miio_reboot(id);
    }
	else if (json_verify_method_value(msg, "method", "miIO.restore", json_type_string) == 0) {
//		ret = iot_miio_restore(id);
    }
    else {
        log_err("msg:%s ,strlen: %d, len: %d\n",msg, (int)strlen(msg), len);
    }
	return ret;
}

static int miio_recv_handler(int sockfd)
{
	char buf[BUFFER_MAX];
	ssize_t count;
	int left_len = 0;
	bool first_read = true;
	int ret = 0;
	memset(buf, 0, BUFFER_MAX);
	while (1) {
		count = recv(sockfd, buf + left_len, sizeof(buf) - left_len, MSG_DONTWAIT);
		if (count < 0) {
			return -1;
		}
		if (count == 0) {
			if (first_read) {
				log_err("iot_close_retry\n");
//				miio_close_retry();
			}
			if (left_len) {
				buf[left_len] = '\0';
				log_warning("%s() remain str: %s\n", __func__, buf);
			}
			return 0;
		}
		first_read = false;
		ret = miio_recv_handler_block(sockfd, buf, count + left_len);
		if (ret < 0) {
			log_warning("%s_one() return -1\n", __func__);
			return -1;
		}
		left_len = count + left_len - ret;
		memmove(buf, buf + ret, left_len);
	}
	return 0;
}

static int miio_recv_handler_block(int sockfd, char *msg, int msg_len)
{
	struct json_tokener *tok = 0;;
	struct json_object *json = 0;
	int ret = 0;

	if (json_verify(msg) < 0)
		return -1;
	/* split json if multiple */
	tok = json_tokener_new();
	while (msg_len > 0) {
		char *tmpstr;
		int tmplen;
        miio_message_queue_t msg_queue;
        json = json_tokener_parse_ex(tok, msg, msg_len);
		if (json == NULL) {
			log_warning("%s(), token parse error msg: %.*s, length: %d bytes\n",
				    __func__, msg_len, msg, msg_len);
			json_tokener_free(tok);
			return ret;
		}
		tmplen = tok->char_offset;
		tmpstr = malloc(tmplen);
		if (tmpstr == NULL) {
			log_warning("%s(), malloc error\n", __func__);
			json_tokener_free(tok);
			json_object_put(json);
			return -1;
		}
		memcpy(tmpstr, msg, tmplen);
//		tmpstr[tmplen] = '\0';
        msg_queue.mtype = MIIO_MESSAGE_TYPE;
        msg_queue.len = tmplen;
        memset(msg_queue.msg_buf, 0, sizeof(msg_queue.msg_buf));
        memcpy(msg_queue.msg_buf, tmpstr, tmplen);
        free(tmpstr);
		log_warning("%s, len:%d\n",msg_queue.msg_buf,msg_queue.len);
        miio_send_msg_queue(message_id,&msg_queue);
		json_object_put(json);
		ret += tok->char_offset;
		msg += tok->char_offset;
		msg_len -= tok->char_offset;
	}
	json_tokener_free(tok);
	return ret;
}

static void miio_close_retry(void)
{
	int n, found;

	if (msg_helper.otd_sock > 0) {
		/* close sock */
		found = 0;
		for (n = 0; n < msg_helper.count_pollfds; n++) {
			if (msg_helper.pollfds[n].fd == msg_helper.otd_sock) {
				found = 1;
				while (n < msg_helper.count_pollfds) {
					msg_helper.pollfds[n] = msg_helper.pollfds[n + 1];
					n++;
				}
			}
		}
		if (found)
			msg_helper.count_pollfds--;
		else
			log_warning("kit.otd_sock (%d) not in pollfds.\n", msg_helper.otd_sock);
		close(msg_helper.otd_sock);
		msg_helper.otd_sock = 0;
	}
}

static int miio_rsv_init(void *param)
{
	int ret = -1;
	pthread_t message_tid;

    message_id = miio_create_msg_queue();
    if(message_id == -1) {
        log_err("xm_createMsgQueue failed");
    	return -1;
    }
    if ((ret = pthread_create(&message_tid, NULL, miio_rsv_func, param))) {
    	printf("create miio message rsv handler, ret=%d\n", ret);
    	return -1;
    }
    misc_set_bit(&info.thread_start, THREAD_RSV, 1);
    return 0;
}

static int miio_poll_init(void *param)
{
	int ret = -1;
	pthread_t message_tid;
	int conn=0;

	memset(&msg_helper,0,sizeof(msg_helper));
    do {
        sleep(3);
        msg_helper.otd_sock= miio_socket_init();
        conn++;
    }while(msg_helper.otd_sock == -1 && conn < MAX_SOCKET_TRY);
    if( conn >= MAX_SOCKET_TRY) {
    	log_err("socket failed!");
    	return -1;
    }
	if (msg_helper.otd_sock >= 0) {
		msg_helper.pollfds[msg_helper.count_pollfds].fd = msg_helper.otd_sock;
		msg_helper.pollfds[msg_helper.count_pollfds].events = POLLIN;
		msg_helper.count_pollfds++;
	}
    if ((ret = pthread_create(&message_tid, NULL, miio_poll_func, param))) {
    	log_err("create mi message handler, ret=%d\n", ret);
    	return -1;
    }
    misc_set_bit(&info.thread_start, THREAD_POLL, 1);
    return 0;
}

static void *miio_poll_func(void *arg)
{
	int n=0;
	int i;
	server_status_t st;

    signal(SIGINT, server_thread_termination);
    signal(SIGTERM, server_thread_termination);
	misc_set_thread_name("server_miio_poll");
    pthread_detach(pthread_self());
	while ( (n >= 0) && ( !server_get_status(STATUS_TYPE_EXIT) ) ) {
		//exit logic
		st = server_get_status(STATUS_TYPE_STATUS);
		if( st != STATUS_RUN ) {
			if ( st == STATUS_IDLE || st == STATUS_SETUP || st == STATUS_START)
				continue;
			else
				break;
		}
		n = poll(msg_helper.pollfds, msg_helper.count_pollfds, POLL_TIMEOUT);
		if (n < 0) {
			perror("poll");
			continue;
		}
		if (n == 0) {
			continue;
		}
		for (i = 0; i < msg_helper.count_pollfds && n > 0; i++) {
			if (msg_helper.pollfds[i].revents & POLLIN) {
				if (msg_helper.pollfds[i].fd == msg_helper.otd_sock)
					miio_recv_handler(msg_helper.otd_sock);
				n--;
			}
			else if (msg_helper.pollfds[i].revents & POLLOUT) {
				if (msg_helper.pollfds[i].fd == msg_helper.otd_sock)
					log_info("POLLOUT fd: %d\n", msg_helper.otd_sock);
				n--;
			}
			else if (msg_helper.pollfds[i].revents & (POLLNVAL | POLLHUP | POLLERR)) {
				int j = i;
				log_warning("POLLNVAL | POLLHUP | POLLERR fd: pollfds[%d]: %d, revents: 0x%08x\n",
					    i, msg_helper.pollfds[i].fd, msg_helper.pollfds[i].revents);
				if (msg_helper.pollfds[i].fd == msg_helper.otd_sock) {
					log_err("iot_close_retry \n");
					miio_close_retry();
					n--;
					continue;
				}
				close(msg_helper.pollfds[i].fd);
				while (j < msg_helper.count_pollfds) {
					msg_helper.pollfds[j] = msg_helper.pollfds[j + 1];
					j++;
				}
				msg_helper.count_pollfds--;
				n--;
			}
		}
	}
	if (msg_helper.otd_sock > 0) {
		log_err("close miio.otd_sock\n");
		close(msg_helper.otd_sock);
	}
	log_info("-----------thread exit: server_miio_poll-----------");
	misc_set_bit(&info.thread_start, THREAD_POLL, 0);
	pthread_exit(0);
}

static void *miio_rsv_func(void *arg)
{
    int ret = 0;
    struct miio_message_queue_t msg_buf;
    msg_buf.mtype = MIIO_MESSAGE_TYPE;
    int st;
    signal(SIGINT, server_thread_termination);
    signal(SIGTERM, server_thread_termination);
    misc_set_thread_name("server_miio_rsv");
    pthread_detach(pthread_self());
	while( !server_get_status(STATUS_TYPE_EXIT) ) {
		st = server_get_status(STATUS_TYPE_STATUS);
		//exit logic
		if( st!= STATUS_RUN ) {
			if ( st == STATUS_IDLE || st == STATUS_SETUP || st == STATUS_START)
				continue;
			else
				break;
		}
		memset(msg_buf.msg_buf, 0, sizeof(msg_buf.msg_buf));
		ret = miio_rec_msg_queue(message_id,MIIO_MESSAGE_TYPE,&msg_buf);
		if(ret == 0) {
			miio_message_dispatcher((const char *) msg_buf.msg_buf,msg_buf.len);
		}
		else {
			usleep(1000);//1ms
		}
    }
	log_info("-----------thread exit: server_miio_rsv-----------");
	misc_set_bit(&info.thread_start, THREAD_RSV, 0);
	pthread_exit(0);
}

static void server_thread_termination(void)
{
	message_t msg;
    /********message body********/
	msg_init(&msg);
	msg.message = MSG_MIIO_SIGINT;
	msg.sender = msg.receiver = SERVER_MIIO;
	/***************************/
	manager_message(&msg);
}

static int server_release(void)
{
	int ret = 0;
	message_t msg;
	/********message body********/
	msg_init(&msg);
	msg.message = MSG_MANAGER_TIMER_REMOVE;
	msg.arg_in.handler = miio_routine_1000ms;
	/****************************/
	manager_message(&msg);
	msg_buffer_release(&message);
	return ret;
}

static int rpc_send_msg(int msg_id, const char *method, const char *params)
{
	char sendbuf[MIIO_MAX_PAYLOAD] = {0x00};
	int ret = 0;

	if (NULL == params)
		return -1;

	struct json_object *params_obj = json_tokener_parse(params);
	if (NULL == params_obj) {
		log_err("%s: Not in json format: %s\n", __func__, params);
		return -1;
	}

	struct json_object *send_object = json_object_new_object();
	if (NULL == send_object) {
		log_err("%s: init send_object failed\n", __func__);
		return -1;
	}

	json_object_object_add(send_object, "id", json_object_new_int(msg_id));
	json_object_object_add(send_object, "method", json_object_new_string(method));
	json_object_object_add(send_object, "params", params_obj);
	sprintf(sendbuf, "%s", json_object_to_json_string_ext(send_object, JSON_C_TO_STRING_NOZERO));

	json_object_put(send_object);
	//json_object_put(params_obj);
	if (msg_helper.otd_sock == 0) {
		log_err("rpc socket uninit\n");
		return -1;
	}
	log_info("rpc_msg_send: %s\n", sendbuf);
	ret = miio_socket_send(sendbuf, strlen(sendbuf));
	if(ret > 0)
		return 0;
	return -1;
}

static int rpc_send_report(int msg_id, const char *method, const char *params)
{
	char sendbuf[MIIO_MAX_PAYLOAD] = {0x00};
	if (NULL == params)
		return -1;
	struct json_object *send_object = json_object_new_object();
	if (NULL == send_object) {
		log_err("%s: init send_object failed\n", __func__);
		return -1;
	}
	struct json_object *params_obj = json_object_new_object();
	if (NULL == params_obj) {
		log_err("%s: init params_obj failed\n", __func__);
		return -1;
	}
	json_object_object_add(params_obj, "data", json_object_new_string(params));
	json_object_object_add(params_obj, "dataType", json_object_new_string("EventData"));
	json_object_object_add(send_object, "id", json_object_new_int(msg_id));
	json_object_object_add(send_object, "method", json_object_new_string(method));
	json_object_object_add(send_object, "params", params_obj);
	sprintf(sendbuf, "%s", json_object_to_json_string_ext(send_object, JSON_C_TO_STRING_NOZERO));
	json_object_put(send_object);
	miio_socket_send(sendbuf,strlen(sendbuf));
	log_info("rpc_report_send: %s\n", sendbuf);
	return 0;
}

static int server_set_status(int type, int st)
{
	int ret=-1;
	ret = pthread_rwlock_wrlock(&info.lock);
	if(ret)	{
		log_err("add lock fail, ret = %d", ret);
		return ret;
	}
	if(type == STATUS_TYPE_STATUS)
		info.status = st;
	else if(type==STATUS_TYPE_EXIT)
		info.exit = st;
	else if(type==STATUS_TYPE_CONFIG)
		config.status = st;
	ret = pthread_rwlock_unlock(&info.lock);
	if (ret)
		log_err("add unlock fail, ret = %d", ret);
	return ret;
}

static int server_get_status(int type)
{
	int st;
	int ret;
	ret = pthread_rwlock_wrlock(&info.lock);
	if(ret)	{
		log_err("add lock fail, ret = %d", ret);
		return ret;
	}
	if(type == STATUS_TYPE_STATUS)
		st = info.status;
	else if(type== STATUS_TYPE_EXIT)
		st = info.exit;
	else if(type==STATUS_TYPE_CONFIG)
		st = config.status;
	ret = pthread_rwlock_unlock(&info.lock);
	if (ret)
		log_err("add unlock fail, ret = %d", ret);
	return st;
}

static int server_message_proc(void)
{
	int ret = 0, ret1 = 0;
	message_t msg;
	message_t send_msg;
	msg_init(&msg);
	msg_init(&send_msg);
	ret = pthread_rwlock_wrlock(&message.lock);
	if(ret)	{
		log_err("add message lock fail, ret = %d\n", ret);
		return ret;
	}
	ret = msg_buffer_pop(&message, &msg);
	ret1 = pthread_rwlock_unlock(&message.lock);
	if (ret1) {
		log_err("add message unlock fail, ret = %d\n", ret1);
	}
	if( ret == -1) {
		msg_free(&msg);
		return -1;
	}
	else if( ret == 1) {
		return 0;
	}
	switch(msg.message){
	case MSG_MANAGER_EXIT:
		server_set_status(STATUS_TYPE_EXIT,1);
		break;
	case MSG_MANAGER_TIMER_ACK:
		((HANDLER)msg.arg_in.handler)();
		break;
	case MSG_MIIO_SOCKET_SEND:
		miio_socket_send(msg.arg, msg.arg_size);
		break;
	case MSG_MIIO_RPC_SEND:
		rpc_send_msg(msg.arg_in.cat, msg.extra, msg.arg);
		break;
	case MSG_MIIO_RPC_REPORT_SEND:
		rpc_send_report(msg.arg_in.cat, msg.extra, msg.arg);
		break;
	case MSG_VIDEO_GET_PARA_ACK:
	case MSG_DEVICE_GET_PARA_ACK:
	case MSG_RECORDER_GET_PARA_ACK:
		if( msg.arg_pass.handler != NULL)
			( *( int(*)(message_arg_t,int,int,void*) ) msg.arg_pass.handler ) (msg.arg_pass, msg.result, msg.arg_size, msg.arg);
		break;
	case MSG_VIDEO_CTRL_ACK:
	case MSG_VIDEO_CTRL_EXT_ACK:
	case MSG_VIDEO_CTRL_DIRECT_ACK:
	case MSG_VIDEO_START_ACK:
	case MSG_VIDEO_STOP_ACK:
	case MSG_RECORDER_CTRL_DIRECT_ACK:
		if( msg.arg_pass.handler != NULL)
			( *( int(*)(message_arg_t,int,int,void*) ) msg.arg_pass.handler ) (msg.arg_pass, msg.result, msg.arg_size, msg.arg);
		break;
	case MSG_DEVICE_ACTION_ACK:
		miio_action_func_ack(msg.arg_pass, msg.result, msg.arg_size, msg.arg);
		break;
//	case MSG_KERNEL_OTA_REPORT:
//		ota_proc(msg.arg_in.cat, msg.arg_in.dog, msg.arg_in.duck);
//		break;
//	case MSG_KERNEL_OTA_REQUEST_ACK:
//		ota_get_state_ack(msg.arg_in.duck, msg.arg_pass.cat, msg.arg_in.cat, msg.arg_in.dog);
//		break;
	default:
		log_err("not processed message = %d", msg.message);
		break;
	}
	msg_free(&msg);
	return ret;
}

static int heart_beat_proc(void)
{
	int ret = 0;
	message_t msg;
	long long int tick = 0;
	tick = time_get_now_stamp();
	if( (tick - info.tick) > 10 ) {
		info.tick = tick;
	    /********message body********/
		msg_init(&msg);
		msg.message = MSG_MANAGER_HEARTBEAT;
		msg.sender = msg.receiver = SERVER_MIIO;
		msg.arg_in.cat = info.status;
		msg.arg_in.dog = info.thread_start;
		msg.arg_in.duck = info.thread_exit;
		ret = manager_message(&msg);
		/***************************/
	}
	return ret;
}

/*
 * task error: error->5 seconds->shut down server->msg manager
 */
static void task_error(void)
{
	unsigned int tick=0;
	switch( info.status ) {
		case STATUS_ERROR:
			log_err("!!!!!!!!error in miio, restart in 5 s!");
			info.tick = time_get_now_stamp();
			info.status = STATUS_NONE;
			break;
		case STATUS_NONE:
			tick = time_get_now_stamp();
			if( (tick - info.tick) > 5 ) {
				info.exit = 1;
				info.tick = tick;
			}
			break;
	}
	usleep(1000);
	return;
}

static void task_default(void)
{
	message_t msg;
	int ret = 0;
	switch( info.status){
		case STATUS_NONE:
			if( !misc_get_bit( info.thread_exit, MIIO_INIT_CONDITION_CONFIG ) ) {
				ret = config_miio_read(&config);
				if( !ret && misc_full_bit(config.status, CONFIG_MIIO_MODULE_NUM) ) {
					misc_set_bit(&info.thread_exit, MIIO_INIT_CONDITION_CONFIG, 1);
				}
				else {
					info.status = STATUS_ERROR;
					break;
				}
			}
			if( misc_full_bit( info.thread_exit, MIIO_INIT_CONDITION_NUM ) )
				info.status = STATUS_WAIT;
			else
				usleep(100000);
			break;
		case STATUS_WAIT:
			info.status = STATUS_SETUP;
			break;
		case STATUS_SETUP:
			ret = miio_rsv_init(NULL);
			if ( ret!=0 ) {
				server_set_status(STATUS_TYPE_STATUS, STATUS_ERROR);
				break;
			}
			ret = miio_poll_init(NULL);
			if ( ret!=0 ) {
				server_set_status(STATUS_TYPE_STATUS, STATUS_ERROR);
				break;
			}
			server_set_status(STATUS_TYPE_STATUS, STATUS_IDLE);
			break;
		case STATUS_IDLE:
			info.status = STATUS_START;
			break;
		case STATUS_START:
		    /********message body********/
			msg_init(&msg);
			msg.message = MSG_MANAGER_TIMER_ADD;
			msg.sender = SERVER_MIIO;
			msg.arg_in.cat = 1000;
			msg.arg_in.dog = 0;
			msg.arg_in.duck = 0;
			msg.arg_in.handler = &miio_routine_1000ms;
			manager_message(&msg);
			/****************************/
			server_set_status(STATUS_TYPE_STATUS, STATUS_RUN);
			break;
		case STATUS_RUN:
			break;
		case STATUS_STOP:
			break;
		case STATUS_RESTART:
			break;
		case STATUS_ERROR:
			info.task.func = task_error;
			break;
	}
	usleep(1000);
	return;
}

/*
 * server entry point
 */
static void *server_func(void)
{
    signal(SIGINT, server_thread_termination);
    signal(SIGTERM, server_thread_termination);
	misc_set_thread_name("server_miio");
	pthread_detach(pthread_self());
	//default task
	info.task.func = task_default;
	info.task.start = STATUS_NONE;
	info.task.end = STATUS_RUN;
	while( !info.exit ) {
		info.task.func();
		server_message_proc();
		heart_beat_proc();
	}
	if( info.exit ) {
		while( info.thread_start ) {
		}
	    /********message body********/
		message_t msg;
		msg_init(&msg);
		msg.message = MSG_MANAGER_EXIT_ACK;
		msg.sender = SERVER_MIIO;
		manager_message(&msg);
		/***************************/
	}
	server_release();
	log_info("-----------thread exit: server_miio-----------");
	pthread_exit(0);
}

/*
 * internal interface
 */

int miio_send_to_cloud(char *buf, int size)
{
	return miio_socket_send(buf,size);
}

/*
 * external interface
 */
int server_miio_start(void)
{
	int ret=-1;
	msg_buffer_init(&message, MSG_BUFFER_OVERFLOW_NO);
	pthread_rwlock_init(&info.lock, NULL);
	ret = pthread_create(&info.id, NULL, server_func, NULL);
	if(ret != 0) {
		log_err("miio server create error! ret = %d",ret);
		 return ret;
	 }
	else {
		log_err("miio server create successful!");
		return 0;
	}
}

int server_miio_message(message_t *msg)
{
	int ret=0,ret1=0;
	ret = pthread_rwlock_wrlock(&message.lock);
	if(ret)	{
		log_err("add message lock fail, ret = %d\n", ret);
		return ret;
	}
	ret = msg_buffer_push(&message, msg);
	log_info("push into the miio message queue: sender=%d, message=%d, ret=%d", msg->sender, msg->message, ret);
	if( ret!=0 )
		log_err("message push in miio error =%d", ret);
	ret1 = pthread_rwlock_unlock(&message.lock);
	if (ret1)
		log_err("add message unlock fail, ret = %d\n", ret1);
	return ret;
}
