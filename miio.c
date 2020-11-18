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
//program header
#include "../../tools/tools_interface.h"
#include "../../server/miss/miss_local.h"
#include "../../server/miss/miss_interface.h"
#include "../../manager/manager_interface.h"
#include "../../server/video/video_interface.h"
#include "../../server/audio/audio_interface.h"
#include "../../server/recorder/recorder_interface.h"
#include "../../server/device/device_interface.h"
#include "../../server/video2/video2_interface.h"
#include "../../server/scanner/scanner_interface.h"
#include "../../server/player/player_interface.h"
#include "../../server/kernel/kernel_interface.h"
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
static int server_set_status(int type, int st, int value);
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
static int miio_action(const char *msg);
static int miio_action_func(int id,char *did,int siid,int aiid,cJSON *json_in);
static int miio_action_func_ack(message_arg_t arg_pass, int result, int size, void *arg);
static int miot_properties_changed(int piid,int siid,int value, char* string);
static int miio_query_device_did(void);
static int miio_parse_did(char* msg, char *key);

/*
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 */

/*
 * helper
 */
static int send_message(int receiver, message_t *msg)
{
	int st = 0;
	switch(receiver) {
		case SERVER_DEVICE:
			st = server_device_message(msg);
			break;
		case SERVER_KERNEL:
			st = server_kernel_message(msg);
			break;
		case SERVER_REALTEK:
			st = server_realtek_message(msg);
			break;
		case SERVER_MIIO:
			st = server_miio_message(msg);
			break;
		case SERVER_MISS:
			st = server_miss_message(msg);
			break;
		case SERVER_MICLOUD:
	//		st = server_micloud_message(msg);
			break;
		case SERVER_VIDEO:
			st = server_video_message(msg);
			break;
		case SERVER_AUDIO:
			st = server_audio_message(msg);
			break;
		case SERVER_RECORDER:
			st = server_recorder_message(msg);
			break;
		case SERVER_PLAYER:
			st = server_player_message(msg);
			break;
		case SERVER_SPEAKER:
			st = server_speaker_message(msg);
			break;
		case SERVER_VIDEO2:
			st = server_video2_message(msg);
			break;
		case SERVER_SCANNER:
			st = server_scanner_message(msg);
			break;
		case SERVER_MANAGER:
			st = manager_message(msg);
			break;
		default:
			log_qcy(DEBUG_SERIOUS, "unknown message target! %d", receiver);
			break;
	}
	return st;
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
		&& miio_info.time_sync) {
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
	/*
	static sent = 0;
	if( !sent) {
		char temp[256] = "{ \"id\": 12345 ,\"method\": \"local.ble.config_router\", \"params\": { \"bind_key\": \"xx\", \"ssid\": \"WiFi-BE11\", \"passwd\": \"New1234321\", \"tz\":\"Asia\/Shanghai\", \"country_domain\":\"cn\" } }";
		msg_init(&msg);
		msg.message = MSG_SCANNER_QR_CODE_BEGIN_ACK;
		msg.receiver = msg.sender = SERVER_MIIO;
		msg.result = 0;
		msg.arg = temp;
		msg.arg_size = strlen(temp) + 1;
		server_miio_message(&msg);
    	sent = 1;
        message_t msg;
    	msg_init(&msg);
    	msg.message = MSG_PLAYER_GET_FILE_DATE;
    	msg.sender = msg.receiver = SERVER_MISS;
    	msg.arg_pass.cat = GET_RECORD_DATE;
    	msg.arg_in.cat = 1605398400;
    	msg.arg_in.dog = 1605409200;
//     	msg.arg_pass.handler = session;
    	server_player_message(&msg);

        message_t msg;
        int msgg = 0;
    	msg_init(&msg);
    	msg.message = MSG_MANAGER_PROPERTY_SET;
    	msg.sender = msg.receiver = SERVER_MIIO;
    	msg.arg_pass.cat = MANAGER_PROPERTY_SLEEP;
    	msg.arg_in.cat = MANAGER_PROPERTY_SLEEP;
    	msg.arg = &msgg;
    	msg.arg_size = sizeof(msgg);
    	manager_message(&msg);
	}
*/
	return ret;
}

static int miio_socket_init(void)
{
	struct sockaddr_in serveraddr;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		log_qcy(DEBUG_SERIOUS, "Create socket error: %m");
		return -1;
	}
	bzero(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = inet_addr(MIIO_IP);
	serveraddr.sin_port = htons(MIIO_PORT);
	if (connect(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
		log_qcy(DEBUG_SERIOUS, "Connect to otd error: %s:%d", MIIO_IP, MIIO_PORT);
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
		log_qcy(DEBUG_SERIOUS, "add session wrlock fail, ret = %d", ret);
		return -1;
	}
	if (msg_helper.otd_sock <= 0) {
		log_qcy(DEBUG_WARNING,"sock not ready: %d", msg_helper.otd_sock);
		goto end;
	}
	if (size == 0)
		goto end;
	log_qcy(DEBUG_VERBOSE, "send: %s",buf);
	while (size > 0) {
		ret = send(msg_helper.otd_sock, buf + sent, size, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (ret < 0) {
			// FIXME EAGAIN
			log_qcy(DEBUG_SERIOUS, "%s: send error: %s(%m)");
			goto end;
		}
		if (ret < size)
			log_qcy(DEBUG_WARNING, "Partial written");
		sent += ret;
		size -= ret;
	}
end:
	ret = pthread_rwlock_unlock(&info.lock);
	if (ret) {
		log_qcy(DEBUG_SERIOUS, "add session unlock fail, ret = %d", ret);
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
				if( arg_pass.dog == IID_2_1_On ) item = cJSON_CreateNumber( *((int*)arg) );
				else if( arg_pass.dog == IID_2_2_ImageRollover) item = cJSON_CreateNumber( *((int*)arg) );
				else if( arg_pass.dog == IID_2_3_NightShot) item = cJSON_CreateNumber( *((int*)arg) );
				else if( arg_pass.dog == IID_2_4_TimeWatermark) item = cJSON_CreateNumber( *((int*)arg) );
				else if( arg_pass.dog == IID_2_7_RecordingMode) item = cJSON_CreateNumber( *((int*)arg) );
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
				if( arg_pass.dog == IID_5_1_MotionDetection) item = cJSON_CreateNumber( *((int*)arg) );
				else if( arg_pass.dog == IID_5_2_AlarmInterval) item = cJSON_CreateNumber( *((int*)arg) );
				else if( arg_pass.dog == IID_5_3_DetectionSensitivity) item = cJSON_CreateNumber( *((int*)arg) );
				else if( arg_pass.dog == IID_5_4_MotionDetectionStartTime) item = cJSON_CreateString( (char*)arg );
				else if( arg_pass.dog == IID_5_5_MotionDetectionEndTime) item = cJSON_CreateString( (char*)arg );
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
					item = cJSON_CreateNumber( *((int*)arg) );
				}
				else if(arg_pass.dog == IID_6_8_CloudUploadEnable) {
//					tmp = (micloud_iot_config_t*)arg;
//					item = cJSON_CreateNumber(tmp->custom_cloud_save);
				}
				else if(arg_pass.dog == IID_6_9_MotionAlarmPush) item = cJSON_CreateNumber( *((int*)arg) );
				else if(arg_pass.dog == IID_6_10_DistortionSwitch) item = cJSON_CreateNumber( *((int*)arg) );
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
    cJSON *item = NULL;
    item = cJSON_CreateString(did);
    cJSON_AddItemToObject(json,"did",item);
    item = cJSON_CreateNumber(siid);
    cJSON_AddItemToObject(json,"siid",item);
    item = cJSON_CreateNumber(piid);
    cJSON_AddItemToObject(json,"piid",item);
	/********message body********/
    msg_init(&msg);
	msg.sender = msg.receiver = SERVER_MIIO;
	msg.arg_pass.cat = id;
	msg.arg_pass.dog = piid;
	msg.arg_pass.chick = siid;
	msg.arg_pass.handler = miio_get_properties_callback;
	/****************************/
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
			msg.message = MSG_VIDEO_PROPERTY_GET;
/*			if( piid == IID_2_1_On ) {
				msg.arg_in.cat = VIDEO_PROPERTY_SWITCH;
				send_message(SERVER_VIDEO, &msg);
			}
*/
			if( piid == IID_2_1_On ) {
				msg.message = MSG_MANAGER_PROPERTY_GET;
				msg.arg_in.cat = MANAGER_PROPERTY_SLEEP;
				send_message(SERVER_MANAGER, &msg);
			}
			else if( piid == IID_2_2_ImageRollover) {
				msg.arg_in.cat = VIDEO_PROPERTY_IMAGE_ROLLOVER;
				send_message(SERVER_VIDEO, &msg);
			}
			else if( piid == IID_2_3_NightShot) {
				msg.arg_in.cat = VIDEO_PROPERTY_NIGHT_SHOT;
				send_message(SERVER_VIDEO, &msg);
			}
			else if( piid == IID_2_4_TimeWatermark) {
				msg.arg_in.cat = VIDEO_PROPERTY_TIME_WATERMARK;
				send_message(SERVER_VIDEO, &msg);
			}
			else if( piid == IID_2_7_RecordingMode) {
				msg.message = MSG_RECORDER_PROPERTY_GET;
				msg.arg_in.cat = RECORDER_PROPERTY_RECORDING_MODE;
				send_message(SERVER_RECORDER, &msg);
			}
			else if( piid == IID_2_8_MotionTracking) {
				msg.arg_in.cat = VIDEO_PROPERTY_MOTION_SWITCH;
				send_message(SERVER_VIDEO, &msg);
			}
			return -1;
		case IID_5_MotionDetection:
			msg.message = MSG_VIDEO_PROPERTY_GET;
			if( piid == IID_5_1_MotionDetection ) {
				msg.arg_in.cat = VIDEO_PROPERTY_MOTION_SWITCH;
			}
			else if( piid == IID_5_2_AlarmInterval) {
				msg.arg_in.cat = VIDEO_PROPERTY_MOTION_ALARM_INTERVAL;
			}
			else if( piid == IID_5_3_DetectionSensitivity) {
				msg.arg_in.cat = VIDEO_PROPERTY_MOTION_SENSITIVITY;
			}
			else if( piid == IID_5_4_MotionDetectionStartTime) {
				msg.arg_in.cat = VIDEO_PROPERTY_MOTION_START;
			}
			else if( piid == IID_5_5_MotionDetectionEndTime) {
				msg.arg_in.cat = VIDEO_PROPERTY_MOTION_END;
			}
			send_message(SERVER_VIDEO, &msg);
			return -1;
		case IID_3_IndicatorLight:
		case IID_4_MemoryCardManagement:
			msg.message = MSG_DEVICE_GET_PARA;
			msg.arg_in.cat = DEVICE_CTRL_SD_INFO;
			send_message(SERVER_DEVICE, &msg);
			return -1;
		case IID_6_MoreSet:
			if(	piid == IID_6_9_MotionAlarmPush ) {
				msg.message = MSG_VIDEO_PROPERTY_GET;
				msg.arg_in.cat = VIDEO_PROPERTY_CUSTOM_WARNING_PUSH;
				send_message(SERVER_VIDEO, &msg);
			}
			else if ( piid == IID_6_10_DistortionSwitch ) {
				msg.message = MSG_VIDEO_PROPERTY_GET;
				msg.arg_in.cat = VIDEO_PROPERTY_CUSTOM_DISTORTION;
				send_message(SERVER_VIDEO, &msg);
			}
			else if( piid == IID_6_7_StorageSwitch ) {
				msg.message = MSG_RECORDER_PROPERTY_GET;
				msg.arg_in.cat = RECORDER_PROPERTY_SAVE_MODE;
				send_message(SERVER_RECORDER, &msg);
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
			return -1;
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
	log_qcy(DEBUG_INFO, "----%s--------",msg);
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
    item = cJSON_CreateString(did);
    cJSON_AddItemToObject(result_json,"did",item);
    item = cJSON_CreateNumber(siid);
    cJSON_AddItemToObject(result_json,"siid",item);
    item = cJSON_CreateNumber(piid);
    cJSON_AddItemToObject(result_json,"piid",item);
	/********message body********/
    msg_init(&msg);
	msg.sender = msg.receiver = SERVER_MIIO;
	msg.arg_pass.cat = id;
	msg.arg_pass.dog = piid;
	msg.arg_pass.chick = siid;
	msg.arg_pass.handler = miio_set_properties_callback;
	/****************************/
    switch(siid){
		case IID_2_CameraControl:
			if(piid == IID_2_1_On) {
				log_qcy(DEBUG_INFO, "IID_2_1_On:%d ",value_json->valueint);
				/*
				if( value_json->valueint == 1) {
					msg.message = MSG_VIDEO_START;
					msg.arg_in.cat = VIDEO_PROPERTY_SWITCH;
					send_message(SERVER_VIDEO, &msg);
				}
				else {
					msg.message = MSG_VIDEO_STOP;
					msg.arg_in.cat = VIDEO_PROPERTY_SWITCH;
					send_message(SERVER_VIDEO, &msg);
				}
				*/
				msg.message = MSG_MANAGER_PROPERTY_SET;
				msg.arg_in.cat = MANAGER_PROPERTY_SLEEP;
				msg.arg = &(value_json->valueint);
				msg.arg_size = sizeof( value_json->valueint );
				send_message(SERVER_MANAGER, &msg);
				return -1;
			}
			else if(piid == IID_2_2_ImageRollover) {
				log_qcy(DEBUG_INFO, "IID_2_2_ImageRollover:%d ",value_json->valueint);
				msg.message = MSG_VIDEO_PROPERTY_SET_EXT;
				msg.arg_in.cat = VIDEO_PROPERTY_IMAGE_ROLLOVER;
				msg.arg = &(value_json->valueint);
				msg.arg_size = sizeof(value_json->valueint);
				send_message(SERVER_VIDEO, &msg);
				return -1;
			}
			else if(piid == IID_2_3_NightShot) {
				log_qcy(DEBUG_INFO, "IID_2_3_NightShot:%d ",value_json->valueint);
				msg.message = MSG_VIDEO_PROPERTY_SET_DIRECT;
				msg.arg_in.cat = VIDEO_PROPERTY_NIGHT_SHOT;
				msg.arg = &(value_json->valueint);
				msg.arg_size = sizeof(value_json->valueint);
				send_message(SERVER_VIDEO, &msg);
				return -1;
			}
			else if(piid == IID_2_4_TimeWatermark) {
				log_qcy(DEBUG_INFO, "IID_2_4_TimeWatermark:%d ",value_json->valueint);
				msg.message = MSG_VIDEO_PROPERTY_SET_EXT;
				msg.arg_in.cat = VIDEO_PROPERTY_TIME_WATERMARK;
				msg.arg = &(value_json->valueint);
				msg.arg_size = sizeof(value_json->valueint);
				send_message(SERVER_VIDEO, &msg);
				return -1;
			}
			else if(piid == IID_2_7_RecordingMode) {
				log_qcy(DEBUG_INFO, "IID_2_7_RecordingMode:%d ",value_json->valueint);
				msg.message = MSG_RECORDER_PROPERTY_SET;
				msg.arg_in.cat = RECORDER_PROPERTY_RECORDING_MODE;
				msg.arg = &(value_json->valueint);
				msg.arg_size = sizeof(value_json->valueint);
				send_message(SERVER_RECORDER, &msg);
				return -1;
			}
			return -1;
		case IID_3_IndicatorLight:
			if(piid == IID_3_1_On) {
				log_qcy(DEBUG_INFO, "IID_3_1_On:%d ",value_json->valueint);
				device_iot_config_t tmp;
				memset(&tmp, 0, sizeof(device_iot_config_t));
				tmp.led1_onoff = value_json->valueint;
				tmp.led2_onoff = value_json->valueint;
				msg.message = MSG_DEVICE_CTRL_DIRECT;
				msg.arg_in.cat = DEVICE_CTRL_LED;
				msg.arg = &tmp;
				msg.arg_size = sizeof(tmp);
				send_message(SERVER_DEVICE, &msg);
				return -1;
			}
			break;
		case IID_4_MemoryCardManagement:
			break;
		case IID_5_MotionDetection:
			if(piid == IID_5_1_MotionDetection) {
				log_qcy(DEBUG_INFO, "IID_5_1_MotionDetection:%d ",value_json->valueint);
				msg.message = MSG_VIDEO_PROPERTY_SET;
				msg.arg_in.cat = VIDEO_PROPERTY_MOTION_SWITCH;
				msg.arg = &(value_json->valueint);
				msg.arg_size = sizeof(value_json->valueint);
				send_message(SERVER_VIDEO, &msg);
				return -1;
			}
			else if(piid == IID_5_2_AlarmInterval) {
				log_qcy(DEBUG_INFO, "IID_5_2_AlarmInterval:%d ",value_json->valueint);
				msg.message = MSG_VIDEO_PROPERTY_SET;
				msg.arg_in.cat = VIDEO_PROPERTY_MOTION_ALARM_INTERVAL;
				msg.arg = &(value_json->valueint);
				msg.arg_size = sizeof(value_json->valueint);
				send_message(SERVER_VIDEO, &msg);
				return -1;
			}
			else if(piid == IID_5_3_DetectionSensitivity) {
				log_qcy(DEBUG_INFO, "IID_5_3_DetectionSensitivity:%d ",value_json->valueint);
				msg.message = MSG_VIDEO_PROPERTY_SET;
				msg.arg_in.cat = VIDEO_PROPERTY_MOTION_SENSITIVITY;
				msg.arg = &(value_json->valueint);
				msg.arg_size = sizeof(value_json->valueint);
				send_message(SERVER_VIDEO, &msg);
				return -1;
			}
			else if(piid == IID_5_4_MotionDetectionStartTime) {
				log_qcy(DEBUG_INFO, "IID_5_4_MotionDetectionStartTime:%s ",value_json->valuestring);
				msg.message = MSG_VIDEO_PROPERTY_SET_DIRECT;
				msg.arg_in.cat = VIDEO_PROPERTY_MOTION_START;
				msg.arg = value_json->valuestring;
				msg.arg_size =  strlen(value_json->valuestring) + 1;
				send_message(SERVER_VIDEO, &msg);
				return -1;
			}
			else if(piid == IID_5_5_MotionDetectionEndTime) {
				log_qcy(DEBUG_INFO, "IID_5_4_MotionDetectionEndTime:%s ",value_json->valuestring);
				msg.message = MSG_VIDEO_PROPERTY_SET_DIRECT;
				msg.arg_in.cat = VIDEO_PROPERTY_MOTION_END;
				msg.arg = value_json->valuestring;
				msg.arg_size =  strlen(value_json->valuestring) + 1;
				send_message(SERVER_VIDEO, &msg);
				return -1;
			}
			break;
		case IID_6_MoreSet:
			if(piid == IID_6_6_TimeZone) {
				log_qcy(DEBUG_INFO, "IID_6_6_TimeZone:%d ",value_json->valueint);
	/*			send_complicate_request(&msg, MSG_KERNEL_CTRL_DIRECT, SERVER_KERNEL, id, piid, siid,
						KERNEL_CTRL_TIMEZONE, &(value_json->valueint), sizeof(int),miio_set_properties_callback);
	*/
				return -1;
			}
			else if(piid == IID_6_7_StorageSwitch) {
				log_qcy(DEBUG_INFO, "IID_6_7_StorageSwitch:%d ",value_json->valueint);
				msg.message = MSG_RECORDER_PROPERTY_SET;
				msg.arg_in.cat = RECORDER_PROPERTY_SAVE_MODE;
				msg.arg = &(value_json->valueint);
				msg.arg_size = sizeof(value_json->valueint);
				send_message(SERVER_RECORDER, &msg);
				return -1;
			}
			else if(piid == IID_6_8_CloudUploadEnable) {
				log_qcy(DEBUG_INFO, "IID_6_8_CloudUploadEnable:%d ",value_json->valueint);
	//			send_complicate_request(&msg, MSG_MICLOUD_CTRL_DIRECT, SERVER_MICLOUD, id, piid, siid,
	//					MICLOUD_CTRL_CLOUD_SAVE, &(value_json->valueint), sizeof(int),miio_set_properties_callback);
				return -1;
			}
			else if(piid == IID_6_9_MotionAlarmPush) {
				log_qcy(DEBUG_INFO, "IID_6_9_MotionAlarmPush:%d ",value_json->valueint);
				msg.message = MSG_VIDEO_PROPERTY_SET;
				msg.arg_in.cat = VIDEO_PROPERTY_CUSTOM_WARNING_PUSH;
				msg.arg = &(value_json->valueint);
				msg.arg_size = sizeof(value_json->valueint);
				send_message(SERVER_VIDEO, &msg);
				return -1;
			}
			else if(piid == IID_6_10_DistortionSwitch) {
				log_qcy(DEBUG_INFO, "IID_6_10_DistortionSwitch:%d ",value_json->valueint);
				msg.message = MSG_VIDEO_PROPERTY_SET_DIRECT;
				msg.arg_in.cat = VIDEO_PROPERTY_CUSTOM_DISTORTION;
				msg.arg = &(value_json->valueint);
				msg.arg_size = sizeof(value_json->valueint);
				send_message(SERVER_VIDEO, &msg);
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
				log_qcy(DEBUG_INFO, "aaaaaaaa -----sss  IID_3_1_On");
				if(!result) {
					sprintf(ackbuf, OT_REG_OK_TEMPLATE, arg_pass.cat);
				}
				else {
					sprintf(ackbuf, OT_REG_ERR_TEMPLATE, arg_pass.cat);
				}
			}
			miio_socket_send(ackbuf, strlen(ackbuf));
			break;
		case KERNEL_SET_TZ:
				if(!result) {
					sprintf(ackbuf, "{\"id\":%d,\"result\":[\"OK\"]}", arg_pass.cat);
				}
				else {
					sprintf(ackbuf, "{\"id\":%d,\"result\":[\"ERROR\"]}", arg_pass.cat);
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
    msg_init(&msg);
	/********message body********/
	msg.sender = msg.receiver = SERVER_MIIO;
	msg.arg_pass.cat = id;
	msg.arg_pass.dog = aiid;
	msg.arg_pass.chick = siid;
	msg.arg_pass.handler = miio_action_func_ack;
	/****************************/
    switch(siid) {
		case IID_4_MemoryCardManagement:
			if(aiid == IID_4_1_Format) {
				log_qcy(DEBUG_INFO, "IID_4_1_Format");
				msg.message = MSG_DEVICE_ACTION;
				msg.arg_in.cat = DEVICE_ACTION_SD_FORMAT;
				send_message(SERVER_DEVICE, &msg);
//				miot_properties_changed(IID_4_1_Status,IID_4_MemoryCardManagement,SD_CARD_FORMATING,0);
			}
			else if(aiid == IID_4_2_PopUp) {
				log_qcy(DEBUG_INFO, "IID_4_2_PopUp");
				msg.message = MSG_DEVICE_CTRL_DIRECT;
				msg.arg_in.cat = DEVICE_ACTION_SD_UMOUNT;
				send_message(SERVER_DEVICE, &msg);
			}

			break;
		case IID_6_MoreSet:
			if(aiid == IID_6_1_Reboot) {
				log_qcy(DEBUG_SERIOUS, "IID_6_1_Reboot");
				msg.message = MSG_KERNEL_ACTION;
				msg.arg_in.cat = KERNEL_ACTION_REBOOT;
				send_message(SERVER_KERNEL, &msg);
				/*send_complicate_request(&msg, MSG_KERNEL_ACTION, SERVER_KERNEL, id, aiid, siid,
						KERNEL_ACTION_REBOOT, 0, 0);*/
			}
			break;

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
	log_qcy(DEBUG_INFO, "method:action");
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

static int miio_set_timezone(const char *msg)
{
	cJSON *json,*arrayItem,*object,*item;
    int i=0, ret = 0, id;
    message_t message;
	log_qcy(DEBUG_INFO, "method:set_timezone");
	//get id
	ret = json_verify_get_int(msg, "id", &id);
	if (ret < 0) {
		return ret;
	}
    json=cJSON_Parse(msg);
    arrayItem = cJSON_GetObjectItem(json,"params");
    //add ack json msg
    if(arrayItem) {
        object = cJSON_GetArrayItem(arrayItem,i);
        if(object) {
        	/********message body********/
            msg_init(&message);
            message.sender = message.receiver = SERVER_MIIO;
            message.arg_pass.cat = id;
            message.arg_pass.handler = miio_action_func_ack;
			message.arg_pass.chick = KERNEL_SET_TZ;
			message.message = MSG_KERNEL_CTRL_TIMEZONE;
			message.arg_in.cat = KERNEL_SET_TZ;
            message.arg = (void*)object->valuestring;
            message.arg_size = strlen(object->valuestring) + 1;
        	send_message(SERVER_KERNEL, &message);
        }
    }
    cJSON_Delete(json);
    return ret;
}

static int iot_miio_restore(const char *msg)
{
	cJSON *json,*arrayItem,*object,*item;
    int i=0, ret = 0, id;
    message_t message;
	log_qcy(DEBUG_INFO, "method:miIO.restore");
	//get id
	ret = json_verify_get_int(msg, "id", &id);
	if (ret < 0) {
		return ret;
	}
        	/********message body********/
            msg_init(&message);
            message.sender = message.receiver = SERVER_MIIO;
            message.arg_pass.cat = id;
            message.arg_pass.handler = miio_action_func_ack;
			message.message = MSG_KERNEL_ACTION;
			message.arg_in.cat = KERNEL_ACTION_RESTORE;
			message.arg_pass.chick = KERNEL_ACTION_RESTORE;
        	send_message(SERVER_KERNEL, &message);

    return ret;

}
static int miio_result_parse(const char *msg,int id)
{
    log_qcy(DEBUG_INFO, "msg: %s, strlen: %d",msg, (int)strlen(msg));
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
		log_qcy(DEBUG_WARNING, "%s: Not in json format: %s", __func__, msg);
		return -1;
	}
	if (!json_object_object_get_ex(new_obj, "params", &params)) {
		log_qcy(DEBUG_WARNING, "%s: get params error", __func__);
		json_object_put(new_obj);
		return -1;
	}
	if (!json_object_object_get_ex(params, "code", &tmp_obj)) {
		log_qcy(DEBUG_WARNING, "%s: get code error", __func__);
		json_object_put(new_obj);
		return -1;
	}
	if (json_object_get_type(tmp_obj) != json_type_int) {
		log_qcy(DEBUG_WARNING, "%s: code not int: %s", __func__, msg);
		json_object_put(new_obj);
		return -1;
	}
	code = json_object_get_int(tmp_obj);
	if (!json_object_object_get_ex(params, "ts", &tmp_obj)) {
		log_qcy(DEBUG_WARNING, "%s: get ts error", __func__);
		json_object_put(new_obj);
		return -1;
	}
	if (json_object_get_type(tmp_obj) != json_type_int) {
		log_qcy(DEBUG_WARNING, "%s: ts not int: %s", __func__, msg);
		json_object_put(new_obj);
		return -1;
	}
	json_object_get_int(tmp_obj);
	if (code == -90) {
		log_qcy(DEBUG_WARNING, "TUTK bug: -90, ignore this because interval < 60s.");
	}
	json_object_put(new_obj);
	return 0;
}

int miio_parse_did(char *msg, char *key)
{
    int ret = 0;
    char local_did[32] = {0};
	char *pA = NULL, *pB = NULL, *pC = NULL;
	char buf[64] = {0};
	int len = 0;
	//char *key = "params";
	if (strlen(key) > 59) {
		log_qcy(DEBUG_WARNING,  "key(%s) len is too long(%d), max len(59)!", key, strlen(key));
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
				log_qcy(DEBUG_WARNING,  "value len is too long(%d), max len(32)!", len);
				return -1;
			}
			strncpy(local_did, pA, len);
		} else {
			log_qcy(DEBUG_WARNING,  "response url parse '%s' error!", key);
			return -1;
		}
	} else {
		log_qcy(DEBUG_WARNING,  "response url don't have '%s'!", key);
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
    int old_status = miio_info.miio_status;
	if( json_verify_method_value(msg, "method", "local.bind", json_type_string) == 0) {
		if( (json_verify_method_value(msg, "result", "ok", json_type_string) == 0) &&
				miio_info.miio_status == STATE_WIFI_AP_MODE ) {
			miio_info.miio_status = STATE_WIFI_STA_MODE;
			/***************************************/
			msg_init(&message);
			message.message = MSG_MIIO_PROPERTY_NOTIFY;
			message.sender = message.receiver = SERVER_MIIO;
			message.arg_in.cat = MIIO_PROPERTY_CLIENT_STATUS;
			message.arg_in.dog = miio_info.miio_status;
			manager_message(&message);
			/***************************************/
		}
		return 0;
	}
	if ((json_verify_method_value(msg, "method", "local.status", json_type_string) == 0)) {
		if( json_verify_method_value(msg, "params", "wifi_ap_mode", json_type_string) == 0) {
			if ( (miio_info.miio_status != STATE_WIFI_AP_MODE ) ) {
				miio_info.miio_status = STATE_WIFI_AP_MODE;
				/***************************************/
				msg_init(&message);
				message.message = MSG_SCANNER_QR_CODE_BEGIN;
				message.sender = message.receiver = SERVER_MIIO;
				server_scanner_message(&message);
				/***************************************/
			}
		}
		else if( json_verify_method_value(msg, "params", "wifi_connected", json_type_string) == 0) {
			if ( (miio_info.miio_status != STATE_WIFI_STA_MODE ) ) {
				miio_info.miio_status = STATE_WIFI_STA_MODE;
				if( old_status == STATE_WIFI_AP_MODE) {
					/***************************************/
					msg_init(&message);
					message.message = MSG_MIIO_PROPERTY_NOTIFY;
					message.sender = message.receiver = SERVER_MIIO;
					message.arg_in.cat = MIIO_PROPERTY_CLIENT_STATUS;
					message.arg_in.dog = miio_info.miio_status;
					manager_message(&message);
					/***************************************/
				}
			}
		}
		else if(json_verify_method_value(msg, "params", "internet_connected", json_type_string) == 0) {
			miio_info.miio_status = STATE_CLOUD_CONNECTED;
		}
		else if(json_verify_method_value(msg, "params", "cloud_connected", json_type_string) == 0) {
			miio_info.miio_status = STATE_CLOUD_CONNECTED;
			if( old_status == STATE_WIFI_AP_MODE) {
				/***************************************/
				msg_init(&message);
				message.message = MSG_MIIO_PROPERTY_NOTIFY;
				message.sender = message.receiver = SERVER_MIIO;
				message.arg_in.cat = MIIO_PROPERTY_CLIENT_STATUS;
				message.arg_in.dog = miio_info.miio_status;
				manager_message(&message);
				/***************************************/
			}
		}
		if( old_status != miio_info.miio_status ) {
			/********message body********/
			msg_init(&message);
			message.sender = message.receiver = SERVER_MIIO;
			message.message = MSG_MIIO_PROPERTY_NOTIFY;
			message.arg_in.cat = MIIO_PROPERTY_CLIENT_STATUS;
			message.arg_in.dog = miio_info.miio_status;
			server_miss_message(&message);
			server_kernel_message(&message);
			/****************************/
		}
		return 0;
	}
next_level:
    ret = json_verify_get_int(msg, "id", &id);
    if (ret < 0) {
    	return ret;
    }
    if ( id == ntp_get_rpc_id() ) {
       ret = ntp_time_parse(msg);
       if(ret < 0 ){
            log_qcy(DEBUG_WARNING, "http_jason_get_timeInt error");
       }
       else{
			miio_info.time_sync = 1;
			/********message body********/
			msg_init(&message);
			message.sender = message.receiver = SERVER_MIIO;
			message.message = MSG_MIIO_PROPERTY_NOTIFY;
			message.arg_in.cat = MIIO_PROPERTY_TIME_SYNC;
			message.arg_in.dog = miio_info.time_sync;
			server_player_message(&message);
			server_recorder_message(&message);
			server_video_message(&message);
			server_video2_message(&message);
			server_kernel_message(&message);
			/****************************/
       }
       return 0;
    }
    if ( config.iot.board_type && (id == did_rpc_id) ) {
       ret = miio_parse_did(msg, "params");
       if(ret < 0 ){
            log_qcy(DEBUG_WARNING, "http_jason_get_device_did error");
       }
       else{
    	   if(strlen(config.device.did) > 1)
    	   {
    		   miio_info.did_acquired = 1;
			   /********message body********/
				msg_init(&message);
				message.message = MSG_MIIO_PROPERTY_NOTIFY;
				message.sender = message.receiver = SERVER_MIIO;
				message.arg_in.cat = MIIO_PROPERTY_DID_STATUS;
				message.arg_in.dog = miio_info.did_acquired;
				message.arg = config.device.did;
				message.arg_size = strlen(config.device.did) + 1;
				server_miss_message(&message);
				/********message body********/
    	   }
       }
       return 0;
    }
	/********message body********/
	msg_init(&message);
	message.message = MSG_MISS_RPC_SEND;
	message.sender = message.receiver = SERVER_MIIO;
	message.arg_in.cat = id;
	message.arg = msg;
	message.arg_size = len + 1;
	ret = server_miss_message(&message);
	/********message body********/
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
    else if (json_verify_method_value(msg, "method", "miIO.set_timezone", json_type_string) == 0) {
    	ret = miio_set_timezone(msg);
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
		log_qcy(DEBUG_INFO, "miIO.event: %s", msg);
		sprintf(ackbuf, OT_ACK_SUC_TEMPLATE, id);
		ret = miio_socket_send(ackbuf, strlen(ackbuf));
		miio_event(msg);
	}
	else if (json_verify_method_value(msg, "method", "miss.set_vendor", json_type_string) == 0) {
		log_qcy(DEBUG_INFO, "miss.set_vendor: %s", msg);
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
		ret = iot_miio_restore(msg);
    }
    else {
        log_qcy(DEBUG_INFO, "msg:%s ,strlen: %d, len: %d",msg, (int)strlen(msg), len);
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
				log_qcy(DEBUG_WARNING, "iot_close_retry");
//				miio_close_retry();
			}
			if (left_len) {
				buf[left_len] = '\0';
				log_qcy(DEBUG_WARNING,"%s() remain str: %s", __func__, buf);
			}
			return 0;
		}
		first_read = false;
		ret = miio_recv_handler_block(sockfd, buf, count + left_len);
		if (ret < 0) {
			log_qcy(DEBUG_WARNING,"%s_one() return -1", __func__);
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
			log_qcy(DEBUG_WARNING,"%s(), token parse error msg: %.*s, length: %d bytes",
				    __func__, msg_len, msg, msg_len);
			json_tokener_free(tok);
			return ret;
		}
		tmplen = tok->char_offset;
		tmpstr = malloc(tmplen);
		if (tmpstr == NULL) {
			log_qcy(DEBUG_WARNING,"%s(), malloc error", __func__);
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
		log_qcy("%s, len:%d",msg_queue.msg_buf,msg_queue.len);
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
			log_qcy(DEBUG_WARNING,"kit.otd_sock (%d) not in pollfds.", msg_helper.otd_sock);
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
        log_qcy(DEBUG_SERIOUS, "xm_createMsgQueue failed");
    	return -1;
    }
    if ((ret = pthread_create(&message_tid, NULL, miio_rsv_func, param))) {
    	log_qcy(DEBUG_INFO, "create miio message rsv handler, ret=%d", ret);
    	return -1;
    }
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
    	log_qcy(DEBUG_SERIOUS, "socket failed!");
    	return -1;
    }
	if (msg_helper.otd_sock >= 0) {
		msg_helper.pollfds[msg_helper.count_pollfds].fd = msg_helper.otd_sock;
		msg_helper.pollfds[msg_helper.count_pollfds].events = POLLIN;
		msg_helper.count_pollfds++;
	}
    if ((ret = pthread_create(&message_tid, NULL, miio_poll_func, param))) {
    	log_qcy(DEBUG_SERIOUS, "create mi message handler, ret=%d", ret);
    	return -1;
    }
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
    server_set_status(STATUS_TYPE_THREAD_START, THREAD_POLL, 1);
	while ( (n >= 0) && ( !info.exit ) ) {
		//exit logic
		st = info.status;
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
					log_qcy(DEBUG_WARNING, "POLLOUT fd: %d", msg_helper.otd_sock);
				n--;
			}
			else if (msg_helper.pollfds[i].revents & (POLLNVAL | POLLHUP | POLLERR)) {
				int j = i;
				log_qcy(DEBUG_WARNING,"POLLNVAL | POLLHUP | POLLERR fd: pollfds[%d]: %d, revents: 0x%08x",
					    i, msg_helper.pollfds[i].fd, msg_helper.pollfds[i].revents);
				if (msg_helper.pollfds[i].fd == msg_helper.otd_sock) {
					log_qcy(DEBUG_WARNING, "iot_close_retry ");
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
		log_qcy(DEBUG_WARNING, "close miio.otd_sock");
		close(msg_helper.otd_sock);
	}
	log_qcy(DEBUG_INFO, "-----------thread exit: server_miio_poll-----------");
	server_set_status(STATUS_TYPE_THREAD_START, THREAD_POLL, 0);
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
    server_set_status(STATUS_TYPE_THREAD_START, THREAD_RSV, 1);
	while( !info.exit ) {
		st = info.status;
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
	log_qcy(DEBUG_INFO, "-----------thread exit: server_miio_rsv-----------");
	server_set_status(STATUS_TYPE_THREAD_START, THREAD_RSV, 0);
	pthread_exit(0);
}

static int server_set_status(int type, int st, int value)
{
	int ret=-1;
	ret = pthread_rwlock_wrlock(&info.lock);
	if(ret)	{
		log_qcy(DEBUG_SERIOUS, "add lock fail, ret = %d", ret);
		return ret;
	}
	if(type == STATUS_TYPE_STATUS)
		info.status = st;
	else if(type==STATUS_TYPE_EXIT)
		info.exit = st;
	else if(type==STATUS_TYPE_CONFIG)
		config.status = st;
	else if(type==STATUS_TYPE_THREAD_START)
		misc_set_bit(&info.thread_start, st, value);
	ret = pthread_rwlock_unlock(&info.lock);
	if (ret)
		log_qcy(DEBUG_SERIOUS, "add unlock fail, ret = %d", ret);
	return ret;
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

static int server_release_1(void)
{
	int ret = 0;
	message_t msg;
	miio_close_retry();
	/********message body********/
	msg_init(&msg);
	msg.message = MSG_MANAGER_TIMER_REMOVE;
	msg.sender = msg.receiver = SERVER_MIIO;
	msg.arg_in.handler = miio_routine_1000ms;
	manager_message(&msg);
	/****************************/
	return ret;
}

static int server_release_2(void)
{
	int ret = 0;
	msg_buffer_release(&message);
	msg_free(&info.task.msg);
	memset(&info,0,sizeof(server_info_t));
	memset(&config,0,sizeof(miio_config_t));
	memset(&miio_info,0,sizeof(miio_info_t));
	memset(&msg_helper,0,sizeof(msg_helper_t));
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
		log_qcy(DEBUG_WARNING, "%s: Not in json format: %s", __func__, params);
		return -1;
	}

	struct json_object *send_object = json_object_new_object();
	if (NULL == send_object) {
		log_qcy(DEBUG_WARNING, "%s: init send_object failed", __func__);
		return -1;
	}

	json_object_object_add(send_object, "id", json_object_new_int(msg_id));
	json_object_object_add(send_object, "method", json_object_new_string(method));
	json_object_object_add(send_object, "params", params_obj);
	sprintf(sendbuf, "%s", json_object_to_json_string_ext(send_object, JSON_C_TO_STRING_NOZERO));

	json_object_put(send_object);
	//json_object_put(params_obj);
	if (msg_helper.otd_sock == 0) {
		log_qcy(DEBUG_WARNING, "rpc socket uninit");
		return -1;
	}
	log_qcy(DEBUG_INFO, "rpc_msg_send: %s", sendbuf);
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
		log_qcy(DEBUG_WARNING, "%s: init send_object failed", __func__);
		return -1;
	}
	struct json_object *params_obj = json_object_new_object();
	if (NULL == params_obj) {
		log_qcy(DEBUG_WARNING, "%s: init params_obj failed", __func__);
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
	log_qcy(DEBUG_INFO, "rpc_report_send: %s", sendbuf);
	return 0;
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
		log_qcy(DEBUG_SERIOUS, "add message lock fail, ret = %d", ret);
		return ret;
	}
	ret = msg_buffer_pop(&message, &msg);
	ret1 = pthread_rwlock_unlock(&message.lock);
	if (ret1) {
		log_qcy(DEBUG_SERIOUS, "add message unlock fail, ret = %d", ret1);
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
			info.exit = 1;
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
		case MSG_VIDEO_PROPERTY_GET_ACK:
		case MSG_DEVICE_GET_PARA_ACK:
		case MSG_RECORDER_PROPERTY_GET_ACK:
		case MSG_MANAGER_PROPERTY_GET_ACK:
			if( msg.arg_pass.handler != NULL)
				( *( int(*)(message_arg_t,int,int,void*) ) msg.arg_pass.handler ) (msg.arg_pass, msg.result, msg.arg_size, msg.arg);
			break;
		case MSG_VIDEO_PROPERTY_SET_ACK:
		case MSG_VIDEO_PROPERTY_SET_EXT_ACK:
		case MSG_VIDEO_PROPERTY_SET_DIRECT_ACK:
		case MSG_VIDEO_START_ACK:
		case MSG_VIDEO_STOP_ACK:
		case MSG_RECORDER_PROPERTY_SET_ACK:
		case MSG_MANAGER_PROPERTY_SET_ACK:
			if( msg.arg_pass.handler != NULL)
				( *( int(*)(message_arg_t,int,int,void*) ) msg.arg_pass.handler ) (msg.arg_pass, msg.result, msg.arg_size, msg.arg);
			break;
		case MSG_DEVICE_ACTION_ACK:
		case MSG_KERNEL_CTRL_TIMEZONE_ACK:
		case MSG_KERNEL_ACTION_ACK:
			miio_action_func_ack(msg.arg_pass, msg.result, msg.arg_size, msg.arg);
			break;
		case MSG_KERNEL_OTA_REPORT_ACK:
			ota_proc(msg.arg_in.cat, msg.arg_in.dog,msg.arg_in.duck);
			break;
		case MSG_KERNEL_OTA_REQUEST_ACK:
			//log_info("into MSG_KERNEL_OTA_REQUEST_ACK\n");
			ota_get_state_ack(msg.arg_pass.cat, msg.arg_pass.chick, msg.arg_in.cat, msg.arg_in.dog);
			break;
		case MSG_KERNEL_OTA_DOWNLOAD_ACK:
			//log_info("into MSG_KERNEL_OTA_DOWNLOAD_ACK\n");
			ota_down_ack(msg.arg_pass.cat, msg.result);
			break;
		case MSG_MIIO_PROPERTY_GET:
		    /********message body********/
			msg_init(&send_msg);
			send_msg.message = msg.message | 0x1000;
			send_msg.sender = send_msg.receiver = SERVER_MIIO;
			send_msg.arg_in.cat = msg.arg_in.cat;
			if( send_msg.arg_in.cat == MIIO_PROPERTY_CLIENT_STATUS) {
				send_msg.arg_in.dog = miio_info.miio_status;
			}
			else if( msg.arg_in.cat == MIIO_PROPERTY_TIME_SYNC) {
				send_msg.arg_in.dog = miio_info.time_sync;
			}
			else if( msg.arg_in.cat == MIIO_PROPERTY_DID_STATUS) {
				send_msg.arg_in.dog = miio_info.did_acquired;
				send_msg.arg = config.device.did;
				send_msg.arg_size = strlen(config.device.did) + 1;
			}
			send_msg.result = 0;
			ret = send_message(msg.receiver, &send_msg);
			/***************************/
			break;
		case MSG_SCANNER_QR_CODE_BEGIN_ACK:
			if( !msg.result ) {
				ret = miio_socket_send((char*)msg.arg, msg.arg_size-1);
			}
			break;
		default:
			log_qcy(DEBUG_SERIOUS, "not processed message = %x", msg.message);
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
	if( (tick - info.tick) > SERVER_HEARTBEAT_INTERVAL ) {
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
			log_qcy(DEBUG_SERIOUS, "!!!!!!!!error in miio, restart in 5 s!");
			info.tick2 = time_get_now_stamp();
			info.status = STATUS_NONE;
			break;
		case STATUS_NONE:
			tick = time_get_now_stamp();
			if( (tick - info.tick2) > SERVER_RESTART_PAUSE ) {
				info.exit = 1;
				info.tick2 = tick;
			}
			break;
		default:
			log_qcy(DEBUG_SERIOUS, "!!!!!!!unprocessed server status in task_error = %d", info.status);
			break;
	}
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
			break;
		case STATUS_WAIT:
			info.status = STATUS_SETUP;
			break;
		case STATUS_SETUP:
			ret = miio_rsv_init(NULL);
			if ( ret!=0 ) {
				info.status = STATUS_ERROR;
				break;
			}
			ret = miio_poll_init(NULL);
			if ( ret!=0 ) {
				info.status = STATUS_ERROR;
				break;
			}
			info.status = STATUS_IDLE;
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
			info.status = STATUS_RUN;
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
		default:
			log_qcy(DEBUG_SERIOUS, "!!!!!!!unprocessed server status in task_default = %d", info.status);
			break;
	}
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
	if( !message.init ) {
		msg_buffer_init(&message, MSG_BUFFER_OVERFLOW_NO);
	}
	//default task
	info.task.func = task_default;
	info.task.start = STATUS_NONE;
	info.task.end = STATUS_RUN;
	while( !info.exit ) {
		info.task.func();
		server_message_proc();
		if( info.status!=STATUS_ERROR )
			heart_beat_proc();
	}
	server_release_1();
	if( info.exit ) {
		while( info.thread_start ) {
			log_qcy(DEBUG_INFO, "---------------locked miio---- %d", info.thread_start);
		}
		server_release_2();
	    /********message body********/
		message_t msg;
		msg_init(&msg);
		msg.message = MSG_MANAGER_EXIT_ACK;
		msg.sender = SERVER_MIIO;
		manager_message(&msg);
		/***************************/
	}
	log_qcy(DEBUG_INFO, "-----------thread exit: server_miio-----------");
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
	ret = pthread_create(&info.id, NULL, server_func, NULL);
	if(ret != 0) {
		log_qcy(DEBUG_SERIOUS, "miio server create error! ret = %d",ret);
		 return ret;
	 }
	else {
		log_qcy(DEBUG_INFO, "miio server create successful!");
		return 0;
	}
}

int server_miio_message(message_t *msg)
{
	int ret=0,ret1=0;
	if( !message.init ) {
		log_qcy(DEBUG_INFO, "miio server is not ready for message processing!");
		return -1;
	}
	ret = pthread_rwlock_wrlock(&message.lock);
	if(ret)	{
		log_qcy(DEBUG_SERIOUS, "add message lock fail, ret = %d", ret);
		return ret;
	}
	ret = msg_buffer_push(&message, msg);
	log_qcy(DEBUG_VERBOSE, "push into the miio message queue: sender=%d, message=%x, ret=%d, head=%d, tail=%d", msg->sender, msg->message, ret,
			message.head, message.tail);
	if( ret!=0 )
		log_qcy(DEBUG_WARNING, "message push in miio error =%d", ret);
	ret1 = pthread_rwlock_unlock(&message.lock);
	if (ret1)
		log_qcy(DEBUG_SERIOUS, "add message unlock fail, ret = %d", ret1);
	return ret;
}
