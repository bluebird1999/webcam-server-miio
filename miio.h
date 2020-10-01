/*
 * miio.h
 *
 *  Created on: Aug 13, 2020
 *      Author: ning
 */


#ifndef SERVER_MIIO_MIIO_H_
#define SERVER_MIIO_MIIO_H_

/*
 * header
 */
#include <stdio.h>

/*
 * define
 */
#define	THREAD_POLL					0
#define	THREAD_RSV					1

#define	MIIO_CLIENT_AGENT_FILE		"miio_client"
#define	MIIO_CLIENT_HELPER_FILE		"miio_helper"

#define BUFFER_MAX  				4096
#define MIIO_IP      				"127.0.0.1"
#define MIIO_PORT    				54322
#define MAX_POLL_FDS    			10
#define POLL_TIMEOUT    			100	/* 100ms */
#define TIMER_INTERVAL  			(30*1000*60*60*12)	/* 30d */
#define TIMER_INTERVAL_REPORT 		5000

#define OT_ACK_SUC_TEMPLATE 		"{\"id\":%d,\"result\":[\"OK\"]}"
#define OT_ACK_ERR_TEMPLATE 		"{\"id\":%d,\"error\":{\"code\":-33020,\"message\":\"%s\"}}"
#define OT_UP_PWD_TEMPLATE 			"{\"id\":%d,\"method\":\"props\",\"params\":{\"p2p_id\":\"%s\",\"p2p_password\":\"%s\", \"p2p_checktoken\":\"%s\", \"p2p_dev_public_key\":\"%s\"}}"
#define OT_UP_SYS_STATUS_TEMPLATE 	"{\"id\":%d,\"method\":\"props\",\"params\":{\"power\":\"%s\"}}"
#define OT_GET_P2P_ID_TEMPLATE 		"{\"id\":%d,\"method\":\"_sync.get_p2p_id\",\"params\":{}}"

#define	CALLBACK_OWN					0		//callback for only usage
#define	CALLBACK_MIIO_GET_PROPERTY		1		//send back property
#define	CALLBACK_MIIO_SET_RPOPERTY		2		//send back property set result

/*
 * structure
 */
typedef enum miio_status_t {
	STATE_DEVICE_INIT,
	STATE_DIDKEY_REQ1,
	STATE_DIDKEY_REQ2,
	STATE_DIDKEY_DONE,
	STATE_TOKEN_DONE,
	STATE_WIFI_AP_MODE,
	STATE_WIFI_STA_MODE,
	STATE_CLOUD_TRYING,
	STATE_CLOUD_CONNECTED,
	STATE_CLOUD_CONNECT_RETRY,
} miio_status_t;


typedef struct msg_helper_t {
	struct pollfd pollfds[MAX_POLL_FDS];
	int count_pollfds;
	int timerfd;
	int timerfd2;
	int otd_sock;
	int mc_fd;
	bool force_exit;
} msg_helper_t;

typedef enum{
    MIIO_CLIENT_NONE,
	MIIO_CLIENT_RUN,
	MIIO_CLIENT_ERROR,
}miio_client_t;

typedef struct miio_info_t {
	miio_status_t	miio_status;
	int				time_sync;
} miio_info_t;

/*
 * function
 */
int miio_send_to_cloud(char *buf, int size);


#endif /* SERVER_MIIO_MIIO_H_ */
