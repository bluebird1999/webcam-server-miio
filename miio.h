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
#include <poll.h>
#include "miio_interface.h"
/*
 * define
 */
#define	THREAD_POLL					0
#define	THREAD_RSV					1

#define	MIIO_CLIENT_AGENT_FILE		"miio_client"
#define	MIIO_CLIENT_HELPER_FILE		"miio_helper"

#define	ACK_MAX						1024
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
#define	OT_REG_OK_TEMPLATE			"{\"id\": %d,\"result\" : {\"code\" : 0,\"out\" : []}}"
#define OT_REG_ERR_TEMPLATE			"{\"id\": %d,\"result\" : {\"code\" : -4004}}"
#define OT_REG_BOOL_TEMPLATE		"{\"id\": %d,\"method\": \"properties_changed\",\"params\":[{\"did\" : \"%s\",\"siid\" : %d,\"piid\" : %d,\"value\" : %s}]}"
#define OT_REG_INT_TEMPLATE			"{\"id\": %d,\"method\": \"properties_changed\",\"params\":[{\"did\" : \"%s\",\"siid\" : %d,\"piid\" : %d,\"value\" : %d}]}"
#define OT_REG_STR_TEMPLATE			"{\"id\": %d,\"method\": \"properties_changed\",\"params\":[{\"did\" : \"%s\",\"siid\" : %d,\"piid\" : %d,\"value\" : \"%s\"}]}"

#define		MIIO_INIT_CONDITION_NUM				1
#define		MIIO_INIT_CONDITION_CONFIG			0

#define		MIIO_EXIT_CONDITION					0
/*
 * structure
 */
typedef struct msg_helper_t {
	struct pollfd pollfds[MAX_POLL_FDS];
	int count_pollfds;
	int timerfd;
	int timerfd2;
	int otd_sock;
	int mc_fd;
	bool force_exit;
} msg_helper_t;

typedef struct miio_msg_ctl {
	int id;
	int sum;
	int num;
	cJSON *root_ack;
	cJSON *item_result;
} miio_msg_ctl_t;

typedef enum{
    MIIO_CLIENT_NONE,
	MIIO_CLIENT_RUN,
	MIIO_CLIENT_ERROR,
}miio_client_t;

typedef struct miio_info_t {
	miio_status_t	miio_status;
	miio_status_t	miio_old_status;
	int				time_sync;
	int				did_acquired;
} miio_info_t;

/*
 * function
 */
int miio_send_to_cloud(char *buf, int size);

#endif /* SERVER_MIIO_MIIO_H_ */
