/*
 * ntp.c
 *
 *  Created on: Sep 17, 2020
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
#include "../../tools/json/json.h"
#include "../../tools/log.h"
//server header
#include "ntp.h"


/*
 * static
 */
//variable
static int	ntp_id;
//function
static int ntp_change_system_time(struct timeval newtime);
static int ntp_parse_jason(char* msg, char* key, char*value, int max_len);
/*
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 */

/*
 * helper
 */
static int ntp_change_system_time(struct timeval newtime)
{
    int ret;
    struct timeval tv;
	ret = settimeofday(&newtime, NULL);
	if(ret == -1) {
		log_err("mod systemTime settimeofday error\n");
		return -1;
	}
    gettimeofday (&tv, NULL);
    log_info("after ntp set time,get tv_sec; %ld\n", tv.tv_sec);
	return 0;
}

static int ntp_parse_jason(char* msg, char* key, char*value, int max_len)
{
	int ret = 0;
	char *pA = NULL, *pB = NULL, *pC = NULL;
	char buf[64] = {0};
	int len = 0;
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
			if (len > max_len) {
				log_err( "value len is too long(%d), max len(%d)!\n", len, max_len);
				return -1;
			}
			strncpy(value, pA, len);
		} else {
			log_err( "response url parse '%s' error!\n", key);
			return -1;
		}
	} else {
		log_err( "response url don't have '%s'!\n", key);
		return -1;
	}
	return ret;
}
/*
 * interface
 */
int ntp_get_local_time(void)
{
	int ret = 0;
  	ntp_id = generate_random_id();
	char ackbuf[1024] = {0x00};

	struct json_object *send_object = json_object_new_object();
	json_object_object_add(send_object, "id", json_object_new_int(ntp_id));
	json_object_object_add(send_object, "method", json_object_new_string("local.query_time"));
	sprintf(ackbuf, "%s", json_object_to_json_string_ext(send_object, 1));

	json_object_put(send_object);
	ret = miio_send_to_cloud(ackbuf, strlen(ackbuf));
	return ret;
}

int ntp_get_rpc_id(void)
{
    return ntp_id;
}

int ntp_time_parse(char *msg)
{
    int ret = 0;
    unsigned long long time_sec;
    struct timeval timeval;
    char local_time[32] = {0};

    ret = ntp_parse_jason(msg, "params", local_time, sizeof(local_time));
    if( ret == -1 ) {
    	log_err("json string parse error\n");
    	return ret;
    }
    time_sec = atoll(local_time);
    timeval.tv_sec = time_sec;
    timeval.tv_usec = 0;
    ret = ntp_change_system_time(timeval);
    if(ret < 0) {
        log_err("mod systemTime error\n");
    }

    return ret ;
}

