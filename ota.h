/*
 * ota.h
 *
 *  Created on: Oct 5, 2020
 *      Author: ning
 */

#ifndef SERVER_MIIO_OTA_H_
#define SERVER_MIIO_OTA_H_

/*
 * header
 */
#include "../../manager/global_interface.h"

/*
 * define
 */
/*
 * structure
 */
typedef struct ota_config_t {
	int		status;
	int		progress;
    char 	url[MAX_SYSTEM_STRING_SIZE*8];
    char 	md5[MAX_SYSTEM_STRING_SIZE*4];
    int 	mode;
    int 	proc;
} ota_config_t;

/*
 * function
 */
int ota_get_state_ack(int did, int type, int status, int progress);
int ota_init(const char *msg);
int ota_get_state(const char *msg);
int ota_get_progress(const char *msg);
int ota_proc(int status, int progress, int err_id);
int ota_down_ack(int id, int result);

#endif /* SERVER_MIIO_OTA_H_ */
