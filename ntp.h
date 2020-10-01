/*
 * ntp.h
 *
 *  Created on: Sep 17, 2020
 *      Author: ning
 */

#ifndef SERVER_MIIO_NTP_H_
#define SERVER_MIIO_NTP_H_

/*
 * header
 */

/*
 * define
 */

/*
 * structure
 */

/*
 * function
 */
int ntp_get_local_time(void);
int ntp_get_rpc_id(void);
int ntp_time_parse(char *msg);

#endif /* SERVER_MIIO_NTP_H_ */
