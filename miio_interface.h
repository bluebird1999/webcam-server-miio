/*
 * miio_interface.h
 *
 *  Created on: Aug 28, 2020
 *      Author: ning
 */

#ifndef SERVER_MIIO_MIIO_INTERFACE_H_
#define SERVER_MIIO_MIIO_INTERFACE_H_

/*
 * header
 */
#include "../../manager/manager_interface.h"


#define		MSG_DEVICE_BASE						(SERVER_DEVICE<<16)
#define		MSG_DEVICE_GET_PARA					MSG_DEVICE_BASE | 0x0000
#define		MSG_DEVICE_GET_PARA_ACK				MSG_DEVICE_BASE | 0x1000

/*
 * define
 */
#define		MSG_MIIO_BASE						(SERVER_MIIO<<16)
#define		MSG_MIIO_CLOUD_TRYING				MSG_MIIO_BASE | 0x0000
#define		MSG_MIIO_CLOUD_CONNECTED			MSG_MIIO_BASE | 0x0001
#define		MSG_MIIO_MISSRPC_ERROR				MSG_MIIO_BASE | 0x0002
#define		MSG_MIIO_RPC_SEND					MSG_MIIO_BASE | 0x0003
#define		MSG_MIIO_RPC_REPORT_SEND			MSG_MIIO_BASE | 0x0004
#define		MSG_MIIO_SIGINT						MSG_MIIO_BASE | 0x0010
#define		MSG_MIIO_SIGTERM					MSG_MIIO_BASE | 0x0011
#define		MSG_MIIO_EXIT						MSG_MIIO_BASE | 0X0020

/*
 * structure
 */

/*
 * function
 */
int server_miio_start(void);
int server_miio_message(message_t *msg);


#endif /* SERVER_MIIO_MIIO_INTERFACE_H_ */
