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

/*
 * define
 */
#define		SERVER_MIIO_VERSION_STRING			"alpha-8.1"

#define		MSG_MIIO_BASE						(SERVER_MIIO<<16)
#define		MSG_MIIO_SIGINT						(MSG_MIIO_BASE | 0x0000)
#define		MSG_MIIO_SIGINT_ACK					(MSG_MIIO_BASE | 0x1000)
#define		MSG_MIIO_MISSRPC_ERROR				(MSG_MIIO_BASE | 0x0010)
#define		MSG_MIIO_RPC_SEND					(MSG_MIIO_BASE | 0x0020)
#define		MSG_MIIO_RPC_SEND_ACK				(MSG_MIIO_BASE | 0x1020)
#define		MSG_MIIO_RPC_REPORT_SEND			(MSG_MIIO_BASE | 0x0021)
#define		MSG_MIIO_RPC_REPORT_SEND_ACK		(MSG_MIIO_BASE | 0x1021)
#define		MSG_MIIO_SOCKET_SEND				(MSG_MIIO_BASE | 0x0022)
#define		MSG_MIIO_SOCKET_SEND_ACK			(MSG_MIIO_BASE | 0x1022)
#define		MSG_MIIO_PROPERTY_GET				(MSG_MIIO_BASE | 0x0030)
#define		MSG_MIIO_PROPERTY_GET_ACK			(MSG_MIIO_BASE | 0x1030)
#define		MSG_MIIO_PROPERTY_NOTIFY			(MSG_MIIO_BASE | 0x0031)

/*
#define		OTA_TYPE_UBOOT							0x00
#define		OTA_TYPE_KERNEL							0x01
#define		OTA_TYPE_ROOTFS							0x02
#define		OTA_TYPE_APPLICATION					0x03
#define		OTA_TYPE_MIIO_CLIENT					0x04
#define		OTA_TYPE_CONFIG							0x05
#define		OTA_TYPE_LIB							0x06
*/
#define		MIIO_PROPERTY_SERVER_STATUS				(0x0000 | PROPERTY_TYPE_GET)
#define		MIIO_PROPERTY_CLIENT_STATUS				(0x0001 | PROPERTY_TYPE_GET | PROPERTY_TYPE_NOTIFY)
#define		MIIO_PROPERTY_TIME_SYNC					(0x0002 | PROPERTY_TYPE_GET | PROPERTY_TYPE_NOTIFY)
#define		MIIO_PROPERTY_DID_STATUS				(0x0003 | PROPERTY_TYPE_GET | PROPERTY_TYPE_NOTIFY)

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

typedef enum
{
	OTA_PROC_DNLD = 1,
	OTA_PROC_INSTALL,
	OTA_PROC_DNLD_INSTALL,
}OTA_PROC;

typedef enum
{
	OTA_MODE_SILENT = 1,
	OTA_MODE_NORMAL,
}OTA_MODE;

typedef enum
{
	OTA_STATE_IDLE = 0,
	OTA_STATE_DOWNLOADING,
	OTA_STATE_DOWNLOADED,
	OTA_STATE_INSTALLING,
	OTA_STATE_WAIT_INSTALL,
	OTA_STATE_INSTALLED,
	OTA_STATE_FAILED,
	OTA_STATE_BUSY,
}OTA_STATE;

typedef enum
{
	OTA_ERR_NONE = 0,       //无错误
	OTA_ERR_DOWN_ERR,       //下载失败，设备侧无法提供失败的原因，一般是网络连接失败
	OTA_ERR_DNS_ERR,        //dns解析失败
	OTA_ERR_CONNECT_ERR,    //连接下载服务器失败
	OTA_ERR_DICONNECT,      //下载过程中连接中断
	OTA_ERR_INSTALL_ERR,    //安装错误，下载已经完成，但是安装的时候报错
	OTA_ERR_CANCEL,         //设备侧取消下载
	OTA_ERR_LOW_ENERGY,     //电量低，终止下载
	OTA_ERR_UNKNOWN,        //未知原因
};

/*
 * function
 */
int server_miio_start(void);
int server_miio_message(message_t *msg);


#endif /* SERVER_MIIO_MIIO_INTERFACE_H_ */
