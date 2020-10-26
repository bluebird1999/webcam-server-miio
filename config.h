/*
 * config_miio.h
 *
 *  Created on: Aug 16, 2020
 *      Author: ning
 */

#ifndef SERVER_MIIO_CONFIG_H_
#define SERVER_MIIO_CONFIG_H_

/*
 * header
 */

/*
 * define
 */
#define		CONFIG_MIIO_MODULE_NUM 	2
#define		CONFIG_MIIO_IOT			0
#define		CONFIG_MIIO_DEVICE		1

#define 	CONFIG_MIIO_IOT_PATH				"/opt/qcy/config/miio_iot.config"
#define		CONFIG_MIIO_DEVICE_PATH				"/etc/miio/device.conf"
#define		CONFIG_MIIO_TOKEN_PATH				"/etc/miio/device.token"
#define		CONFIG_MIIO_OSRELEASE_PATH			"/etc/miio/os-release"

/*
 * structure
 */
typedef struct miio_config_device_t {
	char did[MAX_SYSTEM_STRING_SIZE];
	char key[MAX_SYSTEM_STRING_SIZE];
	char vendor[MAX_SYSTEM_STRING_SIZE];
	char mac[MAX_SYSTEM_STRING_SIZE];
	char model[MAX_SYSTEM_STRING_SIZE];
	char version[MAX_SYSTEM_STRING_SIZE];		//linux
	char miio_token[2*MAX_SYSTEM_STRING_SIZE];
} miio_config_device_t;


typedef struct miio_config_iot_t {
	int	board_type;
} miio_config_iot_t;


typedef struct miio_config_t {
	int							status;
	miio_config_device_t		device;
	miio_config_iot_t			iot;
} miio_config_t;
/*
 * function
 */
int config_miio_read(miio_config_t *);
int config_miio_set(int module, void *arg);
int config_miio_get_config_status(int module);

#endif /* SERVER_MIIO_CONFIG_H_ */
