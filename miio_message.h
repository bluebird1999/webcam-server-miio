/*
 * miio_message.h
 *
 *  Created on: Aug 14, 2020
 *      Author: ning
 */

#ifndef SERVER_MIIO_MIIO_MESSAGE_H_
#define SERVER_MIIO_MIIO_MESSAGE_H_

/*
 * header
 */

/*
 * define
 */
#define MIIO_MAX_PAYLOAD        1024
#define MIIO_MESSAGE_TYPE 		1

/*
 * structure
 */
typedef struct miio_message_queue_t {
    long 	mtype;
    int 	len;
    char 	msg_buf[MIIO_MAX_PAYLOAD];
}miio_message_queue_t;

/*
 * function
 */
int miio_send_msg_queue(int msg_id,struct miio_message_queue_t *msg_queue);
int miio_rec_msg_queue(int msg_id, int recvType, struct miio_message_queue_t *msg_queue);
int miio_create_msg_queue();

#endif /* SERVER_MIIO_MIIO_MESSAGE_H_ */
