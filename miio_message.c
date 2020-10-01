/*
 * mi_message.c
 *
 *  Created on: Aug 14, 2020
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
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <pthread.h>
#include <json-c/json.h>
//program header
#include "../../tools/json/json.h"
#include "../../tools/log.h"
//server header
#include "miio_message.h"


/*
 * static
 */
//variable


//function
static int miio_comm_msg_queue(int flags);
static int miio_get_msg_queue(void);
static int miio_destory_msg_queue(int msg_id);

/*
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 */
static int miio_comm_msg_queue(int flags)
{
    key_t key = ftok("/tmp", 0x6666);
    if(key < 0) {
        perror("ftok");
        return -1;
    }

    int msg_id = msgget(key, flags);
    if(msg_id < 0) {
        perror("msgget");
    }
    return msg_id;
}

static int miio_get_msg_queue(void)
{
    return miio_comm_msg_queue(IPC_CREAT);
}

static int miio_destory_msg_queue(int msg_id)
{
    if(msgctl(msg_id, IPC_RMID, NULL) < 0) {
        perror("msgctl");
        return -1;
    }
    return 0;
}


/*
 * interface
 */
int miio_send_msg_queue(int msg_id,struct miio_message_queue_t *msg_queue)
{
    struct miio_message_queue_t buf;

    buf.mtype = msg_queue->mtype;
    buf.len = msg_queue->len;
//    buf.msg_buf = msg_queue->msg_buf;
    memcpy(buf.msg_buf, msg_queue->msg_buf, buf.len);

    int ret = msgsnd(msg_id, (void*)&buf, (4 + buf.len), 0);
    if( ret < 0) {
//      perror("msgsnd");
        return -1;
    }
    return 0;
}

int miio_rec_msg_queue(int msg_id, int recvType, struct miio_message_queue_t *msg_queue)
{
    struct miio_message_queue_t buf;

    int size = MIIO_MAX_PAYLOAD + 4;
    int ret = msgrcv(msg_id, (void*)&buf, size, recvType, IPC_NOWAIT);
    if( ret < 0) {
//      perror("msgrcv");
        return -1;
    }

    msg_queue->len = buf.len;
//   msg_queue->msg_buf = buf.msg_buf;
    memcpy(msg_queue->msg_buf, buf.msg_buf, msg_queue->len);
    return 0;
}

int miio_create_msg_queue()
{
    return miio_comm_msg_queue(IPC_CREAT|0666);
}
