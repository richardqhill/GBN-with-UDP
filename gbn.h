#ifndef _gbn_h
#define _gbn_h

#include<sys/types.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<signal.h>
#include<unistd.h>
#include<fcntl.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<time.h>
#include <arpa/inet.h>


/*----- Error variables -----*/
extern int h_errno;
extern int errno;

/*----- Protocol parameters -----*/
#define LOSS_PROB 1e-2    /* loss probability                            */
#define CORR_PROB 1e-3    /* corruption probability                      */
#define DATALEN   1024    /* length of the payload                       */
#define N         1024    /* Max number of packets a single call to gbn_send can process */
#define TIMEOUT      10    /* timeout to resend packets (2 second)        */
#define MAX_NUM_TIMEOUTS 5  /* Max # of timeouts before sender closes connection   */

/*----- Packet/State types -----*/
#define SYN      0        /* Opens a connection                          */
#define SYNACK   1        /* Acknowledgement of the SYN packet           */
#define DATA     2        /* Data packets                                */
#define DATAACK  3        /* Acknowledgement of the DATA packet          */
#define FIN      4        /* Ends a connection                           */
#define FINACK   5        /* Acknowledgement of the FIN packet           */
#define RST      6        /* Reset packet used to reject new connections */

/*----- Ack status types ----- */
#define ACKSTATUS_TIMEOUT -1
#define ACKSTATUS_CORRUPT -2
#define ACKSTATUS_BADSEQ -3

/*----- Window Speed Modes ----- */
#define WINDOW_SLOWMODE 1
#define WINDOW_MODMODE 2
#define WINDOW_FASTMODE 4

/*----- Booleans -----*/
#define TRUE  1
#define FALSE 0

/*----- Roles -----*/
#define CLIENT  2
#define SERVER  3

/*----- Go-Back-n packet format -----*/
typedef struct {
	uint8_t type;            /* packet type (e.g. SYN, DATA, ACK, FIN)       */
	// uint16_t seqnum;         /* sequence number of the packet. Updated to 16 */
	uint16_t data_length_in_bytes;
	uint16_t packet_num;
    uint16_t checksum;        /* header and payload checksum                  */
    uint8_t data[DATALEN];    /* pointer to the payload                       */
} __attribute__((packed)) gbnhdr;

typedef struct state_t{

    uint8_t state;
    uint8_t role;

    struct sockaddr_storage client;
    struct sockaddr *client_ptr;
    struct sockaddr_storage server;
    struct sockaddr *server_ptr;
    socklen_t dest_socklen;


    uint16_t next_expected_pack_num;  /* Server/Receiver: packet number after the highest in sequence packet  */
    uint16_t window_start;            /* Client/Sender: the highest packet number that server has not yet DATAACKED */

    uint8_t recv_ack_timeout_count;

    uint8_t window_size;
    gbnhdr packet_buf[N+1];     /* Packet #1 is stored at index 1              */

} state_t;



enum {
	CLOSED=0,
	LISTENING,
	SYN_SENT,
	SYN_RCVD,
	ESTABLISHED,
	FIN_SENT,
	FIN_RCVD
};

extern state_t s;

void gbn_init();
int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen);
int gbn_listen(int sockfd, int backlog);
int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen);
int gbn_socket(int domain, int type, int protocol);
int gbn_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int gbn_close(int sockfd);
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags);

ssize_t  maybe_recvfrom(int  s, char *buf, size_t len, int flags, \
            struct sockaddr *from, socklen_t *fromlen);

uint16_t checksum(uint16_t *buf, int nwords);

void gbn_init();
void gbnhdr_clear_packet(gbnhdr *packet);
uint8_t gbnhdr_packet_builder(gbnhdr *packet, uint8_t type, uint16_t packet_num, uint16_t payload_length, const void *buf);
uint8_t gbnhdr_validate_checksum(gbnhdr *packet);
ssize_t gbn_send_data_packet(int sockfd, uint16_t packet_num, int flags);
ssize_t gbn_recv_dataack(int sockfd, int flags);
ssize_t gbn_send_dataack(int sockfd, uint16_t packet_num, int flags);

void signal_handler();

void set_window_slow();
void set_window_med();
void set_window_fast();




#endif
