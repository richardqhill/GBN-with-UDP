#include "gbn.h"

state_t client_state;
state_t server_state;

int gbn_socket(int domain, int type, int protocol){
    gbn_init();
    return socket(domain, type, protocol);
}
void gbn_init(){
    /* Initialize our Server struct */
    memset(&server_state,0,sizeof(server_state));
    server_state.state = CLOSED;
    server_state.seqnum = 0;

    /* Initialize our Client struct */
    memset(&client_state,0,sizeof(client_state));
    client_state.state = CLOSED;
    client_state.seqnum = 0;

    /* Set up struct for interrupt timer */
    struct sigaction sact;
    sact.sa_handler = signal_handler;
    sact.sa_flags = 0;
    sigaction(SIGALRM, &sact, NULL);
}
int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){
    sockfd = bind(sockfd, server, socklen);

    // We do not want recvfrom to block so that we can queue up multiple recvfrom's
    //fcntl(sockfd, F_SETFL, O_NONBLOCK);

    return sockfd;
}
int gbn_listen(int sockfd, int backlog){
    return(0);
}

/* Called by Server/Sender to connect to Client/Receiver */
// Does this work if runs receiver first?
int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){
    printf("gbn_connect:\n");

    /* Use our Client struct to keep track of Server sockaddr/length */
    memcpy(&client_state.server, server, socklen);
    client_state.server_ptr = &client_state.server;
    client_state.dest_socklen = socklen;

    state_t temp = client_state; // troubleshooting

    // Create a SYN packet
    gbnhdr syn_packet;
    size_t packet_size = gbnhdr_packet_builder(&syn_packet, SYN, client_state.seqnum, NULL, 0);

    // Create a place to store a return packet from Server
    gbnhdr packet_from_server;
    gbnhdr_clear_packet(&packet_from_server);

    // we can update this to try like ~5-10 times
    while(TRUE){
        if((sendto(sockfd, &syn_packet, packet_size, 0, server, socklen)) == -1){
            printf("We failed to send SYN\n");
        }
        else {
            printf("Client sent SYN, waiting to receive SYNACK from Server \n");
            client_state.state = SYN_SENT;

            if((recvfrom(sockfd, &packet_from_server, sizeof(gbnhdr), 0, server, &socklen)) == -1)
                printf("Client did not receive SYNACK from Server \n");
            else if(packet_from_server.type == SYNACK) {
                printf("Client received SYNACK from Server! \n");
                client_state.state = ESTABLISHED;
                return 0;
            }
        }
    }
    printf("Client failed to connect to Server \n");
    return(-1);
}

/* Called by Client/Receiver to take SYN from Receiver and return SYNACK */
int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){
    printf("gbn_accept:\n");

    /* Allow Server to keep track of Client sockaddr/length with our state struct */
    memcpy(&server_state.sockaddr, client, *socklen);
    server_state.dest_sockaddr_ptr = &server_state.sockaddr;
    server_state.dest_socklen = *socklen;

    state_t temp = server_state;  // troubleshooting


    // Create a place to store packet from Client. Populated by recvfrom
    gbnhdr packet_from_client;
    gbnhdr_clear_packet(&packet_from_client);

    // Update to have like 10 attempts, 1 attempt every second...
    while(TRUE){
        if((recvfrom(sockfd, &packet_from_client, sizeof(gbnhdr), 0, client, socklen)) == -1)
            printf("Server failed to receive anything from Client");

        else if(packet_from_client.type == SYN){
            printf("Server successfully received SYN from client, sending SYNACK \n");
            server_state.state = SYN_RCVD;

            // Server to create and send SYNACK
            gbnhdr synack_packet;
            size_t packet_size = gbnhdr_packet_builder(&synack_packet, SYNACK, server_state.seqnum, NULL, 0);

            if((sendto(sockfd, &synack_packet, packet_size, 0, client, *socklen)) == -1){
                printf("Server failed to send SYNACK \n");
            }
            else{
                printf("Server sent SYNACK and considers connection established! \n");
                client_state.state = ESTABLISHED;
                return 0;
            }
        }
    }
	return(-1);
}

/* Called by Server to start sending data to Client */
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){

    // Retrieve Client sockaddr info from state struct
    struct sockaddr* client = server_state.dest_sockaddr_ptr;
    socklen_t socklen = server_state.dest_socklen;

    state_t temp = server_state;
    state_t temp2 = client_state;

    /* Hint: Check the data length field 'len'.
     *       If it is > DATALEN, you will have to split the data
     *       up into multiple packets - you don't have to worry
     *       about getting more than N * DATALEN.
     */

    // !!! ignore buf for now and send Hello world in the packet data
    char testString[100] = "Hello world";
    size_t testStringLen = strlen(testString);

    ssize_t len_sent = sendto(sockfd, testString, testStringLen, 0, client, socklen);
    if (len_sent == -1)
        printf("Server failed to send Hello World\n");
    else
        printf("Server sent Hello World\n");

    // create a data packet
    gbnhdr data_packet;
    size_t packet_size = gbnhdr_packet_builder(&data_packet, DATA, server_state.seqnum, testString, testStringLen);
    //size_t packet_size = gbnhdr_packet_builder(&data_packet, SYN, state.seqnum, buf, 0);

    while(TRUE) {
        continue;
        ssize_t len_sent = sendto(sockfd, &data_packet, packet_size, 0, client, socklen);
        if (len_sent == -1) {
            printf("We failed to send data packet\n");
        }
    }

    // create a place to store DATAACK packet from receiver
    gbnhdr packet_from_receiver;
    gbnhdr_clear_packet(&packet_from_receiver);


    //if(len > DATALEN){
    // implement later!!
    //}

    return(-1);
}


/* Called by Client to start getting data from Server */
ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

    // Retrieve Server sockaddr info from state struct
    struct sockaddr* server = client_state.dest_sockaddr_ptr;
    socklen_t socklen = client_state.dest_socklen;

    // Create a place to store data packet from Server
    gbnhdr packet_from_server;
    gbnhdr_clear_packet(&packet_from_server);

    char echoBuffer[500];
    ssize_t len_recv = recvfrom(sockfd, echoBuffer, 11, 0, server, socklen);
    if(len_recv == -1)
        printf("Client failed to receive anything from Server");
    else
        printf("Client received %s from Server \n",echoBuffer);

    while(TRUE){
        continue;
        /*ssize_t len_recv = recvfrom(sockfd, &packet_from_server, sizeof(gbnhdr), 0, server, socklen);

        if(len_recv == -1)
            printf("Sender did not receive SYNACK!\n");
        else{
            //validate checksum

            printf("Client received %s from Server \n", packet_from_server.data);
        }*/
    }
    return(-1);
}




int gbn_close(int sockfd){

    /* TODO: Your code here. */

    // clear out state structs
    // free packets??
    // stop timers???

    return(-1);
}

/* Helper fx to build packets */
size_t gbnhdr_packet_builder(gbnhdr *packet, uint8_t type, uint8_t seqnum, const void *buf, size_t len){

    if( len > DATALEN)
        return -1;

    gbnhdr_clear_packet(packet);

    packet->type = type;
    packet->seqnum = seqnum;
    packet->checksum = 0;

    if (buf != NULL && len >0){
        memcpy(packet->data, buf, len);
    }

    packet->checksum = checksum((uint16_t *)packet, sizeof(*packet) / sizeof(uint16_t));

    //printf("gbnhdr_build: created packet with checksum %d\n", packet->checksum);

    /* return the length of the packet ??? */
    return sizeof(packet->type) + sizeof(packet->seqnum) + sizeof(packet->checksum) + (sizeof(uint8_t) * len);
}

/* Helper fx for Server to keep track of Client acks */
ssize_t gbnhdr_recv_ack(int sockfd, gbnhdr *packet, int flags) {
    printf("recv_ack:\n");

    gbnhdr_clear_packet(packet);

    // set the signal alarm
    alarm(TIMEOUT);

    // the packet is corrupt
    if (gbnhdr_validate_checksum(packet)) {
        printf("recv_ack: ACK CORRUPT\n");
        return ACKSTATUS_CORRUPT;
    }
}

/* Check if packet is corrupted by comparing given checksum and calculated checksum */
uint8_t gbnhdr_validate_checksum(gbnhdr *packet){

    uint16_t received_checksum = packet->checksum;
    uint16_t calculated_checksum = checksum((uint16_t *)packet, sizeof(*packet) / sizeof(uint16_t));

    if (received_checksum == calculated_checksum){
        printf("validate_packet: success, checksum %d\n", received_checksum);
        return TRUE;
    }
    else{
        printf("***********************************************************\n");
        printf("checksum mismatch, received: %d, calculated: %d\n", received_checksum, calculated_checksum);
        printf("***********************************************************\n");
        return FALSE;
    }
}

/* Use memset to clear packet and make sure we do not access garbage */
void gbnhdr_clear_packet(gbnhdr *packet) {
    memset(packet, 0, sizeof(*packet));
}



void signal_handler(){
    // Do nothing
}

/* Provided by instructor to introduce corruption and packet dropping */
ssize_t maybe_recvfrom(int  s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen){

    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB*RAND_MAX){


        /*----- Receiving the packet -----*/
        int retval = recvfrom(s, buf, len, flags, from, fromlen);

        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB*RAND_MAX){
            /*----- Selecting a random byte inside the packet -----*/
            int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

            /*----- Inverting a bit -----*/
            char c = buf[index];
            if (c & 0x01)
                c &= 0xFE;
            else
                c |= 0x01;
            buf[index] = c;
        }

        return retval;
    }
    /*----- Packet lost -----*/
    return(len);  /* Simulate a success */
}

/* Provided by instructor to calculate a checksum */
uint16_t checksum(uint16_t *buf, int nwords) {
    uint32_t sum;

    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}