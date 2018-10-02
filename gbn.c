#include "gbn.h"

state_t client_state;
state_t server_state;

int gbn_socket(int domain, int type, int protocol){
    gbn_init();
    return socket(domain, type, protocol);
}
void gbn_init(){
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

/* Called by Client/Sender to connect to Server/Receiver */
// Does this work if runs receiver first?
int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){
    printf("gbn_connect:\n");

    /* Initialize our Client struct and use to keep track of Server sockaddr/length */
    memset(&client_state,0,sizeof(client_state));
    client_state.state = CLOSED;
    memcpy(&client_state.server, server, socklen);
    client_state.server_ptr = &client_state.server;
    client_state.dest_socklen = socklen;
    client_state.packet_num = 0;
    client_state.window_size = WINDOW_SLOWMODE;

    state_t temp = client_state; // troubleshooting

    // Create a SYN packet
    gbnhdr syn_packet;
    size_t packet_size = gbnhdr_packet_builder(&syn_packet, SYN, 0, 0, NULL, 0);

    // Create a place to store a return packet from Server
    gbnhdr packet_from_server;
    gbnhdr_clear_packet(&packet_from_server);

    // we can update this to try like ~5-10 times
    while(TRUE){
        if((sendto(sockfd, &syn_packet, packet_size, 0, server, socklen)) == -1){
            printf("Client failed to send SYN\n");
        }
        else {
            printf("Client sent SYN, waiting to receive SYNACK from Server \n");
            client_state.state = SYN_SENT;

            if((recvfrom(sockfd, &packet_from_server, sizeof(gbnhdr), 0, server, &socklen)) == -1)
                printf("Client did not receive SYNACK from Server \n");
            else if(packet_from_server.type == SYNACK) {
                printf("Client received SYNACK from Server, considers connection established! \n");
                client_state.state = ESTABLISHED;
                return 0;
            }
        }
    }
    printf("Client failed to connect to Server \n");
    return(-1);
}

/* Called by Client/Sender to start sending data to Server */
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
    printf("gbn_send:\n");

    // Retrieve Server sockaddr info from Client state struct
    struct sockaddr* server = client_state.server_ptr;
    socklen_t socklen = client_state.dest_socklen;


    size_t length_of_last_packet = len % 1024;
    size_t expected_number_of_packets;
    size_t num_acked_packets = 0;
    if(length_of_last_packet == 0)
        expected_number_of_packets = len / 1024;
    else
        expected_number_of_packets = len / 1024 + 1;
    size_t current_offset = 0;
    size_t window_beginning_offset = 0;


    while(num_acked_packets < expected_number_of_packets){

        gbnhdr data_packet;

        /* If we are at the last packet */
        if(client_state.packet_num == expected_number_of_packets && length_of_last_packet!= 0){
            size_t packet_size = gbnhdr_packet_builder(&data_packet, DATA, length_of_last_packet, client_state.packet_num, buf + current_offset, DATALEN);

            if ((sendto(sockfd, &data_packet, sizeof(data_packet), 0, server, socklen)) == -1)
                printf("Client failed to send packet# %d\n",client_state.packet_num);
            else
                printf("Client sent send packet# %d\n",client_state.packet_num);

            client_state.packet_num++;

            // wait for ack?
            // implement later
        }


        // send packets that aren't the last packet
    }


    /*
    // create a data packet
    gbnhdr data_packet;
    char testString[100] = "Hello world";
    size_t testStringLen = strlen(testString);
    size_t packet_size = gbnhdr_packet_builder(&data_packet, DATA, server_state.seqnum, testString, testStringLen);
    //size_t packet_size = gbnhdr_packet_builder(&data_packet, SYN, state.seqnum, buf, 0);


    while(TRUE) {
        if ((sendto(sockfd, &data_packet, sizeof(data_packet), 0, server, socklen)) == -1)
            printf("Client failed to send Hello World\n");
        else
            printf("Client sent Hello World\n");

        //counter++;
        continue;
        //ssize_t len_sent = sendto(sockfd, &data_packet, packet_size, 0, server, socklen);
        //if (len_sent == -1) {
        //    printf("We failed to send data packet\n");
        //}
    }




    //int counter = 0;

    // create a place to store DATAACK packet from receiver
    gbnhdr packet_from_receiver;
    gbnhdr_clear_packet(&packet_from_receiver);


    //if(len > DATALEN){
    // implement later!!
    //}
    */

    return(-1);
}

/* Called by Server/Receiver to take SYN from Client and return SYNACK */
int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){
    printf("gbn_accept:\n");

    /* Initialize our Server struct  */
    memset(&server_state,0,sizeof(server_state));
    server_state.state = CLOSED;
    server_state.packet_num = 0;

    state_t temp = server_state;  // troubleshooting

    // Create a place to store packet from Client (Populated by recvfrom)
    gbnhdr packet_from_client;
    gbnhdr_clear_packet(&packet_from_client);

    // Update to have like 10 attempts, 1 attempt every second...
    while(TRUE){
        if((recvfrom(sockfd, &packet_from_client, sizeof(gbnhdr), 0, client, socklen)) == -1)
            printf("Server failed to receive anything from Client");

        else if(packet_from_client.type == SYN){
            printf("Server successfully received SYN\n");

            /* Use Server struct to keep track of Client sockaddr/length */
            memcpy(&server_state.client, client, *socklen);
            server_state.client_ptr = &server_state.client;
            server_state.dest_socklen = *socklen;

            // Server to create and send SYNACK
            gbnhdr synack_packet;
            size_t packet_size = gbnhdr_packet_builder(&synack_packet, SYNACK, 0, 0, NULL, 0);

            if((sendto(sockfd, &synack_packet, packet_size, 0, client, *socklen)) == -1){
                printf("Server failed to send SYNACK \n");
            }
            else{
                printf("Server sent SYNACK and considers connection established! \n");
                client_state.state = ESTABLISHED;
                return sockfd;
            }
        }
    }
    return(-1);
}



/* Called by Server/Receiver to start getting data from Client */
ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){
    printf("gbn_recv:\n");

    size_t bytes_written_to_buf = 0;

    // Create a place to store data packet from Client
    gbnhdr packet_from_client;

    while(TRUE){

        printf("----------------------------------------\n");
        printf("gbn_recv: receiving DATA \n");

        gbnhdr_clear_packet(&packet_from_client);

        if((recvfrom(sockfd, &packet_from_client, sizeof(packet_from_client), 0, NULL, NULL)) <= 0) {
            return bytes_written_to_buf;
        }
        else{

            // Drop any corrupted packets
            if(gbnhdr_validate_checksum(&packet_from_client))
                continue;

            // Drop any packet that is not the next expected packet num
            if(packet_from_client.packet_num != server_state.packet_num){

            }

            printf("Server failed to recieve anything from Client \n");
        }

        continue;
        /*ssize_t len_recv = recvfrom(sockfd, &packet_from_client, sizeof(gbnhdr), 0, server, socklen);

        if(len_recv == -1)
            printf("Sender did not receive SYNACK!\n");
        else{
            //validate checksum

            printf("Client received %s from Server \n", packet_from_client.data);
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

/* Helper fx to build packets */
size_t gbnhdr_packet_builder(gbnhdr *packet, uint8_t type, uint16_t data_length_in_bits, uint16_t packet_num,
        const void *buf, size_t len){

    if( len > DATALEN)
        return -1;

    gbnhdr_clear_packet(packet);

    packet->type = type;
    packet->checksum = 0;
    packet->data_length_in_bits = data_length_in_bits;
    packet->packet_num = packet_num;

    if (buf != NULL && len >0){
        memcpy(packet->data, buf, len);
    }

    packet->checksum = checksum((uint16_t *)packet, sizeof(*packet) / sizeof(uint16_t));

    return sizeof(packet->type) + sizeof(packet->seqnum) + sizeof(packet->checksum) + (sizeof(uint8_t) * len);
}

/* Helper fx to check if packet is corrupted by comparing given checksum and calculated checksum */
uint8_t gbnhdr_validate_checksum(gbnhdr *packet){

    uint16_t received_checksum = packet->checksum;
    packet->checksum = 0;
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

/* Helper fx to clear packet memory and make sure we do not access garbage */
void gbnhdr_clear_packet(gbnhdr *packet) {
    memset(packet, 0, sizeof(*packet));
}
void signal_handler(){
    // Do nothing
}
void set_window_slow(){
    printf("set_window_slow: window=%d\n", WINDOW_SLOWMODE);
    client_state.window_size = WINDOW_SLOWMODE;
}
void set_window_med(){
    printf("set_window_med: window=%d\n", WINDOW_MODMODE);
    client_state.window_size = WINDOW_MODMODE;
}
void set_window_fast(){
    printf("set_window_fast: window=%d\n", WINDOW_FASTMODE);
    client_state.window_size = WINDOW_FASTMODE;
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