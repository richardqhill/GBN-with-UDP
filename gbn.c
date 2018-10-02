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
    return bind(sockfd, server, socklen);
}

/* Called by Client/Sender to connect to Server/Receiver */
int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){
    printf("gbn_connect:\n");

    // Set sockfd to be non-block, recvfrom will not block the thread
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    uint8_t attempts_to_connect = 1;
    uint8_t max_attempts_to_connect = 20;

    /* Initialize our Client struct and use to keep track of Server sockaddr/length */
    memset(&client_state,0,sizeof(client_state));
    client_state.state = CLOSED;
    client_state.role = CLIENT;
    memcpy(&client_state.server, server, socklen);
    client_state.server_ptr = &client_state.server;
    client_state.dest_socklen = socklen;
    client_state.packet_num = 0;
    client_state.window_size = WINDOW_SLOWMODE;

    // Create a SYN packet
    gbnhdr syn_packet;
    gbnhdr_packet_builder(&syn_packet, SYN, 0, 0, NULL, 0);

    // Create a place to store a return packet from Server
    gbnhdr packet_from_server;
    gbnhdr_clear_packet(&packet_from_server);

    while(attempts_to_connect <= max_attempts_to_connect){
        if((sendto(sockfd, &syn_packet, sizeof(syn_packet), 0, server, socklen)) == -1){
            printf("Client failed to send SYN\n");
        }
        else {
            printf("Client sent SYN, waiting to receive SYNACK from Server \n");
            client_state.state = SYN_SENT;

            if((recvfrom(sockfd, &packet_from_server, sizeof(packet_from_server), 0, server, &socklen)) == -1)
                printf("Client did not receive SYNACK from Server \n");
            else if(packet_from_server.type == SYNACK) {
                printf("Client received SYNACK from Server, considers connection established! \n");
                client_state.state = ESTABLISHED;
                return 0;
            }
        }
        attempts_to_connect++;
        sleep(1); // Wait one second
    }
    printf("Client failed to connect to Server after %d attempts \n",attempts_to_connect);
    return(-1);
}

/* Called by Client/Sender to send data to Server */
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
    printf("gbn_send:\n");

    // Retrieve Server sockaddr info from Client state struct
    struct sockaddr* server = client_state.server_ptr;
    socklen_t socklen = client_state.dest_socklen;

    // Set sockfd to be non-block, recvfrom will not block the thread
    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    client_state.packet_num = 0;
    size_t length_of_last_packet = len % DATALEN;
    size_t expected_number_of_packets;
    size_t num_acked_packets = 0;
    if(length_of_last_packet == 0)
        expected_number_of_packets = len / DATALEN;
    else
        expected_number_of_packets = len / DATALEN + 1;
    size_t current_offset = 0;
    size_t window_beginning_offset = 0;


    while(num_acked_packets < expected_number_of_packets){

        gbnhdr data_packet;
        uint16_t current_packet_num = client_state.packet_num + 1;

        /* If we are at the last packet */
        if(current_packet_num == expected_number_of_packets && length_of_last_packet!= 0){
            gbnhdr_packet_builder(&data_packet, DATA, current_packet_num, length_of_last_packet,
                    buf + current_offset, DATALEN);

            if ((sendto(sockfd, &data_packet, sizeof(data_packet), flags, server, socklen)) == -1) {
                printf("Client failed to send packet# %d\n", current_packet_num);
                return -1;
            }
            else
                printf("Client sent packet# %d\n",current_packet_num);

            client_state.packet_num++;

            // wait for ack?
            // implement later
        }

        // send packets that aren't the last packet!

    }


    /*

    // create a place to store DATAACK packet from receiver
    gbnhdr packet_from_receiver;
    gbnhdr_clear_packet(&packet_from_receiver);

    */

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



/* Called by Server/Receiver. Initializes server state struct and updates state to Listening */
int gbn_listen(int sockfd, int backlog){

    /* Initialize our Server struct  */
    memset(&server_state,0,sizeof(server_state));
    server_state.state = LISTENING;
    server_state.role = SERVER;
    server_state.packet_num = 0; // Set to 0 so that next expected packet num is packet #1

    return(0);
}

/* Called by Server/Receiver to take SYN from Client and return SYNACK */
int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){
    printf("gbn_accept:\n");

    // Create a place to store packet from Client (Populated by recvfrom)
    gbnhdr packet_from_client;
    gbnhdr_clear_packet(&packet_from_client);

    // Update to have like 10 attempts, 1 attempt every second...
    while(TRUE){
        if((recvfrom(sockfd, &packet_from_client, sizeof(gbnhdr), 0, client, socklen)) == -1)
            printf("Server failed to receive anything from Client");

        else if(packet_from_client.type == SYN){
            printf("Server successfully received SYN\n");
            server_state.state = SYN_RCVD;

            /* Use Server struct to keep track of Client sockaddr/length */
            memcpy(&server_state.client, client, *socklen);
            server_state.client_ptr = (struct sockaddr*) &server_state.client;
            server_state.dest_socklen = *socklen;

            // Server to create and send SYNACK
            gbnhdr synack_packet;
            gbnhdr_packet_builder(&synack_packet, SYNACK, 0, 0, NULL, 0);

            if((sendto(sockfd, &synack_packet, sizeof(synack_packet), 0, client, *socklen)) == -1){
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

/* Called by Server/Receiver to get data from Client */
ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){
    printf("gbn_recv:\n");
    if(len < DATALEN)
        return -1; // Cannot fit packet contents into buffer

     // Clear buffer
     memset(buf, 0, len);

    // when does server_state packnum get set back to 0? How do I know when we're on a new gbn_send
    // well, we know what the max packnum for one window is 1024, so packnum should wrap around
    // could be mod or more explicit logic


    size_t bytes_written_to_buf = 0;
    uint16_t next_expected_packet_num;

    // Retrieve Client sockaddr from Server state struct so that we can send Acks
    struct sockaddr* client = server_state.client_ptr;
    socklen_t socklen = server_state.dest_socklen;

    // Create a place to store packets received from Client
    gbnhdr packet_from_client;
    gbnhdr ack_packet;

    // Loop until we obtain a valid packet with the next expected packet num
    while(TRUE){
        printf("-------------------------------------------\n");
        printf("gbn_recv: Server waiting to receive packets \n");

        gbnhdr_clear_packet(&packet_from_client);

        if((recvfrom(sockfd, &packet_from_client, sizeof(packet_from_client), flags, NULL, NULL)) == -1) {
            printf("Server stopped receiving from Client. Exiting... \n");
            // I think this recvfrom needs a timeout to call close if no packets come in 10 seconds?
            return 0;
        }
        else{
            // Drop corrupted packets
            if(gbnhdr_validate_checksum(&packet_from_client) == FALSE)
                continue;

            // Drop packets if not next expected packet num. Send ack for next expected packet num

            // !!!!!!!
            // To Do: think if we want to store OOO packets into the state struct
            // !!!!!!!
            next_expected_packet_num = (uint16_t) (server_state.packet_num + 1);
            if(packet_from_client.packet_num != next_expected_packet_num){
                gbnhdr_packet_builder(&ack_packet, DATAACK, next_expected_packet_num, 0, NULL, 0);
                if((sendto(sockfd, &ack_packet, sizeof(ack_packet), flags, client, socklen)) == -1) {
                    printf("Server failed to send ACK for OOO packet \n");
                    return -1;
                }
                else {
                    printf("Server sent ACK for OOO packet. Expecting packet #%d \n", server_state.packet_num);
                    continue;
                }
            }
            else if (packet_from_client.packet_num == next_expected_packet_num)
                break;
        }
    }

    // If packet contains Data, write to buf and return
    if (packet_from_client.type == DATA) {
        printf("gbn_recv: received DATA packet\n");

        memcpy(buf, packet_from_client.data, len);

        bytes_written_to_buf = packet_from_client.data_length_in_bytes;

        server_state.packet_num++; // when does this get set back to 0? How do I know when we're on a new gbn_send
        next_expected_packet_num = (uint16_t) (server_state.packet_num + 1);

        printf("gbn_recv: sending DATAACK for next expected packet num \n");
        gbnhdr_packet_builder(&ack_packet, DATAACK, next_expected_packet_num, 0, NULL, 0);
        if ((sendto(sockfd, &ack_packet, sizeof(ack_packet), 0, client, socklen)) == -1) {
            printf("Server failed to send ACK for successful packet \n");
            return -1;
        }
        else {
            printf("Server sent ACK for successful packet. Next expected packet #%d \n", next_expected_packet_num);
            return bytes_written_to_buf;
        }
    }
    // If packet contains FIN, send FINACK
    // I should not increment packet num in case FINACK gets lost
    else if (packet_from_client.type == FIN) {
        printf("gbn_recv: received FIN packet \n");
        server_state.state = FIN_RCVD;

        printf("gbn_recv: sending FINACK \n");
        gbnhdr_packet_builder(&ack_packet, FINACK, 0, 0, NULL, 0);
        if ((sendto(sockfd, &ack_packet, sizeof(ack_packet), 0, client, socklen)) == -1) {
            printf("Server failed to send FINACK packet \n");
            return -1;
        } else {
            printf("Server sent FINACK packet \n");
            return 0;
        }
    }
    printf("gbn_recv: Error. Did not receive DATA or FIN packet \n");
    return -1;
}

/* Called by Client/Sender AND Server/Receiver to close their sockets*/
int gbn_close(int sockfd){
    printf("gbn_close: \n");



    /* TODO: Your code here. */
    // clear out state structs
    // free packets??
    // stop timers???

    if (server_state.role == SERVER){
        server_state.state = CLOSED;
        return close(sockfd);
    }
    else if(client_state.role == CLIENT){

        int sent_fin_count = 0;

        // To Do: attempt to send fin and receive finack
        client_state.state = FIN_SENT;

        // do some stuff

        client_state.state = CLOSED;

        return close(sockfd);
    }
}


/* Helper fx to build packets */
uint8_t gbnhdr_packet_builder(gbnhdr *packet, uint8_t type, uint16_t packet_num, uint16_t data_len, const void *buf,
                             size_t buffer_len) {

    if( buffer_len > DATALEN)
        return -1;

    gbnhdr_clear_packet(packet);

    packet->type = type;
    packet->data_length_in_bytes = data_len;
    packet->packet_num = packet_num;
    packet->checksum = 0; // Need to set this to 0 before calculating checksum so that receiver side can replicate

    if (buf != NULL && buffer_len >0){
        memcpy(packet->data, buf, buffer_len);
    }

    packet->checksum = checksum((uint16_t *)packet, sizeof(*packet) / sizeof(uint16_t));

    // don't think my size of is currently correct
    return 0;
}

/* Helper fx to Receiver check for packet corruption by comparing given checksum and calculated checksum */
uint8_t gbnhdr_validate_checksum(gbnhdr *packet){

    // Store received checksum into a temp and set packet's checksum to 0 to recreate the conditions where
    // Sender/Client initially calculated the checksum
    uint16_t received_checksum = packet->checksum;
    packet->checksum = 0;
    uint16_t calculated_checksum = checksum((uint16_t *)packet, sizeof(*packet) / sizeof(uint16_t));

    if (received_checksum == calculated_checksum){
        printf("validate_packet: success, checksum %d\n", received_checksum);
        return TRUE;
    }
    else{
        printf("***********************************************************\n");
        printf("Checksum mismatch, received: %d, calculated: %d\n", received_checksum, calculated_checksum);
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