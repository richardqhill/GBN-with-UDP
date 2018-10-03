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
    client_state.window_start = 1; // First packet num is #1 (not #0)
    client_state.window_size = WINDOW_SLOWMODE;
    client_state.recv_ack_timeout_count = 0;

    // Create a SYN packet
    gbnhdr syn_packet;
    gbnhdr_packet_builder(&syn_packet, SYN, 0, 0, NULL);

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

/* Called by Client/Sender to send data to Server 1111 */
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
    printf("gbn_send:\n");

    //Turn off non-blocking mode (i.e. make recvfrom blocking again)
    int flag_control = fcntl(sockfd, F_SETFL, 0);

    uint16_t length_of_last_packet_in_buf = (uint16_t)(len % DATALEN);
    size_t expected_number_of_packets;
    if(length_of_last_packet_in_buf == 0)
        expected_number_of_packets = len / DATALEN;
    else
        expected_number_of_packets = len / DATALEN + 1;

    // Reset client state in case gbn_send has been called previously
    memset(client_state.packet_buf,0,sizeof(client_state.packet_buf));
    client_state.window_start = 1; // First packet num is #1 (not #0)

    // Create every packet needed for this buffer and store into the client state struct
    int builder_offset = 0;
    for(uint16_t i=1; i<=expected_number_of_packets; i++){
        gbnhdr data_packet;

        // Handle case where last packet does not have full payload
        if(i == expected_number_of_packets && length_of_last_packet_in_buf!= 0){
            gbnhdr_packet_builder(&data_packet, DATA, i, length_of_last_packet_in_buf,
                                  buf + builder_offset);
        }
        else{
            gbnhdr_packet_builder(&data_packet, DATA, i, DATALEN,
                                  buf + builder_offset);
            builder_offset += DATALEN;
        }
        client_state.packet_buf[i] = data_packet;
    }

    // Client starts sending data packets to Server
    while(client_state.window_start <= expected_number_of_packets){

        if(client_state.recv_ack_timeout_count >= MAX_NUM_TIMEOUTS){
            return -1;
        }

        // Send variable number of packets based on current Window Size
        //for(int i=0; i<1; i++){                                     //              !!!!!!!!!!!!!!!!!!!!!!!!!!!!
        //for(int i=0; i<client_state.window_size; i++){
        //    gbn_send_data_packet(sockfd, client_state.window_start + i, flags);
        //}

        gbn_send_data_packet(sockfd, client_state.window_start, flags);

        ssize_t return_value = gbn_recv_dataack(sockfd, flags);
        if(return_value == ACKSTATUS_TIMEOUT){
            printf("gbn_send: Client timed out waiting for DATAACK FROM Server\n");
            gbn_set_window_slow();
            client_state.recv_ack_timeout_count++;
            errno = 0;
        }
        else if(return_value == -1){
            printf("gbn_send: gbn_recv_dataack returned -1, not sure why? \n");
        }
        else if (return_value ==0){   // Successfully received a DATAACK (any #)
            client_state.recv_ack_timeout_count = 0;
            continue;
        }
    }

    return 0;
}

/* Helper fx called by Client/Sender to send data to Server */
ssize_t gbn_send_data_packet(int sockfd, uint16_t packet_num, int flags){

    // There can only be 1024 packets per GBN_send. Packet num cannot be above 1024
    // Windows will sometimes cross 1024, but we will just ignore these
    if(packet_num > 1024)
        return 0;

    // Retrieve Server sockaddr info from Client state struct
    struct sockaddr* server = client_state.server_ptr;
    socklen_t socklen = client_state.dest_socklen;

    //state_t temp = client_state;
    //gbnhdr* temp2 = &client_state.packet_buf[packet_num];

    if ((sendto(sockfd, &client_state.packet_buf[packet_num], sizeof(gbnhdr), flags, server, socklen)) == -1) {
        printf("Client failed to send packet# %d\n", packet_num);
        return -1;
    }
    else {
        printf("Client sent packet# %d\n", packet_num);
        return 0;
    }
}

/* Helper fx for Client/Sender to keep track of Server dataacks */
ssize_t gbn_recv_dataack(int sockfd, int flags) {
    printf("recv_dataack:\n");

    //Turn off non-blocking mode (i.e. make recvfrom blocking again)
    int flag_control = fcntl(sockfd, F_SETFL, 0);

    //alarm(TIMEOUT);              !!!!!!!!!!!!!!!!!!!!!!!!!!!!

    // create a place to store DATAACK packet from receiver
    gbnhdr packet_from_server;
    gbnhdr_clear_packet(&packet_from_server);

    ssize_t result = recvfrom(sockfd, &packet_from_server, sizeof(gbnhdr), flags, NULL, NULL);

    // if recvfrom has returned, turn off alarm
    alarm(0);

    if (result == -1){
        if (errno == EINTR){
            printf("gbn_recv_dataack: ACK TIMEOUT\n");
            return ACKSTATUS_TIMEOUT;
        }
        return -1;
    }

    if(gbnhdr_validate_checksum(&packet_from_server) == FALSE)
        return ACKSTATUS_CORRUPT;

    // If Server packet is SYNACK, we have already received one. Drop the packet.
    if(packet_from_server.type == SYNACK) {
        return 0;
    }

    // Update Client window start to Server's next expected packet
    if(packet_from_server.type == DATAACK){

        // First check if we have received an ACK for this packet before
        if(client_state.window_start == packet_from_server.packet_num){
            printf("gbn_send: Client received a DUPLICATE DATACK packet# %d \n", packet_from_server.packet_num);
            gbn_set_window_slow();
        }
        else { // If this is a novel DATAACK, update window start
            // Only update if next expected is higher than window start in case OOO dataack
            // Do not update if number is higher than possible with windowing. Possibly DATAACK from previous buffer
            uint16_t diff = packet_from_server.packet_num - client_state.window_start;
            if(client_state.window_start < packet_from_server.packet_num && diff <= WINDOW_FASTMODE) {
                client_state.window_start = packet_from_server.packet_num;
            }

            printf("gbn_send: Client received DATACK packet# %d \n", packet_from_server.packet_num);
            gbn_increment_window_size();
        }
        return 0;
    }
    return -1;
}

/* Called by Server/Receiver. Initializes server state struct and updates state to Listening */
int gbn_listen(int sockfd, int backlog){

    /* Initialize our Server struct  */
    memset(&server_state,0,sizeof(server_state));
    server_state.state = LISTENING;
    server_state.role = SERVER;
    server_state.next_expected_pack_num = 1; // Set to 0 so that next expected packet num is packet #1

    return(0);
}

/* Called by Server/Receiver to take SYN from Client and return SYNACK  */
int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){
    printf("gbn_accept:\n");

    // Create a place to store packet from Client (Populated by recvfrom)
    gbnhdr packet_from_client;
    gbnhdr_clear_packet(&packet_from_client);

    while(TRUE) {
        if ((recvfrom(sockfd, &packet_from_client, sizeof(gbnhdr), 0, client, socklen)) == -1)
            printf("Server failed to receive anything from Client");

        else if (packet_from_client.type == SYN) {
            printf("Server successfully received SYN\n");
            server_state.state = SYN_RCVD;

            /* Use Server struct to keep track of Client sockaddr/length */
            memcpy(&server_state.client, client, *socklen);
            server_state.client_ptr = (struct sockaddr *) &server_state.client;
            server_state.dest_socklen = *socklen;

            // Server to create and send SYNACK
            gbnhdr synack_packet;
            gbnhdr_packet_builder(&synack_packet, SYNACK, 0, 0, NULL);

            if ((sendto(sockfd, &synack_packet, sizeof(synack_packet), 0, client, *socklen)) == -1) {
                printf("Server failed to send SYNACK \n");
            } else {
                printf("Server sent SYNACK and considers connection established! \n");
                client_state.state = ESTABLISHED;
                return sockfd;
            }
        } else if (packet_from_client.type != SYN) {
            // if packet is not SYN, send RST                                                                                   !!!!!!
            gbnhdr rst_packet;
            gbnhdr_packet_builder(&rst_packet, RST, 0, 0, NULL);
            if ((sendto(sockfd, &rst_packet, sizeof(rst_packet), 0, client, *socklen)) == -1) {
                printf("gbn_accept: Server expecting SYN but received something else. Sent RST \n");
            } else {
                printf("gbn_accept: Server expecting SYN but received something else. Failed to send RST \n");
                client_state.state = ESTABLISHED;
                return sockfd;
            }
        }
    }
    return(-1);
}

/* Called by Server/Receiver to get data from Client
 * This function only parses one packet at a time */
ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){
    printf("gbn_recv:\n");
    if(len < DATALEN)
        return -1; // Cannot fit packet contents into buffer

    // Clear buffer
    memset(buf, 0, len);
    size_t bytes_written_to_buf = 0;

    // If next expected packet is stored in our packet buff, write it to buffer
    if(server_state.packet_buf[server_state.next_expected_pack_num].type == DATA){
        printf("gbn_recv: pulled DATA packet out of OOO buffer \n");

        memcpy(buf, server_state.packet_buf[server_state.next_expected_pack_num].data, len);
        bytes_written_to_buf = server_state.packet_buf[server_state.next_expected_pack_num].data_length_in_bytes;

        server_state.next_expected_pack_num++;
        gbn_send_dataack(sockfd, server_state.next_expected_pack_num, flags);

        return bytes_written_to_buf;
    }

    // Retrieve Server sockaddr info from Client state struct
    struct sockaddr* client = server_state.client_ptr;
    socklen_t socklen = server_state.dest_socklen;


    gbnhdr packet_from_client;
    // Loop until we obtain the next expected packet num.
    // Dropping corrupted packets, and storing OOO Data packets into state buffer
    while(TRUE){
        printf("-------------------------------------------\n");
        printf("gbn_recv: Server waiting to receive packets \n");

        state_t temp_server = server_state;


        gbnhdr_clear_packet(&packet_from_client);
        if((recvfrom(sockfd, &packet_from_client, sizeof(packet_from_client), flags, NULL, NULL)) == -1) {
            printf("Server stopped receiving from Client. Exiting... \n");
            // I think this recvfrom needs a timeout to call close if no packets come in 10 seconds?                      !!!
            return 0;
        }
        else{
            // Drop packets if checksum is not valid (corrupted)
            if(gbnhdr_validate_checksum(&packet_from_client) == FALSE)
                continue;

            // If Server/Receiver's SYNACK was lost, Client will still be sending SYN
            else if (packet_from_client.type == SYN){
                printf("gbn_recv: sending SYNACK \n");

                gbnhdr synack_packet;
                gbnhdr_packet_builder(&synack_packet, SYNACK, 0, 0, NULL);
                if((sendto(sockfd, &synack_packet, sizeof(synack_packet), 0, client, socklen)) == -1){
                    printf("Server failed to send SYNACK \n");
                }
                else{
                    printf("Server sent SYNACK and considers connection established! \n");
                    client_state.state = ESTABLISHED; // Redundant from gbn_accept
                }
            }

            // Do not want to accidentally store FIN packet into state OOO packet buffer
            else if(packet_from_client.type == FIN){
                    break;
                }

            // If Client has started a new call of GBN send, we need to clear the
            else if (packet_from_client.packet_num == 1 && server_state.next_expected_pack_num == 1025) {
                memset(server_state.packet_buf,0,sizeof(server_state.packet_buf));
                server_state.next_expected_pack_num = 1;
                break;
            }

            // Store OOO packets into state struct packet buf
            else if(packet_from_client.packet_num != server_state.next_expected_pack_num){
                memcpy(&server_state.packet_buf[packet_from_client.packet_num],&packet_from_client, sizeof(gbnhdr));

                printf("Sending DATAACK for OOO packet. Expect packet #%d, received packet#%d \n",
                        server_state.next_expected_pack_num, packet_from_client.packet_num);
                gbn_send_dataack(sockfd,server_state.next_expected_pack_num,flags);
            }
            else if (packet_from_client.packet_num == server_state.next_expected_pack_num)
                break;
        }
    }

    // If packet contains Data, write to buf and return
    if (packet_from_client.type == DATA) {
        printf("gbn_recv: received DATA packet\n");

        memcpy(buf, packet_from_client.data, len);
        bytes_written_to_buf = packet_from_client.data_length_in_bytes;

        server_state.next_expected_pack_num++;
        printf("Sending DATAACK for in order packet #%d \n", packet_from_client.packet_num);
        gbn_send_dataack(sockfd,server_state.next_expected_pack_num,flags);

        return bytes_written_to_buf;
    }

    // If FIN packet, send FINACK
    else if (packet_from_client.type == FIN) {
        printf("gbn_recv: received FIN packet \n");
        server_state.state = FIN_RCVD;

        printf("gbn_recv: sending FINACK \n");
        gbnhdr finack_packet;
        gbnhdr_clear_packet(&finack_packet);
        gbnhdr_packet_builder(&finack_packet, FINACK, 0, 0, NULL);

        if ((sendto(sockfd, &finack_packet, sizeof(finack_packet), flags, client, socklen)) == -1) {
            printf("gbn_recv: Server failed to send FINACK packet \n");
            return -1;
        } else {
            printf("gbn_recv: Server sent FINACK packet \n");
            return 0;
        }
    }
    printf("gbn_recv: Error. Did not receive DATA or FIN packet \n");
    return -1;
}

/* Helper fx called by Server/Receiver to send DATAACK to Client */
ssize_t gbn_send_dataack(int sockfd, uint16_t packet_num, int flags){

    return 0; // diagnose issue troubleshoot

    // Retrieve Server sockaddr info from Client state struct
    struct sockaddr* client = server_state.client_ptr;
    socklen_t socklen = server_state.dest_socklen;

    gbnhdr dataack_packet;
    gbnhdr_clear_packet(&dataack_packet);
    gbnhdr_packet_builder(&dataack_packet, DATAACK, packet_num, 0, NULL);

    if ((sendto(sockfd, &dataack_packet, sizeof(gbnhdr), flags, client, socklen)) == -1) {
        printf("Server failed to send dataack for# %d\n", packet_num);
        return -1;
    }
    else
        printf("Server sent dataack for# %d\n",packet_num);
    return -1;
}

/* Called by Client/Sender AND Server/Receiver to close their sockets*/
int gbn_close(int sockfd){
    printf("gbn_close: \n");

    if (server_state.role == SERVER){
        server_state.state = CLOSED;
        return close(sockfd);
    }

    else if(client_state.role == CLIENT){

        int sent_fin_count = 0;
        int max_fin_attempts = 500;

        //Build a Fin Packet
        gbnhdr fin_packet;
        gbnhdr_packet_builder(&fin_packet,FIN,0,0,NULL);

        // Retrieve Server sockaddr info from Client state struct
        struct sockaddr* server = client_state.server_ptr;
        socklen_t socklen = client_state.dest_socklen;

        while(sent_fin_count<max_fin_attempts){

            if ((sendto(sockfd, &fin_packet, sizeof(gbnhdr), 0, server, socklen)) == -1){
                printf("Client failed to send Fin packet\n");
            }
            else {
                printf("Client sent Fin packet \n");
                client_state.state = FIN_SENT;
            }

            sent_fin_count++;

            // Create packet to store Finack
            gbnhdr packet_from_server;
            gbnhdr_clear_packet(&packet_from_server);

            alarm(TIMEOUT);
            recvfrom(sockfd, &packet_from_server, sizeof(gbnhdr),0,NULL,NULL);
            alarm(0);

            if(gbnhdr_validate_checksum(&packet_from_server) && packet_from_server.type == FINACK){
                printf("Client received FINACK from server. Closing! \n");
                client_state.state = CLOSED;
                break;
            }
        }
        return close(sockfd);
    }
}

/* Helper fx to build packets */
uint8_t gbnhdr_packet_builder(gbnhdr *packet, uint8_t type, uint16_t packet_num, uint16_t payload_length, const void *buf) {

    if( payload_length > DATALEN)
        return -1;

    gbnhdr_clear_packet(packet);

    packet->type = type;
    packet->data_length_in_bytes = payload_length;
    packet->packet_num = packet_num;
    packet->checksum = 0; // Need to set this to 0 before calculating checksum so that receiver side can replicate

    if (buf != NULL && payload_length >0){
        memcpy(packet->data, buf, payload_length);
    }

    packet->checksum = checksum((uint16_t *)packet, sizeof(*packet) / sizeof(uint16_t));

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

void gbn_set_window_slow(){
    printf("GBN: Set_window_to slow \n");
    client_state.window_size = WINDOW_SLOWMODE;
}

void gbn_increment_window_size(){
    if(client_state.window_size == WINDOW_SLOWMODE) {
        printf("GBN: Set window_to Mod \n");
        client_state.window_size = WINDOW_MODMODE;
    }
    else if(client_state.window_size == WINDOW_MODMODE) {
        printf("GBN: Set window_to Fast \n");
        client_state.window_size = WINDOW_FASTMODE;
    }
    else if(client_state.window_size == WINDOW_FASTMODE) {
        printf("GBN: Window already at Fast \n");
    }
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

