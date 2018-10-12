## Networks and Distributed Systems: Go-Back-N Assignment
Richard Hill (rqh2) & Charles Kuang (ck742)

## IMPORTANT NOTES
**We edited the Makefile to have the CFLAG set to -gnu99 to avoid errors when testing in Linux**

### Overview
Our goal with this lab was to create a GBN protocol that ensures reliable transmission of data using the UDP methods: `socket()`, `sendto()`, `maybe_recvfrom()`, `close()`, `bind()`.

Our GBN protocol specifies a window of N outstanding packets waiting for acknowledgment. Our client/sender supports three modes: go-back-1, go-back-2, and go-back-4. Each mode corresponds to the number of possible packets outstanding, so go-back-1 allows for one packet, go-back-2 for two, and go-back-4 for four. The client will adjust the mode according to the traffic and packet loss on the network.   

### GBN Method Implementations
###### `gbn_socket()`
Used on both the **client** and **server** to establish a socket.

###### `gbn_bind()`
Used by the **server** to bind a particular socket to a port.

###### `gbn_listen()`
Used to listen for activity on the **server** side.

###### `gbn_connect()`
Used by the **client** to initiate a connection by transmitting a SYN packet and waiting for an SYNACK packet. Our method tries a fixed number of times to send a SYN packet. Once a SYNACK is received, the state is set to established and the **client** proceeds to the `gbn_send()` method. If it does not receive a SYNACK after a certain period of time, it will give up. If the **client** receives an RST packet from the **server**, it closes the connection.

###### `gbn_accept()`
Used by the **server** to listen for a SYN packet and transmit a SYNACK packet. Upon sending a SYNACK, the connection is established on the server end. It will then proceed to the `gbn_recv` method and begin to accept DATA packets. If the first message the **server** receives from the **client** is not a SYN packet, it will respond with an RST packet.

###### `gbn_send()`
* Used by the **client** to create and send DATA packets and receive DATAACK packets.
If we receive a SYNACK, we should just drop the SYNACK packet because the connection is already established.
* We created two helper functions, `send_data_packet()` and `receive_dataack()` that handles the logic for sending and receiving DATAACK packets. The `send_data_packet()` method takes in packet number and uses the number to send the correct one from our storage. The `receive_dataack()` method is recursively called to listen in for DATAACK packets. The function returns when we have received any DATAACK that causes us to slide our window or we timeout.

###### `gbn_recv()`
* Used on the **server** to receive DATA packets and generate DATAACK packets accordingly. Whenever we receive an in-order DATA packet, we write directly to our buffer. If we receive a higher than expected packet number, we store it in our state struct.

* In addition, this method starts off listening for SYN packets just in case the SYNACK packet it sent was lost.

* If we receive a FIN packet, we will respond with a FINACK, update the state, and move to the `gbn_close()` method to close the socket.

###### `gbn_close()`
Used by both the **client** and the **server**, but behaves differently according to who is calling it. For the client, it creates FIN packets and receives FINACK packets. Once a FINACK is received, the client will close its socket. For the server, it immediately closes the socket.

### Challenges & Decisions
###### ADDRESSING
For both the server and client, we stored the sockaddr of the other party(destination) in the state.

###### PACKET STORAGE
On both server and client side, we had to decide on how to store packets to be sent and packets received.
* On the client side, we took the buffer and generated all the packets and stored these packets in the client's state.
* For the server, we created an array of size 1024 that we write any valid incoming packets to. We acknowledge that our solution is not the most memory efficient. Given more time, we would create the packets as needed on the client and implement a smaller sized container to store packets on the server.

###### SEQNUM
We struggled to reconcile reading through the buffer bytestream and having a pointer store the appropriate sequence number, so we assigned an ID to each packet. Instead of transmitting seqNum, we transmitted the ID to identify each packet. (i.e. if the data is 3584 bytes long there would be four packets generated: (0-1024), (1024, 2048), (2048, 3072), (3072, 3584)). Each packet is assigned a packet number: 1, 2, 3, 4.

###### TIMEOUT
For our implementation, duplicate ACKs don't reset the timer, we simply allow the method to proceed. Only when the timer runs out does the window size decrease.

###### ACKS
We chose to drop out of order packets on the server end and not send ACKs. (i.e. if the server receives packet 4 and is expecting packet 5, we disregard the packet)

###### CHECKSUM
We realized the checksum of a packet has to calculated with the checksum set to 0. and subsequently appended to the packet. Upon receipt of a data packet, the checksum is extracted and stored in a variable and set to zero. The checksum of the data packet(without the checksum) is compared to the stored checksum variable.

###### BUFFER FRINGE CASES
* We fixed a bug where the buffer the client was sending was out of sync with the buffer the server expected on the server end. That is, the server had already moved on to begin accepting for the next buffer, while the client was still sending the last packet from the previous buffer. We solved it by checking for a DATAACK for packet 1025, which exceeds the range of possible packets.
* We fixed another bug where the last packet in the last buffer such that if the window size was larger than 1 it would send invalid empty packets to the server.
