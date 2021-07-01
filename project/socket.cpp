#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream> 
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include "include/costants.h"
#include "include/socket.h"

using namespace std;

void send_message(int socket, unsigned int msg_size, unsigned char* message) {
	int ret;

	if ( msg_size > MAX_MESSAGE_SIZE ) {
        cerr << "send:message too big" << endl; 
        return;
    }

	uint32_t size = htonl(msg_size);
	ret = send(socket, &size, sizeof(uint32_t), 0);

	if( ret < 0 ) {
        cerr << "message size send error" << endl;
        exit(1);
    }

	ret = send(socket, message, msg_size, 0);
	if( ret <= 0 ) {
        cerr << "message send error" << endl;
        exit(1);
    }
}

unsigned int receive_message(int socket, unsigned char* message){
	int ret;
	uint32_t networknumber;

	unsigned int received = 0;

	ret = recv(socket, &networknumber, sizeof(uint32_t), 0);
	if( ret < 0 ) {
        cerr << "socket receive error " << strerror(errno) << endl;
        exit(1);
    }

	if( ret > 0 ) {
		unsigned int msg_size = ntohl(networknumber);

		if( msg_size > MAX_MESSAGE_SIZE ) {
            cerr << "receive: message too big" << endl;
            return 0;
        }	

		while( received < msg_size ) {
			ret = recv(socket,  message + received, msg_size - received, 0);	
			if(ret < 0)
            {
                cerr << "message receive error" << endl;
                exit(1);
            }

			received += ret;
		}

	    return msg_size;
	}

	return 0;
}

Socket::Socket(int socketType) {
    this->socketType = socketType;
    port = 8080;

    if ((master_fd = socket(AF_INET, socketType, 0)) < 0)
        throw runtime_error("Socket not created.");
    
    cout << "Socket correctly created" << endl;
    address.sin_family = AF_INET;
    address.sin_port = htons(this->port);
    
    if(inet_pton(AF_INET, LOCALHOST, &this->address.sin_addr) <= 0)
        throw runtime_error("Invalid address/ Address not supported");
}

int Socket::getMasterFD() {
    return master_fd;
}

void Socket::makeConnection() {
    bool is_blocking;
    int flags;
    int ret;
    flags = fcntl(master_fd, F_GETFL, 0);

    if(flags < 0) {
        perror("Connection error");
        throw runtime_error("Connection Failed");
    }

    is_blocking = (flags & O_NONBLOCK) == 0;
    ret = connect(master_fd, (struct sockaddr *)&address, sizeof(address));

    if (ret == -1) {
        if(is_blocking || errno != EINPROGRESS) {
            perror("Connection error");
            throw runtime_error("Connection Failed");
        }

        if(!wait(master_fd)) {
            perror("Connection Error");
            throw runtime_error("Connection Failed");
        }
    }
}

void Socket::setBlockingSocket(int socket, bool is_blocking) {
    int flags;
    flags = fcntl(socket, F_GETFL, 0);

    if(flags < 0) {
        perror("Set non blocking");
        throw runtime_error("Set non blocking socket failed.");
    }

    if ((flags & O_NONBLOCK) && !is_blocking)
        throw runtime_error("Socket was already in non-blocking mode"); 

    if (!(flags & O_NONBLOCK) && is_blocking)
        throw runtime_error("Socket was already in blocking mode");
    
    flags = fcntl(socket, F_SETFL, is_blocking ? flags ^ O_NONBLOCK : flags | O_NONBLOCK);

    if(flags < 0) {
        perror("Set non blocking");
        throw runtime_error("Set non blocking socket failed.");
    }
}

bool Socket::wait(int socket) {
    struct pollfd fds[1];
    int poll_response;

    if(socket < 0){
        throw runtime_error("Socket descriptor not valid.");
    }

    fds[0].fd = socket;
    fds[0].events = POLLIN;

    poll_response = poll(fds, sizeof(fds)/sizeof(struct pollfd), 50);

    if (poll_response <= 0) {
        return false;
    }

    return true;
}

void Socket::send_message(int sd, unsigned char* message, unsigned int message_len) {
    int ret;

    if (message_len > MAX_MESSAGE_SIZE) {
        throw runtime_error("Max message size exceeded in Send");
    }

    do {
        ret = send(sd, message, message_len, 0);
        if(ret == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
            perror("Send Error");
            throw runtime_error("Send failed");
        }   
    } while (ret != message_len);   
}

int SocketClient::receive_message(int sd, unsigned char *buffer) {
    int message_len;

    do {
        message_len = recv(sd, buffer, MAX_MESSAGE_SIZE-1, 0);

        if(message_len == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN))) {
            perror("Receive Error");
            throw runtime_error("Receive failed");
        }  
    } while (message_len < 0);
    
    buffer[message_len] = '\0';
    return message_len;   
}
// ------------------------------------------------------------------------------------

SocketServer::SocketServer(int socketType):SocketClient(socketType) {
    port = 8888;
    for (size_t i = 0; i < MAX_CLIENTS; i++) {
        client_socket[i] = 0;
    }

    address.sin_addr.s_addr = INADDR_ANY;
    serverBind();
    listenForConnections();
}

SocketServer::~SocketServer() {}

void SocketServer::serverBind() {
    if (::bind(master_fd, (struct sockaddr *)&address, sizeof(address)) < 0) 
        throw runtime_error("Error in binding");  
    cout << "Listening on port: " <<  port << endl;  
}

void SocketServer::listenForConnections() {
    if (listen(master_fd, 3) < 0)
        throw runtime_error("Error in listening");
}

void SocketServer::initSet() {
    FD_ZERO(&readfds);  
    FD_SET(master_fd, &readfds);  
    max_sd = master_fd;  
    
    for (int i = 0 ; i < MAX_CLIENTS; i++)  {  
        sd = client_socket[i];  
        if(sd > 0) FD_SET( sd , &readfds);  
        if(sd > max_sd) max_sd = sd;  
    }

    addrlen = sizeof(address);
}

bool SocketServer::isFDSet(int fd) {
    return FD_ISSET(fd, &readfds);
}

int SocketServer::getClient(unsigned int i) {
    if (i > MAX_CLIENTS-1)
        throw runtime_error("Max clients exceeds");
    return client_socket[i];
}

void SocketServer::selectActivity() {
    activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);  
       
    if ((activity < 0) && (errno!=EINTR))
        throw runtime_error("Error in the select function"); 
}

void SocketServer::acceptNewConnection() {
    int new_socket;
    string message;

    try {
        if ((new_socket = accept(master_fd, 
            (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
            perror("accept");  
            throw runtime_error("Failure on accept");
        }  

        cout << "--------------------------------" << endl;
        cout << "New connection incoming" << endl;
        cout << "Socket fd is \t" << new_socket << endl;
        cout << "IP: \t\t" <<  inet_ntoa(address.sin_addr) << endl;
        cout << "Port: \t\t" << ntohs(address.sin_port) << endl;
        cout << "--------------------------------" << endl << endl;
        
        message = "Hi, i'm the server";
        if(send(new_socket, message.c_str(), message.length(), 0) != (ssize_t)message.length())  
            throw runtime_error("Error sending the greeting message"); 

        for (int i = 0; i < MAX_CLIENTS; i++)  {  
            if(client_socket[i] == 0)  {  
                client_socket[i] = new_socket;  
                break;  
            } 
        }  
    } catch(const exception& e) {
        throw;
    }
} 

void SocketServer::readMessageOnOtherSockets() {
    int sd;
    int valread;
    
    for (int i = 0; i < MAX_CLIENTS; i++)  {  
        sd = client_socket[i]; 
        if (FD_ISSET( sd , &readfds)) {  
            valread = read(sd, buffer, 1024);    
            if (valread == 0)  { 
                disconnectHost(sd, i);
            } else {  
                buffer[valread] = '\0';  
                send(sd , buffer , strlen(buffer) , 0 );
            }  
        }  
    }  
}

void SocketServer::disconnectHost(int sd, unsigned int i) {
    getpeername(sd , (struct sockaddr*)&address , (socklen_t*)&addrlen);

    cout << "\n----Host disconnected----" << endl;
    cout << "IP: \t\t" << inet_ntoa(address.sin_addr) << endl;
    cout << "Port: \t\t" << ntohs(address.sin_port) << endl;
    cout << "-------------------------" << endl << endl;

    close(sd);  
    client_socket[i] = 0;
}
