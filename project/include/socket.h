#include <iostream>
#include <string>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <netinet/in.h>
#include <unistd.h>   //close 
#include <arpa/inet.h>    //close
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros 
#include <errno.h>

class Socket {
    private:
    protected:
        int socketType;
        struct sockaddr_in address;
        int master_fd;
        int port;

    public:
        Socket(int socketType);
        int getMasterFD();
        void makeConnection();
        bool wait(int socket);
        void setBlockingSocket(int socket, bool is_blocking);
        void send_message(int socket, unsigned char* message, unsigned int message_len);
        unsigned int receive_message(int socket, unsigned char *buffer);
};