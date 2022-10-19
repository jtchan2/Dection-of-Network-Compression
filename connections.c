#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define PORT 8080
int main (int argc, char *argv[]){
	int socketfd;
	struct sockaddr_in server;

	//creating socket
	socketfd = socket(AF_INET , SOCK_STREAM, 0);
	if(socketfd== -1){
		printf("Could not Create socket");
	}

	//preparing the Sockaddr_in struct
	server.sin_family = AF_INET;


	return 0;
}
