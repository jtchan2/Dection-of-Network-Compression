#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define MYPORT "8080"
#define BACKLOG 10


int main (int argc, char *argv[]){
	int sockfd, new_fd;
	int yes = 1;
	struct addrinfo hints, *res;
	struct sockaddr_storage their_addr;
	socklen_t addr_size;

	//sockfd = socket(AF_INET , SOCK_STREAM, 0);

	// for getting check Beej guide section 3.4
	//preparing the Sockaddr_in struct
	//Loading up address structs with get Addrinfo():
	memset(&hints, 0, sizeof hints);
	hints.ai_family= AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	getaddrinfo(NULL, MYPORT, &hints, &res);

	//making a socket
	sockfd = socket(INADDR_ANY, res->ai_socktype, res->ai_protocol);
	if(sockfd==-1){
		printf("Could not Make Socket");
		return 1;
	}

	//bidning socket to port we got from getaddrinfo():
	bind(sockfd, res->ai_addr, res->ai_addrlen);


	//Checking if able to bind correctly
	if(bind==-1){
		printf("Could not bind socket");
		return 2;
	}

	//losing the pesky "address already in use" error
	if(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes)==-1){
		perror("setsockopt");
		return 3;
	}

	listen(sockfd, BACKLOG);

	addr_size = sizeof their_addr;
	new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);
	close(sockfd);
	return 0;
}
