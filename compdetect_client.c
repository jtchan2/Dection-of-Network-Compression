#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>

#define MAXLINE 1024

int main (int argc, char * argv[]){

	int sock_UDP,port;
	char *ip;
	char buffer[MAXLINE];
	struct sockaddr_in serveraddr;

	ip="192.168.86.248";
	port= 8080;
	memset( &serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(port);
	serveraddr.sin_addr.s_addr = inet_addr(ip);

}
