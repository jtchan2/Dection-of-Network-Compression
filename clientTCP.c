#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#define PORT 8080
#define MAXLINE 1024
#define BACKLOG 10

int main (int agrc, char *argv[]){
	int sockfd;
	struct sockaddr_in serveraddr;
	char buffer[MAXLINE];
	char *msg= "Hello from the CLient Size";
	int len, bytes_sent;


	if((sockfd = socket(AF_INET, SOCK_STREAM, 0))<0){
		perror("failed to create Socket");
		exit(EXIT_FAILURE);
	}
	memset(&serveraddr, 0 , sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = inet_addr("192.168.86.248");
	serveraddr.sin_port = htons(PORT);


	if(connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr) )<0){
		perror("Failed to connect socket");
		exit(EXIT_FAILURE);
	}
	len = strlen(msg);
	bytes_sent = send(sockfd, (char *) msg, len, 0);
	close(sockfd);
	return 0;

}
