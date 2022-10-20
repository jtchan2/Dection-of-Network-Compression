#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT 8080
#define MAXLINE 1024

int main(){
	int sockfd;
	char buffer[MAXLINE];
	char *hello = "Hellow From client";
	double timeRec;
	struct sockaddr_in serveraddr;

	if( (sockfd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset( &serveraddr, 0 ,sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(PORT);
	serveraddr.sin_addr.s_addr = INADDR_ANY;

	int n, len;

	len = sizeof(serveraddr);
	sendto(sockfd, (const char *)hello, strlen(hello), MSG_CONFIRM, (const struct sockaddr *) &serveraddr, sizeof(serveraddr));

	printf("Hello message sent. \n");

	n = recvfrom(sockfd, (char *) buffer, MAXLINE, MSG_WAITALL, (struct sockaddr *) &serveraddr, &len);

	buffer [n] = '\0';
	printf("Server : %s\n", buffer);
	//n = recvfrom(sockfd, (double *) timeRec, sizeof(timeRec), MSG_WAITALL, (struct sockaddr *) &serveraddr, &len);
	//Can only use strings
	printf("Server : time to send %f\n", timeRec);
	close(sockfd);
	return 0;
}
