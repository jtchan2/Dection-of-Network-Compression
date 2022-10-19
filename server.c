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
	char *hello = "Hello from server";
	struct sockaddr_in serveraddr, clientaddr;

	//CREATING UDP SOCKET
	if( (sockfd = socket(AF_INET, SOCK_DGRAM, 0))<0){
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset(&serveraddr, 0, sizeof(serveraddr));
	memset(&clientaddr, 0, sizeof(clientaddr));

	//setting server info
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = INADDR_ANY;
	serveraddr.sin_port = htons(PORT);

	if ( bind(sockfd, (const struct sockaddr *)&serveraddr, sizeof(serveraddr)) <0){
		perror("Not able to bind Socket");
		exit(EXIT_FAILURE);
	}

	int len, n;
	len = sizeof(clientaddr);

	n= recvfrom(sockfd, (char *) buffer, MAXLINE, MSG_WAITALL, (struct sockaddr *) &clientaddr, &len);

	buffer[n] = '\0';
	printf("Client : %s\n", buffer);
	sendto(sockfd, (const char *)hello, strlen(hello), MSG_CONFIRM, (const struct sockaddr *) &clientaddr, len);
	printf("Hello Message sent.\n");

	
	return 0;
}
