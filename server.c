#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <signal.h>

#define PORT 8080
#define MAXLINE 1024

void catch_alarm (int sig_num){
	printf("15 secons is now over\n");
	
}
int main(){

	int sockfd;
	char buffer[MAXLINE];
	char *hello = "Hello from server";
	struct sockaddr_in serveraddr, clientaddr;
	clock_t t;
	//CREATING UDP SOCKET
	if( (sockfd = socket(AF_INET, SOCK_DGRAM, 0))<0){
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset(&serveraddr, 0, sizeof(serveraddr));
	memset(&clientaddr, 0, sizeof(clientaddr));

	//setting server info
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = inet_addr("192.168.86.248");
	serveraddr.sin_port = htons(PORT);

	if ( bind(sockfd, (const struct sockaddr *)&serveraddr, sizeof(serveraddr)) <0){
		perror("Not able to bind Socket");
		exit(EXIT_FAILURE);
	}

	int len, n;
	len = sizeof(clientaddr);
	printf("Starting TImer\n");
	t = clock();
	n= recvfrom(sockfd, (char *) buffer, MAXLINE, MSG_WAITALL, (struct sockaddr *) &clientaddr, &len);
	t = clock()-t;
	double time_taken = ((double)t)/CLOCKS_PER_SEC;
	printf("time it took to recieve a packet was %f seconds \n", time_taken);
	buffer[n] = '\0';
	printf("Client : %s\n", buffer);
	sendto(sockfd, (const char *)hello, strlen(hello), MSG_CONFIRM, (const struct sockaddr *) &clientaddr, len);
	printf("Hello Message sent.\n");
	double * send_time= &time_taken;
	hello="Now I am 15 seconds late";
	signal(SIGALRM, catch_alarm);
	sleep(15);
	sendto(sockfd, (const char *) hello, strlen(hello), MSG_CONFIRM, (const struct sockaddr *) &clientaddr, len);

	return 0;
}
