#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "cJSON.h"

typedef struct
{
	char server_ip[100];
	char client_ip[100];
	int sourceUDP_port;
	int destinationUDP_port;
	int port_sinHead;
	int port_sinTail;
	int port_TCP;
	int payload_size;
	int measure_time;
	int num_of_paks;
	int timeTL;
}instructions;

instructions cJSON_make_struct( char * file, instructions settings){
	cJSON *json, *item, *object;
	json = cJSON_Parse(file);
	//add error catchers later
	//TODO MAKE item stuff go into settings
	item = cJSON_GetObjectItemCaseSensitive(json, "server_ip_address");
	//printf("getobejct got : %s\n", item->string);
	strcpy(settings.server_ip, item->valuestring);

	item =cJSON_GetObjectItemCaseSensitive(json, "client_ip_address");
	strcpy(settings.client_ip, item->valuestring);

	item = cJSON_GetObjectItemCaseSensitive(json, "sourceport_UDP");
	//printf("getobject got string %s, int value %d\n", item->string, item->valueint);
	settings.sourceUDP_port=item->valueint;

	item = cJSON_GetObjectItemCaseSensitive(json, "destinationport_UDP");
	//printf("the %s is %d\n", item->string, item->valueint);
	settings.destinationUDP_port=item->valueint;

	item = cJSON_GetObjectItemCaseSensitive(json, "TCP_Head_Syn");
	settings.port_sinHead= item->valueint;

	item = cJSON_GetObjectItemCaseSensitive(json, "TCP_Tail_Syn");
	settings.port_sinTail= item->valueint;

	item = cJSON_GetObjectItemCaseSensitive(json, "port_TCP");
	//printf("the %s is %d\n", item->string, item->valueint);
	settings.port_TCP= item->valueint;

	item = cJSON_GetObjectItemCaseSensitive(json, "payload_sizeUDP");
	//printf("the %s is %d\n", item->string, item->valueint);
	settings.payload_size= item->valueint;
	if(item== NULL){
		settings.payload_size = 1000;
        }



	item = cJSON_GetObjectItemCaseSensitive(json, "measure_time");
	//printf("the %s is %d\n", item->string, item->valueint);
	settings.measure_time= item->valueint;
	if(item== NULL){
		settings.measure_time= 15;
        }


	item = cJSON_GetObjectItemCaseSensitive(json, "number_of_packets");
	//printf("the %s is %d\n", item->string, item->valueint);
	settings.num_of_paks= item->valueint;
	if(item== NULL){
		settings.num_of_paks= 6000;
	}


	item= cJSON_GetObjectItemCaseSensitive(json, "ttl");
	settings.timeTL= item->valueint;
	if(item == NULL){
		settings.timeTL= 255;
	}
	cJSON_Delete(json);

	return settings;
}

size_t get_file_size(const char *filepath){
	if(filepath == NULL){
		return 0;
	}
	struct stat filestat;
	memset(&filestat, 0, sizeof(struct stat));

	if(stat(filepath, &filestat) == 0){
		return filestat.st_size;
	}else{
		return 0;
	}
}


instructions  read_file(char *filename){
	FILE *fp;
	instructions config;
	/*get file size*/
	size_t size = get_file_size(filename);
	if(size==0){
		printf("failed to get file size\n");
	}

	char * bufr = malloc(size+1);
	if(bufr == NULL){
		printf("Malloc failed\n");
	}

	memset(bufr, 0, size+1);
	fp=fopen(filename, "rb");

	fread(bufr, 1, size, fp);

	fclose(fp);

	config = cJSON_make_struct(bufr, config);
	free(bufr);

	return config;

	printf("reading file complete\n");
}

int main(int argc, char *argv[]){
	printf("Getting Config information\n");
	instructions config = read_file(argv[1]);

	char * serverip= config.server_ip;
	char * clientip= config.client_ip;
	int udp_source_port= config.sourceUDP_port;
	int udp_dest_port= config.destinationUDP_port;
	int tcp_sinHead= config.port_sinHead;
	int tcp_sinTail= config.port_sinTail;
	//TCP reg might not needed
	int tcp_regPort= config.port_TCP;
	int payload= config.payload_size;
	int inter_measure_time= config.measure_time;
	int number_of_packets= config.num_of_paks;
	int timeToLive= config.timeTL;
}
