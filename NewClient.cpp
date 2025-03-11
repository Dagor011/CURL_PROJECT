#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <arpa/inet.h>
#include <pcap.h>
#include <cstring>
#include <netinet/ip.h>

#define PORT 12345
#define SERVER_IP "172.18.128.1"    //привязка к серверу 
#define BUFFER_SIZE 1024


void packetHandler(u_char * args, const struct pcap_pkthdr *header, const u_char *packet){
int socket = *(int *)args;//дескриптор сокета

struct iphdr *ipHeader = (struct iphdr*)(packet + 14); // ethernet header 14 bites


char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
inet_ntop(AF_INET, &(ipHeader->saddr), src_ip_str , INET_ADDRSTRLEN);
inet_ntop(AF_INET, &(ipHeader->saddr), dst_ip_str , INET_ADDRSTRLEN);

//make  massage

char msg[BUFFER_SIZE];
snprintf(msg, sizeof(msg),
	 "Captured packet: %d bytes\nSource IP: %s\nDestination IP: %s\n",
	header->len,
	inet_ntoa(*(in_addr*)&ipHeader->saddr), //source ip
	inet_ntoa(*(in_addr*)&ipHeader->daddr));//terget ip

//отправка на серв

send(socket, msg, strlen(msg), 0);
}

int main(int argc, char **argv){

int socket_fd = socket(AF_INET, SOCK_STREAM,IPPROTO_TCP);
if(socket_fd < 0){
perror("error creation socket");
return 1;
}

struct sockaddr_in server_addres;
memset(&server_addres, 0, sizeof(server_addres));
server_addres.sin_family = AF_INET;
server_addres.sin_port = htons(PORT);
inet_pton(AF_INET, SERVER_IP , &server_addres.sin_addr);
/*
SockAddr.sin_family = AF_INET;
SockAddr.sin_port = htons(PORT);
inet_pton(AF_INET, SERVER_IP, &SockAddr.sin_addr);

connect(Socket, (struct sockaddr *)(&SockAddr), sizeof(SockAddr));
char Buffer[BUFFER_SIZE];

recv(Socket, Buffer, BUFFER_SIZE, 0);
std::cout<< Buffer;
*/
//connect to server
if (connect(socket_fd, (struct sockaddr *)&server_addres, sizeof(server_addres)) < 0){
perror("connection failed");
close(socket_fd);
return 1;
}

char buffer[BUFFER_SIZE];
ssize_t received_bytes = recv(socket_fd, buffer , BUFFER_SIZE, 0);
if(received_bytes >0)
{
buffer[received_bytes] = '\0';
std::cout<< "received from server:" << buffer << std::endl;
}
else
{
std::cerr << "failed to reciev data from server" << std::endl;
}

//capture pockets

char errbuf[PCAP_ERRBUF_SIZE];
pcap_if_t *allDevs;

if(pcap_findalldevs(&allDevs,errbuf) == -1){
std::cerr << "Error fidning alldevs:" << errbuf << std::endl;
shutdown(socket_fd, SHUT_RDWR);
close(socket_fd);
return 1;
}
std::cout << "Available devices:" << std::endl;
for(pcap_if_t* dev = allDevs; dev  != nullptr; dev = dev->next){
std::cout<< dev->name <<std::endl;
}

pcap_t* handle = pcap_open_live(allDevs->name, BUFSIZ, 1, 1000, errbuf);
if(handle == nullptr){
std::cerr << "Error opening devices"<< errbuf <<std::endl;
pcap_freealldevs(allDevs);
shutdown(socket_fd, SHUT_RDWR);
close(socket_fd);
return 1;
} 

//
pcap_loop(handle, 0, packetHandler, (u_char *)&socket_fd);
//freeing up resources
pcap_close(handle);
pcap_freealldevs(allDevs);
shutdown(socket_fd, SHUT_RDWR);
close(socket_fd);
return 0;
}
