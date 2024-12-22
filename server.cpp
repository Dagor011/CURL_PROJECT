#include <unistd.h>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>

#define PORT 12345
#define BUFFER_SIZE 1024

int main(int argc, char **argv) {
	int MasterSocket = socket(
		AF_INET /* IPv4 */,
		SOCK_STREAM /* TCP */,
		IPPROTO_TCP);

	if(MasterSocket<0){
	perror("Error creating socket");
	}

	//биндим сокет к адресу
	struct sockaddr_in SockAddr; //куда присоединяться
	SockAddr.sin_family = AF_INET;
	SockAddr.sin_port = htons(PORT); //htons - перевод номера порта в сетевой порядок байт
	SockAddr.sin_addr.s_addr = htonl(INADDR_ANY); //0.0.0.0


	if(bind(MasterSocket, (struct sockaddr *)(&SockAddr), sizeof(SockAddr))<0){
	perror("eror binding socket");
	close(MasterSocket);
	return 1;
	}

	// listen(MasterSocket, SOMAXCONN);
	if(listen(MasterSocket, 1) < 0){
	perror("error listening on sock");
	close(MasterSocket);
	return 1;
	}

	std::cout << "wait connect...\n"; 

	//принять соеднений
	int SlaveSocket = accept(MasterSocket, NULL, NULL);

	if(SlaveSocket < 0){
	perror("error accepting connection");
	close(MasterSocket);
	return 1;
	}

	char Buffer[BUFFER_SIZE]; //сюда зачитаются 4 символа из сокета

	strcpy(Buffer, "=> Server connected!\n");
	send(SlaveSocket, Buffer, strlen(Buffer), 0);

	while(true){
	memset(Buffer, 0, BUFFER_SIZE);
	
	size_t receivedBytes = recv(SlaveSocket, Buffer , BUFFER_SIZE - 1, 0);
	if(receivedBytes <= 0){
	break;
	}
	std::cout << "Cleint" << Buffer << std::endl;

	std::cin.getline(Buffer, BUFFER_SIZE);
	send(SlaveSocket, Buffer, strlen(Buffer), 0);
	}

	std::cout << "Client disconected.\n";
	shutdown(SlaveSocket, SHUT_RDWR);
	close(SlaveSocket);
	close(MasterSocket);
	return 0;
}
