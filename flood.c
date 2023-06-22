#include "packets.h"

void *handler(void *vargp){

}

int main() {
    // pthread_t thread_id;

    // for(int i = 0; i < IO_LIMIT; i ++){
    //     pthread_create(&thread_id, NULL, handler, NULL);
    // }

    const char *server_ip = "192.168.1.1";
    uint16_t port = 3360;

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd == -1){
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    // packets
    IP_Header *iphead;
    TCP_Header *tcphead;

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    if(inet_pton(AF_INET, server_ip, &dest_addr.sin_addr) <= 0){
        perror("inet_pton error");
        exit(EXIT_FAILURE);
    }
    
    size_t syn_len = sizeof(IP_Header) + sizeof(TCP_Header);

    fill_SYN(iphead, tcphead, dest_addr.sin_addr.s_addr, dest_addr.sin_port);
    byte *ip_stream = serialize_ip_header(iphead);
    byte *tcp_stream = serialize_tcp_header(tcphead);

    byte *syn = form_packet(ip_stream, tcp_stream);
    update_checksums(syn);

    if(sendto(sd, syn, syn_len, 0, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr_in)) < 0){
        perror("sendto error");
        exit(EXIT_FAILURE);
    }else{
        printf("Sent successfully");
    }
    close(sd);
    return 0;
}
