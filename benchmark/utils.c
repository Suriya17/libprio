#include "utils.h"


#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include "prio/util.h"
#include "prio/server.h"
#include "prio/client.h"

// #define SERVER0_IP "127.0.0.1"
// #define SERVER1_IP "127.0.0.1"

// #define SERVER0_IP "100.26.135.121"
// #define SERVER1_IP "3.236.209.253"

void error_exit(const char* const msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void bind_and_listen(struct sockaddr_in *addr, int *sockfd, const int port, const int reuse ) {
    *sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (*sockfd == -1)
        error_exit("Socket creation failed");

    if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)))
        error_exit("Sockopt failed");
    if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)))
        error_exit("Sockopt failed");

    bzero((char *) addr, sizeof(addr));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;
    addr->sin_port = htons(port);

    if (bind(*sockfd, (struct sockaddr*)addr, sizeof(struct sockaddr_in)) < 0) {
        // std::cerr << "Failed to bind to port: " << port << std::endl;
        error_exit("Bind to port failed");
    }

    if (listen(*sockfd, 2) < 0)
        error_exit("Listen failed");   
}

int recv_in(const int sockfd, void* const buf, const size_t len) {
    size_t bytes_read = 0;
    int tmp;
    char* bufptr = (char*) buf;
    while (bytes_read < len) {
        tmp = recv(sockfd, bufptr + bytes_read, len - bytes_read, 0);
        if (tmp <= 0) return tmp; else bytes_read += tmp;
    }
    return bytes_read;
}


// Use example: type obj; read_in(sockfd, &obj, sizeof(type))
size_t read_in(const int sockfd, void* buf, const size_t len) {
    size_t bytes_read = 0;
    char* bufptr = (char*) buf;
    while (bytes_read < len)
        bytes_read += recv(sockfd, bufptr + bytes_read, len - bytes_read, 0);
    return bytes_read;
}

size_t send_out(const int sockfd, const void* buf, const size_t len) {
    size_t ret = send(sockfd, buf, len, 0);
    if (ret <= 0) error_exit("Failed to send");
    return ret;
}

int send_int(const int sockfd, const int x) {
    int x_conv = htonl(x);
    const char* data = (const char*) &x_conv;
    return send(sockfd, data, sizeof(int), 0);
}

int recv_int(const int sockfd) {
    int x;
    recv_in(sockfd, &x, sizeof(int));
    x = ntohl(x);
    return x;
}

void recv_char_array(const int sockfd, unsigned char* data, const size_t len){
    // printf("Receiving char array :  ");
    for(size_t i = 0; i < len; i++){
        read_in(sockfd,data+i,sizeof(char));
        // printf("%d",data[i]);
    }
    // printf("\n");
}

void send_char_array(const int sockfd, unsigned char* data, const size_t len){
    // printf("Sending char array :  ");
    for(size_t i = 0; i < len; i++){
        send_out(sockfd,data+i,sizeof(char));
        // printf("%d",data[i]);
    }
    // printf("\n");
}

void send_packet_data(const int sockfd, unsigned char* data, const unsigned int len){
    send_int(sockfd,len);
    send_char_array(sockfd, data, len);
}

void recv_packet_data(const int sockfd, unsigned char** data, unsigned int* len){
    *len = recv_int(sockfd);
    unsigned char *recv_data = (unsigned char *) malloc(*len * sizeof(char));
    recv_char_array(sockfd,recv_data,*len);
    *data = recv_data;
}

// void recv_pk(const int sockfd, PublicKey* pk){
//     char data[CURVE25519_KEY_LEN];

//     for(int i = 0; i < CURVE25519_KEY_LEN; i++){
//         read_in(sockfd,data+i,sizeof(char));
//         printf("%d",data[i]);
//     }
//     PublicKey_import
//     printf("\n");
// }

// void send_pk(const int sockfd, PublicKey pk){
//     char data[CURVE25519_KEY_LEN];

//     PublicKey_export(pk, (unsigned char *)&data, CURVE25519_KEY_LEN);

//     for(int i = 0; i < CURVE25519_KEY_LEN; i++){
//         send_out(sockfd,data+i,sizeof(char));
//         printf("%d",data[i]);
//     }
//     printf("\n");

// }

// Asymmetric: 1 connects to 0, 0 listens to 1.
void server0_listen(int* sockfd, int *newsockfd, const int port, const int reuse ) {
    struct sockaddr_in addr;
    bind_and_listen(&addr, sockfd, port, reuse);

    socklen_t addrlen = sizeof(addr);
    printf( "  Waiting to accept\n");
    *newsockfd = accept(*sockfd, (struct sockaddr*)&addr, &addrlen);
    if (*newsockfd < 0) error_exit("Accept failure");
    printf("  Accepted\n");
}

void server1_connect(int* sockfd, const int port, const int reuse ) {
    *sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*sockfd == -1) error_exit("Socket creation failed");

    if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)))
        error_exit("Sockopt failed");
    if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)))
        error_exit("Sockopt failed");

    struct sockaddr_in addr;
    bzero((char *) &addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, SERVER0_IP, &addr.sin_addr);

    printf("  Trying to connect...\n");
    if (connect(*sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        error_exit("Can't connect to other server");
    printf( "  Connected\n");
}

void send_mp(const int sockfd, mp_int *mp){
    int len = mp_raw_size(mp);
    // printf("mp_int size : %d \n", len);
    char *str = (char *) malloc(len * sizeof(char));
    mp_toraw(mp,str);
    // printf("Sending mp_int : %s \n", str);
    send_int(sockfd,len);
    send_char_array(sockfd,(unsigned char *)str, len);
    free(str);
}

void recv_mp(const int sockfd, mp_int *mp){
    int len = recv_int(sockfd);
    char *str = (char *) malloc(len * sizeof(char));

    recv_char_array(sockfd,(unsigned char *)str, len);
    mp_read_raw(mp,str, len);
    free(str);
}

void send_p1(const int sockfd, PrioPacketVerify1 p1) {
    send_mp(sockfd, &(p1->share_d));
    send_mp(sockfd, &(p1->share_e));
}

void recv_p1(const int sockfd, PrioPacketVerify1 p1){
    recv_mp(sockfd, &(p1->share_d));
    recv_mp(sockfd, &(p1->share_e));
}

void send_p2(const int sockfd, PrioPacketVerify2 p2) {
    send_mp(sockfd, &(p2->share_out));
}

void recv_p2(const int sockfd, PrioPacketVerify2 p2) {
    recv_mp(sockfd, &(p2->share_out));
}

void send_tB(const int sockfd, PrioTotalShare t){
    for(int i = 0; i < t->data_shares->len; i++)
        send_mp(sockfd,&(t->data_shares->data[i]));
}

void recv_tB(const int sockfd, PrioTotalShare t, const int ndata){
    t->idx = PRIO_SERVER_B;
    MPArray_resize(t->data_shares, ndata);

    for(int i = 0; i < ndata; i++){
        recv_mp(sockfd,&(t->data_shares->data[i]));
    }
}