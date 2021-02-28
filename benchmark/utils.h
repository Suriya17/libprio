#define SERVER0_IP "127.0.0.1"
#define SERVER1_IP "127.0.0.1"

// #define SERVER0_IP "3.238.241.6"
// #define SERVER1_IP "3.234.221.79"

#include <mprio.h>
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>

#include "util.h"

#define PK_A "3F85E74B50C6C92C23D18EC937879D4E6F9CD533D1F9B754B8909D0666546B5F"
#define SK_A "7E3FD0F47C9FBEC48237D56755E859D4C40C834D168D7850AAF4F8DFE1A4A5DD"
#define PK_B "1D2834EDEE0FDCD50E874297DE7304259C20095B88A80B099C419215CFBF1C2D"
#define SK_B "5573D8579DD0096247A92E2240305E27895276CD3EBD8094F192059016517589"


void bind_and_listen(struct sockaddr_in *addr, int *sockfd, const int port, const int reuse);
void server0_listen(int* sockfd, int  *newsockfd, const int port, const int reuse);
void server1_connect(int* sockfd, const int port, const int reuse);

int recv_in(const int sockfd, void* const buf, const size_t len);
int recv_char_array(const int sockfd, unsigned char* data, const size_t len);
int send_char_array(const int sockfd, unsigned char* data, const size_t len);
size_t read_in(const int sockfd, void* buf, const size_t len);
size_t send_out(const int sockfd, const void* buf, const size_t len);
int send_packet_data(const int sockfd, unsigned char* data, const unsigned int len);
int recv_packet_data(const int sockfd, unsigned char** data, unsigned int* len);
int send_mp(const int sockfd, mp_int *mp);
int recv_mp(const int sockfd, mp_int *mp);

int send_p1(const int sockfd, PrioPacketVerify1 p1);
int recv_p1(const int sockfd, PrioPacketVerify1 p1);

int send_p2(const int sockfd, PrioPacketVerify2 p2);
int recv_p2(const int sockfd, PrioPacketVerify2 p2);

int send_tB(const int sockfd, PrioTotalShare t);
int recv_tB(const int sockfd, PrioTotalShare t, const int ndata);
// int send_int(const int sockfd, const int x);
// int recv_int(const int sockfd, int& x);
