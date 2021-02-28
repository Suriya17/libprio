#include <mprio.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "util.h"
#include "utils.h"

int
verify_full(int nclients)
{
  SECStatus rv = SECSuccess;

  PublicKey pkA = NULL;
  PublicKey pkB = NULL;
  PrivateKey skA = NULL;
  PrivateKey skB = NULL;

  PrioConfig cfg = NULL;
  PrioServer sA = NULL;
  PrioServer sB = NULL;
  // PrioVerifier vA = NULL;
  PrioVerifier* vB = malloc(nclients * sizeof(PrioVerifier));
  PrioPacketVerify1* p1A = malloc(nclients * sizeof(PrioPacketVerify1));
  PrioPacketVerify1* p1B = malloc(nclients * sizeof(PrioPacketVerify1));
  PrioPacketVerify2* p2A = malloc(nclients * sizeof(PrioPacketVerify2));
  PrioPacketVerify2* p2B = malloc(nclients * sizeof(PrioPacketVerify2));
  for (int c = 0; c < nclients; c++) {
    vB[c] = NULL;
    p1A[c] = NULL;
    p1B[c] = NULL;
    p2A[c] = NULL;
    p2B[c] = NULL;
  }
  PrioTotalShare tA = NULL;
  PrioTotalShare tB = NULL;

  unsigned char** for_server_a = NULL;
  unsigned char** for_server_b = NULL;

  const unsigned char* batch_id = (unsigned char*)"prio_batch_2020-02-28";
  const unsigned int batch_id_len = strlen((char*)batch_id);

  unsigned long long* output = NULL;
  bool* data_items = NULL;

  // Initialize NSS random number generator.
  P_CHECKC(Prio_init());

  // Number of different boolean data fields we collect.
  const int ndata = 1;

  // Number of clients to simulate.
  

  P_CHECKA(output = calloc(ndata, sizeof(unsigned long long)));
  P_CHECKA(data_items = calloc(ndata, sizeof(bool)));

  unsigned char* pkA_hex = (unsigned char*)PK_A;
  // unsigned char* skA_hex = SK_A;
  unsigned char* pkB_hex = (unsigned char*)PK_B;
  unsigned char* skB_hex = (unsigned char*)SK_B;

  PublicKey_import_hex(&pkA,pkA_hex,CURVE25519_KEY_LEN_HEX);
  PublicKey_import_hex(&pkB,pkB_hex,CURVE25519_KEY_LEN_HEX);
  PrivateKey_import_hex(&skB,skB_hex,CURVE25519_KEY_LEN_HEX,pkB_hex,CURVE25519_KEY_LEN_HEX);

  // Generate keypairs for server
  // P_CHECKC(Keypair_new(&skB, &pkB));
  
  int sockfd_server, serverfd = 0;
  const int server_port = 9999;
  server1_connect(&sockfd_server, server_port, 1);
  serverfd = sockfd_server;

  // Use the default configuration parameters.
  P_CHECKA(cfg = PrioConfig_new(ndata, pkA, pkB, batch_id, batch_id_len));

  PrioPRGSeed server_secret;
  // P_CHECKC(PrioPRGSeed_randomize(&server_secret));

  recv_char_array(serverfd,(unsigned char *)&server_secret,PRG_SEED_LENGTH);

  // Initialize two server objects. The role of the servers need not
  // be symmetric. In a deployment, we envision that:
  //   * Server A is the main telemetry server that is always online.
  //     Clients send their encrypted data packets to Server A and
  //     Server A stores them.
  //   * Server B only comes online when the two servers want to compute
  //     the final aggregate statistics.
  P_CHECKA(sB = PrioServer_new(cfg, PRIO_SERVER_B, skB, server_secret));

  // Initialize empty verifier objects
  for (int c = 0; c < nclients; c++) {
    P_CHECKA(vB[c] = PrioVerifier_new(sB));
  }

  // Initialize shares of final aggregate statistics
  P_CHECKA(tA = PrioTotalShare_new());
  P_CHECKA(tB = PrioTotalShare_new());

  // Initialize shares of verification packets
  for (int c = 0; c < nclients; c++) {
    P_CHECKA(p1A[c] = PrioPacketVerify1_new());
    P_CHECKA(p1B[c] = PrioPacketVerify1_new());
    P_CHECKA(p2A[c] = PrioPacketVerify2_new());
    P_CHECKA(p2B[c] = PrioPacketVerify2_new());
  }

  // Init pointers
  for_server_b = (unsigned char**) malloc( nclients * sizeof(unsigned char* ) );
  unsigned int* bLen;
  bLen = (unsigned int*) malloc( nclients * sizeof(unsigned int ) );

  // Generate client data packets.
  for (int c = 0; c < nclients; c++) {

    // The client's data submission is an arbitrary boolean vector.

    // I. CLIENT DATA SUBMISSION.
    //
    // Construct the client data packets.
    
    // P_CHECKC(PrioClient_encode(
    //   cfg, data_items, &for_server_a, &aLen, &for_server_b, &bLen));

    recv_packet_data(serverfd,&for_server_b[c],&bLen[c]);
  }

    // printf("Processing input %d\n", c);

    // The Prio servers A and B can come online later (e.g., at the end of
    // each day) to download the encrypted telemetry packets from the
    // telemetry server and run the protocol that computes the aggregate
    // statistics. In this way, the client only needs to send a
    // single message (the pair of encrypted ClientPacketData packets)
    // to a single server (the telemetry-data-collection server).

    // THE CLIENT'S JOB IS DONE. The rest of the processing just takes place
    // between the two servers A and B.

    // II. VALIDATION PROTOCOL. (at servers)
    //
    // The servers now run a short 2-step protocol to check each
    // client's packet:
    //    1) Servers A and B broadcast one message (PrioPacketVerify1)
    //       to each other.
    //    2) Servers A and B broadcast another message (PrioPacketVerify2)
    //       to each other.
    //    3) Servers A and B can both determine whether the client's data
    //       submission is well-formed (in which case they add it to their
    //       running total of aggregate statistics) or ill-formed
    //       (in which case they ignore it).
    // These messages must be sent over an authenticated channel, so
    // that each server is assured that every received message came
    // from its peer.

  pid_t pid = 0;
  int status = 0;

  for (int c = 0; c < nclients; c++) {
    // Set up a Prio verifier object.
    P_CHECKC(PrioVerifier_set_data(vB[c], for_server_b[c], bLen[c]));

    // Both servers produce a packet1. Server A sends p1A to Server B
    // and vice versa.
    P_CHECKC(PrioPacketVerify1_set_data(p1B[c], vB[c]));
  }
  pid = fork();
  if (pid == 0) {
    int sentbytes = 0;
    for (int c = 0; c < nclients; c++) {
      sentbytes += send_p1(serverfd, p1B[c]);
    }
    printf("send_p1 bytes: %d\n", sentbytes);
    goto cleanup;
  }
  for(int c = 0; c < nclients; c++) {
    recv_p1(serverfd, p1A[c]);

    // Both servers produce a packet2. Server A sends p2A to Server B
    // and vice versa.
    P_CHECKC(PrioPacketVerify2_set_data(p2B[c], vB[c], p1A[c], p1B[c]));
  }
  waitpid(pid, &status, 0);
  pid = fork();
  if (pid == 0) {
    int sentbytes = 0;
    for(int c = 0; c < nclients; c++) {
      sentbytes += send_p2(serverfd, p2B[c]);
    }
    printf("send_p2 bytes: %d\n", sentbytes);
    goto cleanup;
  }
  for (int c = 0; c < nclients; c++) {
    recv_p2(serverfd, p2A[c]);

    // Using p2A and p2B, the servers can determine whether the request
    // is valid. (In fact, only Server A needs to perform this
    // check, since Server A can just tell Server B whether the check
    // succeeded or failed.)
    P_CHECKC(PrioVerifier_isValid(vB[c], p2A[c], p2B[c]));

    // If we get here, the client packet is valid, so add it to the aggregate
    // statistic counter for both servers.
    P_CHECKC(PrioServer_aggregate(sB, vB[c]));

    // free(for_server_a);
    free(for_server_b[c]);
    // for_server_a = NULL;
    // for_server_b = NULL;

    // The servers repeat the steps above for each client submission.

    // III. PRODUCTION OF AGGREGATE STATISTICS.
    //
    // After collecting aggregates from MANY clients, the servers can compute
    // their shares of the aggregate statistics.
    //
    // Server B can send tB to Server A.


    // Once Server A has tA and tB, it can learn the aggregate statistics
    // in the clear.
    // P_CHECKC(PrioTotalShare_final(cfg, output, tA, tB));

    // Now the output[i] contains a counter that indicates how many clients
    // submitted TRUE for data value i.  We print out this data.
    // for (int i = 0; i < ndata; i++)
    //   printf("output[%d] = %llu\n", i, output[i]);
  }

  P_CHECKC(PrioTotalShare_set_data(tB, sB));

  waitpid(pid, &status, 0);

  int sentbytes = send_tB(serverfd, tB);
  printf("Sent tB in %d bytes\n", sentbytes);

cleanup:
  if (rv != SECSuccess) {
    fprintf(stderr, "Warning: unexpected failure.\n");
  }

  if (for_server_a)
    free(for_server_a);
  if (for_server_b)
    free(for_server_b);
  if (output)
    free(output);
  if (data_items)
    free(data_items);

  PrioTotalShare_clear(tA);
  PrioTotalShare_clear(tB);

  for (int c = 0; c < nclients; c++) {
    PrioPacketVerify2_clear(p2A[c]);
    PrioPacketVerify2_clear(p2B[c]);
    PrioPacketVerify1_clear(p1A[c]);
    PrioPacketVerify1_clear(p1B[c]);
    PrioVerifier_clear(vB[c]);
  }
  free(p2A);
  free(p2B);
  free(p1A);
  free(p1B);
  free(vB);

  // PrioVerifier_clear(vA);
  // PrioVerifier_clear(vB);

  PrioServer_clear(sA);
  PrioServer_clear(sB);
  PrioConfig_clear(cfg);

  PublicKey_clear(pkA);
  PublicKey_clear(pkB);

  PrivateKey_clear(skA);
  PrivateKey_clear(skB);

  Prio_clear();

  return !(rv == SECSuccess);
}

int
main(int argc, char** argv)
{
  if(argc != 2)
    return -1;
  puts("This utility demonstrates how to invoke the Prio API.");
  int nclients = atoi(argv[1]);
  return verify_full(nclients);
}
