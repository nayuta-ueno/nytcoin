#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>

#include "user_config.h"
#include "bc_misc.h"
#include "bc_proto.h"

#define LOG_TAG     "net"
#include "utl_log.h"

#include "bc_network.h"


#if !defined(MAINNET) && !defined(TESTNET)
    #error need MAINNET or TESTNET
#endif


/**************************************************************************
 * static variables
 **************************************************************************/

static bc_protoval_t    mProtoVal;

static volatile bool mLoopRead;


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool connect_sub(int *pSock, const char *pAddr, const char *pService);
static void *read_proc(void *pArg);


/**************************************************************************
 * const variables
 **************************************************************************/

#if defined(MAINNET)
static const char SERVICE[] = "8333";
static const char *SEEDS[] = {
    "dns-seeder.japaneast.cloudapp.azure.com",  //kohei_niimi

    //https://github.com/bitcoin/bitcoin/blob/0.17/src/chainparams.cpp#L132-L138
    "seed.bitcoin.sipa.be", // Pieter Wuille, only supports x1, x5, x9, and xd
    "dnsseed.bluematt.me", // Matt Corallo, only supports x9
    "dnsseed.bitcoin.dashjr.org", // Luke Dashjr
    "seed.bitcoinstats.com", // Christian Decker, supports x1 - xf
    "seed.bitcoin.jonasschnelli.ch", // Jonas Schnelli, only supports x1, x5, x9, and xd
    "seed.btc.petertodd.org", // Peter Todd, only supports x1, x5, x9, and xd
    "seed.bitcoin.sprovoost.nl", // Sjors Provoost
};
#elif defined(TESTNET)
static const char SERVICE[] = "18333";
static const char *SEEDS[] = {
    //https://github.com/bitcoin/bitcoin/blob/0.17/src/chainparams.cpp#L239-L242
    "testnet-seed.bitcoin.jonasschnelli.ch",
    "seed.tbtc.petertodd.org",
    "seed.testnet.bitcoin.sprovoost.nl",
    "testnet-seed.bluematt.me", // Just a static list of stable node(s), only supports x9
};
#endif


/**************************************************************************
 * public functions
 **************************************************************************/

bool bc_network_connect(void)
{
    int ret;
    int lp = 0;
    bool retval;
    pthread_t th;

    while (true) {
        LOGD("search node\n");

#if defined(USERPEER)
        retval = connect_sub(&mProtoVal.socket, PEER_ADDR_STR, PEER_PORT_STR);
        if (retval) {
            goto LABEL_NEXT;
        }
#endif

        //DNS seed
        while (lp < ARRAY_SIZE(SEEDS)) {
            LOGD("SEED: %s\n", SEEDS[lp]);
            retval = connect_sub(&mProtoVal.socket, SEEDS[lp], SERVICE);
            lp++;   //異なるDNS seedから始める
            if (retval) {
                break;
            }
        }
        if (!retval) {
            LOGE("fail: cannnot find connectable node.\n");
            LOGE("fail: retry after...\n");
            sleep(30);
            continue;
        }

#if defined(USERPEER)
LABEL_NEXT:
#endif

        mLoopRead = true;
        mProtoVal.loop = true;
        ret = pthread_create(&th, NULL, read_proc, (void *)&mProtoVal);
        if (ret != 0) {
            LOGE("pthread_create: %s\n", strerror(errno));
            exit(-1);
        }

        bc_start(&mProtoVal);

        LOGD("disconnect\n");
        ret = shutdown(mProtoVal.socket, SHUT_RDWR);
        if (ret < 0) {
            LOGE("shutdown: %s\n", strerror(errno));
        }
        close(mProtoVal.socket);

        mLoopRead = false;
        pthread_join(th, NULL);
    }

    return retval;
}


ssize_t bc_network_read(int fd, void *buf, size_t nbytes)
{
    ssize_t ret = (ssize_t)nbytes;
    uint8_t *p = (uint8_t *)buf;

    while (nbytes > 0) {
        ssize_t len = read(fd, p, nbytes);
        if (len < 0) {
            ret -= nbytes;
            break;
        }
        nbytes -= len;
        p += len;
    }
    return ret;
}


/**************************************************************************
 * private functions
 **************************************************************************/

static bool connect_sub(int *pSock, const char *pAddr, const char *pService)
{
    bool retval = false;
    struct addrinfo hints;
    struct addrinfo *ainfo = NULL;
    int sock = -1;

    //IPアドレス取得
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;

    int ret = getaddrinfo(pAddr, pService, &hints, &ainfo);
    if (ret == 0) {
        struct addrinfo *rp;
        for (rp = ainfo; rp != NULL; rp = rp->ai_next) {
            sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sock == -1) {
                LOGE("  fail: socket\n");
                break;
            }

            struct sockaddr_in *in = (struct sockaddr_in *)rp->ai_addr;
            LOGD("  addr : %s ... ", inet_ntoa(in->sin_addr));
            fflush(stdout);
            ret = connect(sock, rp->ai_addr, rp->ai_addrlen);
            if (!ret) {
                //接続OK
                LOGD2("connected\n");
                *pSock = sock;
                retval = true;
                break;
            }
            LOGD2("fail connect\n");
        }
        freeaddrinfo(ainfo);
        if (rp == NULL) {
            LOGE("fail connect node.\n");
        }
    } else {
        perror("getaddrinfo");
    }

    return retval;
}


static void *read_proc(void *pArg)
{
    int ret;
    bc_protoval_t *p_protoval = (bc_protoval_t *)pArg;

    while (mLoopRead) {
        struct pollfd fds;
        fds.fd = p_protoval->socket;
        fds.events = POLLIN;
        ret = poll(&fds, 1, -1);
        if (ret < 0) {
            perror("poll");
        }
        else if (ret == 0) {
            LOGD("poll: timeout\n");
        }
        else {
            p_protoval->loop = bc_read_message(p_protoval);
            if (!p_protoval->loop) {
                LOGE("fail: bc_read_message()\n");
                break;
            }
        }
    }

    return NULL;
}
