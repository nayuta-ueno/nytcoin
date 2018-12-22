/**************************************************************************
 * @file    bc_proto.c
 * @brief   Bitcoin protocol control
 * @note
 *      - https://en.bitcoin.it/wiki/Protocol_documentation
 **************************************************************************/
#define MURMURHASH_VERSION      (3)
#include "user_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "bc_ope.h"
#include "bc_proto.h"
#include "bc_flash.h"
#include "bc_network.h"
#include "libbloom/bloom.h"

#define LOG_TAG     "proto"
#include "utl_log.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define BC_PROTOCOL_VERSION     ((int32_t)70015)

#if defined(MAINNET)
#define BC_MAGIC                ((uint32_t)0x0709110B)
#define BC_GENESIS              BTC_GENESIS_BTCMAIN
#elif defined(TESTNET)
#define BC_MAGIC                ((uint32_t)0x0709110B)
#define BC_GENESIS              BTC_GENESIS_BTCTEST
#endif

#if defined(MAINNET)
#define BC_PORT                 (8333)
#elif defined(TESTNET)
#define BC_PORT                 (18333)
#elif defined(USERPEER)
#define BC_PORT                 NODE_PORT
#endif


#define BC_CMD_LEN              (12)
#define BC_CHKSUM_LEN           (4)

//Elements=200, Rate=0.00001で、600バイト程度
//Elements=700, Rate=0.00001で、2096バイト程度
//Elements=700, Rate=0.0001で、1677バイト程度
#define BLOOM_ELEMENTS              (700)           //bitcoinjのwallettemplate参考
#define BLOOM_RATE                  (0.0001)        //bitcoinjのwallettemplate参考
#define BLOOM_TWEAK                 rand()

#define BLOOM_UPDATE_NONE           (0)
#define BLOOM_UPDATE_ALL            (1)
#define BLOOM_UPDATE_P2PUBKEY_ONLY  (2)

#define INV_MSG_MSK_WIT             (0x40000000)
#define INV_MSG_ERROR               (0)
#define INV_MSG_TX                  (1)
#define INV_MSG_BLOCK               (2)
#define INV_MSG_FILTERED_BLOCK      (3)
#define INV_MSG_CMPCT_BLOCK         (4)
#define INV_MSG_WIT_TX              (INV_MSG_MSK_WIT | INV_MSG_TX)
#define INV_MSG_WIT_BLOCK           (INV_MSG_MSK_WIT | INV_MSG_BLOCK)
#define INV_MSG_WIT_FILTERED_BLOCK  (INV_MSG_MSK_WIT | INV_MSG_FILTERED_BLOCK)


/** @def    BC_PACKET_LEN()
 *
 * パケット長取得
 */
#define BC_PACKET_LEN(pProto)   (sizeof(struct bc_proto_t) + pProto->length)


/**************************************************************************
 * types
 **************************************************************************/

#pragma pack(1)

/** @struct bc_proto_t
 *
 *
 */
struct bc_proto_t {
    uint32_t    magic;
    char        command[BC_CMD_LEN];
    uint32_t    length;
    uint8_t     checksum[BC_CHKSUM_LEN];
    uint8_t     payload[0];
};


/** @struct net_addr
 *
 *
 */
struct net_addr_t {
    //timestampは自分でやる
    uint64_t    services;
    uint8_t     ipaddr[16];
    uint16_t    port;
};


/** @struct inv_t
 *
 *
 */
struct inv_t {
    uint32_t    type;
    uint8_t     hash[BTC_SZ_HASH256];
};


/** @struct headers_t
 *
 *
 */
struct headers_t {
    int32_t     version;
    uint8_t     prev_block[BTC_SZ_HASH256];
    uint8_t     merkle_root[BTC_SZ_HASH256];
    uint32_t    timestamp;
    uint32_t    bits;
    uint32_t    nonce;
    uint8_t     txn_count;      //getheaders向けに確保しておく
};


struct getcfilters_t {
    uint8_t     filter_type;
    uint32_t    start_height;
    uint8_t     stop_hash[BTC_SZ_HASH256];
};


struct cfilter_t {
    uint8_t     filter_type;
    uint8_t     block_hash[BTC_SZ_HASH256];
    //NumFilterBytes + FilterBytes
    uint8_t     filter_bytes[];
};


struct cheaders_t {
    uint8_t     filter_type;
    uint8_t     stop_hash[BTC_SZ_HASH256];
    uint8_t     prev_filter_headers[BTC_SZ_HASH256];
    //NumFilterBytes + FilterBytes
    uint8_t     filter_bytes[];
};


struct getcfcheckpt {
    uint8_t     filter_type;
    uint8_t     stop_hash[BTC_SZ_HASH256];
};


struct cfcheckpt {
    uint8_t     filter_type;
    uint8_t     stop_hash[BTC_SZ_HASH256];
    //FilterHeadersLength + FilterHeaders
    uint8_t     filter_headers[];
};


#pragma pack()

typedef bool (*read_function_t)(bc_protoval_t *pProtoVal, uint32_t Len);


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool send_data(bc_protoval_t *pProtoVal, struct bc_proto_t *pProto);
static void set_header(struct bc_proto_t *pProto, const char *pCmd);
static int64_t get_current_time(void);
static void print_time(uint64_t tm);

static void add_netaddr(uint8_t **pp, uint64_t serv, int ip0, int ip1, int ip2, int ip3, uint16_t port);
static void add_varint(uint8_t **pp, int Len);

static inline ssize_t get32(int Socket, uint32_t *pVal);
static inline ssize_t get64(int Socket, uint64_t *pVal);
static ssize_t getstr(int Socket, char *pStr);
static ssize_t get_netaddr(int Socket, struct net_addr_t *pAddr);
static ssize_t get_varint(int Socket, uint64_t *pVal);

static void print_netaddr(const struct net_addr_t *pAddr);
static void print_inv(const struct inv_t *pInv);
static void print_headers(const struct headers_t* pHeaders);
static void print_services(const uint64_t Services);

static bool recv_version(bc_protoval_t *pProtoVal, uint32_t Len);
static bool recv_verack(bc_protoval_t *pProtoVal, uint32_t Len);
static bool recv_ping(bc_protoval_t *pProtoVal, uint32_t Len);
static bool recv_pong(bc_protoval_t *pProtoVal, uint32_t Len);
static bool recv_addr(bc_protoval_t *pProtoVal, uint32_t Len);
static bool recv_inv(bc_protoval_t *pProtoVal, uint32_t Len);
static bool recv_inv_tx(bc_protoval_t *pProtoVal, const struct inv_t *pInv);
static bool recv_inv_block(bc_protoval_t *pProtoVal, const struct inv_t *pInv);
static bool recv_block(bc_protoval_t *pProtoVal, uint32_t Len);
static bool recv_tx(bc_protoval_t *pProtoVal, uint32_t Len);
static bool recv_headers(bc_protoval_t *pProtoVal, uint32_t Len);
static bool recv_merkleblock(bc_protoval_t *pProtoVal, uint32_t Len);
static bool recv_feefilter(bc_protoval_t *pProtoVal, uint32_t Len);
static bool recv_sendheaders(bc_protoval_t *pProtoVal, uint32_t Len);
static bool recv_sendcmpct(bc_protoval_t *pProtoVal, uint32_t Len);
// static bool recv_cmpctblock(bc_protoval_t *pProtoVal, uint32_t Len);
// static bool recv_getblocktxn(bc_protoval_t *pProtoVal, uint32_t Len);
// static bool recv_blocktxn(bc_protoval_t *pProtoVal, uint32_t Len);
static bool recv_unknown(bc_protoval_t *pProtoVal, uint32_t Len);

static bool send_version(bc_protoval_t *pProtoVal);
static bool send_verack(bc_protoval_t *pProtoVal);
//static bool send_ping(bc_protoval_t *pProtoVal);
static bool send_pong(bc_protoval_t *pProtoVal, uint64_t Nonce);
static bool send_getblocks(bc_protoval_t *pProtoVal, const uint8_t *pHash);
static bool send_getheaders(bc_protoval_t *pProtoVal, const uint8_t *pHash);
static bool send_getdata(bc_protoval_t *pProtoVal, const struct inv_t *pInv);
static bool send_filterload(bc_protoval_t *pProtoVal, const uint8_t *pPubKeyHash, size_t Len);
static bool send_mempool(bc_protoval_t *pProtoVal);


/**************************************************************************
 * const variables
 **************************************************************************/

const char kCMD_VERSION[] = "version";              ///< [message]version
const char kCMD_VERACK[] = "verack";                ///< [message]verack
const char kCMD_PING[] = "ping";                    ///< [message]ping
const char kCMD_PONG[] = "pong";                    ///< [message]pong
const char kCMD_ADDR[] = "addr";                    ///< [message]addr
const char kCMD_INV[] = "inv";                      ///< [message]inv
const char kCMD_GETBLOCKS[] = "getblocks";          ///< [message]getblocks
const char kCMD_GETHEADERS[] = "getheaders";        ///< [message]getheaders
const char kCMD_GETDATA[] = "getdata";              ///< [message]getdata
const char kCMD_BLOCK[] = "block";                  ///< [message]block
const char kCMD_HEADERS[] = "headers";              ///< [message]headers
const char kCMD_FILTERLOAD[] = "filterload";        ///< [message]filterload
const char kCMD_TX[] = "tx";                        ///< [message]tx
const char kCMD_MEMPOOL[] = "mempool";              ///< [message]mempool
const char kCMD_MERKLEBLOCK[] = "merkleblock";      ///< [message]merkleblock
const char kCMD_FEEFILTER[] = "feefilter";          ///< [message]feefilter
const char kCMD_SENDHEADERS[] = "sendheaders";      ///< [message]sendheaders
const char kCMD_SENDCMPCT[] = "sendcmpct";          ///< [message]sendcmpct
const char kCMD_CMPCTBLOCK[] = "cmpctblock";        ///< [message]cmpctblock
const char kCMD_GETBLOCKTXN[] = "getblocktxn";      ///< [message]getblocktxn
const char kCMD_BLOCKTXN[] = "blocktxn";            ///< [message]blocktxn


/** 受信解析用 */
static const struct {
    const char          *pCmd;                  ///< メッセージ
    read_function_t     pFunc;                  ///< 処理関数
} kReplyFunc[] = {
    {   kCMD_PING,              recv_ping,          },
    {   kCMD_HEADERS,           recv_headers,       },
    {   kCMD_MERKLEBLOCK,       recv_merkleblock,   },
    {   kCMD_INV,               recv_inv,           },
    {   kCMD_TX,                recv_tx,            },
    {   kCMD_BLOCK,             recv_block,         },
    {   kCMD_PONG,              recv_pong,          },
    {   kCMD_ADDR,              recv_addr,          },
    {   kCMD_VERSION,           recv_version,       },
    {   kCMD_VERACK,            recv_verack,        },
    {   kCMD_FEEFILTER,         recv_feefilter,     },
    {   kCMD_SENDHEADERS,       recv_sendheaders,   },
    {   kCMD_SENDCMPCT,         recv_sendcmpct,     },
    {   NULL,                   recv_unknown,       },
};


//PubKeyHash(script部分は除くこと)
const uint8_t kPubKeyHash[] = {
    //tb1qv8vryy3656pkkj3vpmewmpj2aqg9gemlf582lh
    0x61, 0xd8, 0x32, 0x12, 0x3a, 0xa6,
    0x83, 0x6b, 0x4a, 0x2c, 0x0e, 0xf2, 0xed, 0x86,
    0x4a, 0xe8, 0x10, 0x54, 0x67, 0x7f,

    //n19wazVXRaUKZSXUr4JBwVHHGFYDx8t7Wh
    // 0xd7, 0x69, 0x30, 0x82, 0xfb,
    // 0x18, 0xe4, 0xf6, 0x7d, 0x5d, 0xe3, 0x36, 0x57,
    // 0x64, 0xc7, 0x92, 0x1b, 0x08, 0xf2, 0x14
};


/**************************************************************************
 * public functions
 **************************************************************************/

void bc_start(bc_protoval_t *pProtoVal)
{
    LOGD("\n");

    bc_flash_get_last_bhash(&pProtoVal->height, pProtoVal->last_headers_bhash);

    pProtoVal->loop = send_version(pProtoVal);
    while (pProtoVal->loop) {
        sleep(10);
    }
}


bool bc_read_message(bc_protoval_t *pProtoVal)
{
    bool ret = false;
    struct bc_proto_t  proto;

    ssize_t sz = sizeof(proto);
    uint8_t *buf = (uint8_t *)&proto;
    while (sz > 0) {
        ssize_t len = bc_network_read(pProtoVal->socket, buf, sz);
        buf += len;
        sz -= len;
    }
    if (proto.magic == BC_MAGIC) {
        LOGD("--------------------\n");
        //LOGD("  magic : %08x\n", proto.magic);
        LOGD("  cmd   : %s\n", proto.command);
        //LOGD("  len   : %d\n", proto.length);
        //LOGD("  hash  : %02x %02x %02x %02x\n", proto.length.checksum[0], proto.length.checksum[1], proto.length.checksum[2], proto.length.checksum[3]);

        int lp = 0;
        while (kReplyFunc[lp].pCmd != NULL) {
            if (STRCMP(proto.command, kReplyFunc[lp].pCmd) == 0) {
                break;
            }
            lp++;
        }
        ret = (*kReplyFunc[lp].pFunc)(pProtoVal, proto.length);
    } else {
        //不一致
        LOGD("[%s()]  invalid magic(%08x)\n", __func__, proto.magic);
    }

    return ret;
}


/**************************************************************************
 * private functions
 **************************************************************************/

/** 現在時刻の取得(epoch)
 *
 * @return  現在時刻(epoch時間)
 */
static int64_t get_current_time(void)
{
    return time(NULL);
}


/** (コンソール)時刻出力
 *
 * @param[in]   tm       時刻データ(epoch:Little Endian)
 */
static void print_time(uint64_t tm)
{
    LOGD2("%s", ctime((time_t *)&tm));
}


/** TCP送信
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       pProto      Bitcoinプロトコルデータ
 * @return  true    OK
 */
static bool send_data(bc_protoval_t *pProtoVal, struct bc_proto_t *pProto)
{
    LOGD("%s\n", pProto->command);

    //checksum
    uint8_t hash[BTC_SZ_HASH256];
    btc_util_hash256(hash, pProto->payload, pProto->length);
    MEMCPY(pProto->checksum, hash, BC_CHKSUM_LEN);

    return (write(pProtoVal->socket, pProto, BC_PACKET_LEN(pProto)) == BC_PACKET_LEN(pProto));
}


/** Bitcoinパケットヘッダ設定
 *
 * @param[in]   pProto      Bitconプロトコルデータ
 * @param[in]   pCmd        送信コマンド
 */
static void set_header(struct bc_proto_t *pProto, const char *pCmd)
{
    pProto->magic = BC_MAGIC;
    MEMSET(pProto->command, 0, BC_CMD_LEN);
    STRCPY(pProto->command, pCmd);
}


/** net_addr設定
 *
 * @param[in,out]   pp      設定先バッファ
 * @param[in]       serv    サービス
 * @param[in]       ip0     IPv4[0]
 * @param[in]       ip1     IPv4[1]
 * @param[in]       ip2     IPv4[2]
 * @param[in]       ip3     IPv4[03]
 * @param[in]       port    ポート番号
 */
static void add_netaddr(uint8_t **pp, uint64_t serv, int ip0, int ip1, int ip2, int ip3, uint16_t port)
{
    struct net_addr_t addr;

    MEMSET(&addr, 0, 10);
    addr.services = serv;
    addr.ipaddr[10] = addr.ipaddr[11] = 0xff;
    addr.ipaddr[12] = ip0;
    addr.ipaddr[13] = ip1;
    addr.ipaddr[14] = ip2;
    addr.ipaddr[15] = ip3;
    addr.port = (uint16_t)(((port & 0xff00) >> 8) | ((port & 0xff) << 8));     //big endian
    MEMCPY(*pp, &addr, sizeof(addr));
    *pp += sizeof(addr);
}


/** データ設定(1byte～8byteの整数)
 *
 * @param[in,out]   pp      設定先バッファ
 * @param[in]       val     設定値
 * @param[in]       sz      設定値サイズ
 *
 * @note
 *      - ポインタを進める
 */
static inline void bc_misc_add(uint8_t **pp, uint64_t val, size_t sz)
{
    MEMCPY(*pp, &val, sz);
    *pp += sz;
}


/** データ設定(varint)
 *
 * @param[in,out]   pp      設定先バッファ
 * @param[in]       Len     値
 *
 * @note
 *      - ポインタを進める
 */
static void add_varint(uint8_t **pp, int Len)
{
    if (Len < 0xfd) {
        bc_misc_add(pp, Len, 1);
    }
    else if (Len < 0xffff) {
        bc_misc_add(pp, 0xfd, 1);
        bc_misc_add(pp, Len, 2);
    }
    else {
        //TODO:
        LOGE("string too long!\n");
        return;
    }
}


/** データ取得(32bit)
 *
 * @param[in]   Socket  socket
 * @return      データ(32bit)
 *
 * @note
 *      - ポインタを進める
 */
static inline ssize_t get32(int Socket, uint32_t *pVal)
{
    return bc_network_read(Socket, pVal, sizeof(*pVal));
}


/** データ取得(64bit)
 *
 * @param[in]   Socket  socket
 * @return      データ(64bit)
 *
 * @note
 *      - ポインタを進める
 */
static inline ssize_t get64(int Socket, uint64_t *pVal)
{
    return bc_network_read(Socket, pVal, sizeof(*pVal));
}


/** データ取得(文字列)
 *
 * @param[in]   Socket  socket
 * @param[out]  pStr    文字列
 * @return          解析データ長
 */
static ssize_t getstr(int Socket, char *pStr)
{
    uint64_t len;
    ssize_t rlen = get_varint(Socket, &len);
    ssize_t sz = bc_network_read(Socket, pStr, len);
    *(pStr + sz) = '\0';
    return rlen + sz;
}


/** データ取得(net_addr)
 *
 * @param[in]   Socket  socket
 * @param[out]  pAddr   net_addr
 * @return      解析データ長
 */
static ssize_t get_netaddr(int Socket, struct net_addr_t *pAddr)
{
    ssize_t sz = bc_network_read(Socket, pAddr, sizeof(struct net_addr_t));
    pAddr->port = (uint16_t)((pAddr->port >> 8) | ((pAddr->port & 0xff) << 8));
    return sz;
}


/** varint数値変換
 *
 * @param[in]       Socket      socket
 * @param[out]      pVal        変換結果
 * @return  bc_network_read length
 */
static ssize_t get_varint(int Socket, uint64_t *pVal)
{
    int count;
    ssize_t sz1, sz2 = 0;
    uint8_t data[8];

    sz1 = bc_network_read(Socket, data, 1);
    if (data[0] < 0xfd) {
        *pVal = (uint64_t)data[0];
        count = 0;
    }
    else if (data[0] == 0xfd) {
        count = sizeof(uint16_t);
    }
    else if (data[0] == 0xfe) {
        count = sizeof(uint32_t);
    }
    else {
        count = sizeof(uint64_t);
    }

    if (count > 0) {
        sz2 = bc_network_read(Socket, data, count);
        if (sz2 == count) {
            switch (count) {
            case 2:
                *pVal = (uint64_t)*(uint16_t *)data;
                break;
            case 4:
                *pVal = (uint64_t)*(uint32_t *)data;
                break;
            case 8:
                *pVal = (uint64_t)*(uint64_t *)data;
                break;
            default:
                break;
            }
        }
    }

    return sz1 + sz2;
}


/** (コンソール)net_addr出力
 *
 * @param[in]   pAddr       net_addrデータ
 */
static void print_netaddr(const struct net_addr_t *pAddr)
{
    struct in6_addr addr;
    char ipaddr[INET6_ADDRSTRLEN];
    memcpy(addr.s6_addr, pAddr->ipaddr, sizeof(addr.s6_addr));

    LOGD2("      services: %016" PRIx64 "(", pAddr->services);
    print_services(pAddr->services);
    LOGD2(")\n");
    LOGD2("      addr: ");
    DUMPD(pAddr->ipaddr, sizeof(pAddr->ipaddr));
    LOGD2("           (%s)\n", inet_ntop(AF_INET6, &addr, ipaddr, sizeof(ipaddr)));
    LOGD2("      port: %d\n", pAddr->port);
}


/** (コンソール)inv出力
 *
 * @param[in]   pInv    invデータ
 */
static void print_inv(const struct inv_t *pInv)
{
    const char *pTypeName;

    switch (pInv->type) {
    case INV_MSG_ERROR:
        pTypeName = "ERROR";
        break;
    case INV_MSG_TX:
        pTypeName = "MSG_TX";
        break;
    case INV_MSG_BLOCK:
        pTypeName = "MSG_BLOCK";
        break;
    case INV_MSG_FILTERED_BLOCK:
        pTypeName = "MSG_FILTERED_BLOCK";
        break;
    case INV_MSG_CMPCT_BLOCK:
        pTypeName = "MSG_CMPCT_BLOCK";
        break;
    default:
        pTypeName = "unknown type";
        break;
    }

    LOGD2("    type: %s(%d)\n", pTypeName, pInv->type);
    LOGD2("    hash: ");
    TXIDD(pInv->hash);
}


/** (コンソール)headers出力
 *
 */
static void print_headers(const struct headers_t* pHeaders)
{
   //version
   LOGD2("    version: %d\n", pHeaders->version);
   //prev_block
   LOGD2("    prev_block: ");
   TXIDD(pHeaders->prev_block);
   //merkle_root
   LOGD2("    merkle_root: ");
   TXIDD(pHeaders->merkle_root);
   //timestamp
   LOGD2("    timestamp: ");
   print_time(pHeaders->timestamp);
   //bits
   LOGD2("    bits: %08x\n", pHeaders->bits);
   //nonce
   LOGD2("    nonce: %08x\n", pHeaders->nonce);

    //block hash
    uint8_t hash[BTC_SZ_HASH256];
    btc_util_hash256(hash, (const uint8_t *)pHeaders, sizeof(struct headers_t) - 1); //block hash
    LOGD2("    block hash: ");
    TXIDD(hash);
}


/** (コンソール)services出力
 *
 * @param[in]   Services        servicesデータ
 */
static void print_services(const uint64_t Services)
{
    bool b = false;
    if (Services & 1) {
        //This node can be asked for full blocks instead of just headers
        LOGD2("NETWORK");
        b = true;
    }
    if (Services & 2) {
        if (b) {
            LOGD2(",");
        }
        //BIP64
        LOGD2("GETUTXO");
        b = true;
    }
    if (Services & 4) {
        if (b) {
            LOGD2(",");
        }
        //BIP111: support bloom filter
        LOGD2("BLOOM");
        b = true;
    }
    if (Services & 8) {
        if (b) {
            LOGD2(",");
        }
        //BIP144: provide witnesses
        LOGD2("WITNESS");
        b = true;
    }
    if (Services & 1024) {
        if (b) {
            LOGD2(",");
        }
        //BIP159
        LOGD2("NETWORK_LIMITED");
        b = true;
    }
}


/** 受信データ解析(version)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Len         パケット長
 * @retval      true    OK
 */
static bool recv_version(bc_protoval_t *pProtoVal, uint32_t Len)
{
    ssize_t sz;
    uint8_t data;

    //version
    int32_t version;
    Len -= get32(pProtoVal->socket, (uint32_t *)&version);
    LOGD2("   version: %d\n", version);

    //services
    uint64_t services;
    Len -= get64(pProtoVal->socket, &services);
    LOGD2("   services: %016" PRIx64 "(", services);
    print_services(services);
    LOGD2(")\n");

    //timestamp
    LOGD2("   timestamp: ");
    uint64_t timestamp;
    Len -= get64(pProtoVal->socket, &timestamp);
    print_time(timestamp);

    //addr_recv
    LOGD2("   addr_recv:\n");
    struct net_addr_t addr;
    Len -= get_netaddr(pProtoVal->socket, &addr);
    print_netaddr(&addr);

    //addr_from
    LOGD2("   addr_from:\n");
    Len -= get_netaddr(pProtoVal->socket, &addr);
    print_netaddr(&addr);

    //nonce
    uint64_t nonce;
    Len -= get64(pProtoVal->socket, &nonce);
    LOGD2("   nonce: %08x%08x\n", (uint32_t)(nonce >> 32), (uint32_t)(nonce & 0xffffffff));

    //UserAgent
    char buf[50];
    Len -= getstr(pProtoVal->socket, buf);
    LOGD2("   user_agent: %s\n", buf);

    //height
    uint32_t height;
    Len -= get32(pProtoVal->socket, (uint32_t *)&height);
    LOGD2("   height: %d\n", height);

    //relay
    sz = bc_network_read(pProtoVal->socket, &data, 1);
    LOGD2("   relay: %d\n", data);
    Len -= sz;

    if (height < pProtoVal->height) {
        LOGE("fail: peer node is too old(peer=%" PRIu32 ", own=%" PRIu32 ")\n", height, pProtoVal->height);
        Len = 1;    //falseにするため
    }

    return Len == 0;
}


/** 受信データ解析(verack)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Len         パケット長
 * @retval      true    OK
 *
 * @note
 *          - verack, filterload, getheadersを送信する
 */
static bool recv_verack(bc_protoval_t *pProtoVal, uint32_t Len)
{
    recv_unknown(pProtoVal, Len);

    send_verack(pProtoVal);

    LOGD("*** SYNC START(height=%" PRIu32 ") ***\n", pProtoVal->height);
    send_getheaders(pProtoVal, pProtoVal->last_headers_bhash);

    //これ以降、headersが送られてくる

    return true;
}


/** 受信データ解析(ping)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Len         パケット長
 * @retval      true    OK
 *
 * @note
 *          - pongを送信する
 */
static bool recv_ping(bc_protoval_t *pProtoVal, uint32_t Len)
{
    uint64_t ping_nonce;

    Len -= get64(pProtoVal->socket, &ping_nonce);
    send_pong(pProtoVal, ping_nonce);

    return Len == 0;
}


/** 受信データ解析(pong)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Len         パケット長
 * @retval      true    OK
 */
static bool recv_pong(bc_protoval_t *pProtoVal, uint32_t Len)
{
    uint64_t nonce;
    Len -= get64(pProtoVal->socket, &nonce);
    //LOGD("   nonce: %08x%08x\n", (uint32_t)(nonce >> 32), (uint32_t)(nonce & 0xffffffff));

    return (Len == 0) && (nonce == pProtoVal->nonce_ping);
}


/** 受信データ解析(addr)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Len         パケット長
 * @retval      true    OK
 */
static bool recv_addr(bc_protoval_t *pProtoVal, uint32_t Len)
{
    uint64_t lp;
    uint64_t count;

    Len -= get_varint(pProtoVal->socket, &count);

    LOGD("   count: %" PRIu64 "\n", count);
    for (lp = 0; lp < count; lp++) {
        LOGD2("   addr_list[%" PRIu64 "] :\n", lp);
        //timestamp
        LOGD2("    timestamp: ");
        uint32_t timestamp;
        Len -= get32(pProtoVal->socket, &timestamp);
        print_time(timestamp);
        //addr
        LOGD2("    addr:\n");
        struct net_addr_t addr;
        Len -= get_netaddr(pProtoVal->socket, &addr);
        print_netaddr(&addr);
    }

    return Len == 0;
}


/** 受信データ解析(inv)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Len         パケット長
 * @retval      true    OK
 */
static bool recv_inv(bc_protoval_t *pProtoVal, uint32_t Len)
{
    uint64_t count;
    bool b_block = false;
    uint8_t last_inv_bhash[BTC_SZ_HASH256];

    Len -= get_varint(pProtoVal->socket, &count);
    while (count--) {
        struct inv_t inv;
        ssize_t sz = bc_network_read(pProtoVal->socket, &inv, sizeof(inv));
        Len -= sz;
        if (sz == sizeof(inv)) {
            print_inv(&inv);

            bool ret = true;
            switch (inv.type) {
            case INV_MSG_ERROR:
                break;
            case INV_MSG_TX:
                ret = recv_inv_tx(pProtoVal, &inv);
                break;
            case INV_MSG_BLOCK:
                ret = recv_inv_block(pProtoVal, &inv);
                if (ret) {
                    MEMCPY(last_inv_bhash, inv.hash, BTC_SZ_HASH256);
                    b_block = true;
                }
                break;
            case INV_MSG_FILTERED_BLOCK:
                break;
            case INV_MSG_CMPCT_BLOCK:
                break;
            default:
                ;
            }
        } else {
            ;
        }
    }

    //MSG_BLOCKがあるなら、次回のgetheaders負荷を減らすために更新
    if (b_block && (pProtoVal->synced)) {
        bc_flash_save_last_bhash(pProtoVal->height, last_inv_bhash);
    }

    // if (mpPayload != NULL) {
    //     //ここまでをgetdataする
    //     LOGD("  *** send getdata[cnt:%d] ***\n", *pProto->payload);
    //     send_data(pProtoVal, (struct bc_proto_t *)pProtoVal->buffer);
    //     mpPayload = NULL;
    // }

    return Len == 0;
}


static bool recv_inv_tx(bc_protoval_t *pProtoVal, const struct inv_t *pInv)
{
    return send_getdata(pProtoVal, pInv);
}


static bool recv_inv_block(bc_protoval_t *pProtoVal, const struct inv_t *pInv)
{
    //最後に通知されたBhash更新
    pProtoVal->height++;
    LOGD("*** Height=%" PRIu32 "\n", pProtoVal->height);

    return true;
}


/** 受信データ解析(block)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Len         パケット長
 * @retval      true    OK
 */
static bool recv_block(bc_protoval_t *pProtoVal, uint32_t Len)
{
    uint64_t lp;

    struct headers_t headers;
    Len -= bc_network_read(pProtoVal->socket, &headers, sizeof(headers));
    print_headers(&headers);

    //tx
    uint64_t txn_count;
    Len -= get_varint(pProtoVal->socket, &txn_count);
    LOGD("   txn_count: %" PRIu64 "\n", txn_count);
    for (lp = 0; lp < txn_count; lp++) {
        uint8_t data;
        (void)bc_network_read(pProtoVal->socket, &data, 1);
        LOGD2("%02x", data);
    }
    Len -= txn_count;
    LOGD2("\n");

    return Len == 0;
}


/** 受信データ解析(tx)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Len         パケット長
 * @retval      true    OK
 */
static bool recv_tx(bc_protoval_t *pProtoVal, uint32_t Len)
{
    uint8_t *p_tx = (uint8_t *)MALLOC(Len);
    ssize_t sz = bc_network_read(pProtoVal->socket, p_tx, Len);
    btc_print_rawtx(p_tx, Len);
    FREE(p_tx);
    Len -= sz;

    return Len == 0;
}


/** 受信データ解析(headers)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Len         パケット長
 * @retval      true    OK
 */
static bool recv_headers(bc_protoval_t *pProtoVal, uint32_t Len)
{
    uint64_t count;

    Len -= get_varint(pProtoVal->socket, &count);
    if (count == 0) {
        //countが0だった場合はここで終わり

        uint32_t height;
        uint8_t bhash[BTC_SZ_HASH256];
        bc_flash_get_last_bhash(&height, bhash);
        if (height != pProtoVal->height) {
            //最後にheadersで受信したblock hashを保存する
            bc_flash_save_last_bhash(pProtoVal->height, pProtoVal->last_headers_bhash);
        }

        //全headersが終わったので、mempoolを受け付ける
        send_filterload(pProtoVal, kPubKeyHash, sizeof(kPubKeyHash));
        send_mempool(pProtoVal);

        pProtoVal->synced = true;

        LOGD("*** SYNCED ***\n");
        LOGD("  Height=%" PRIu32 "\n", pProtoVal->height);
        LOGD("  blockhash : ");
        TXIDD(pProtoVal->last_headers_bhash);

        return true;
    }


    struct headers_t headers;
    bool ret = true;
    while (count--) {
        ssize_t sz = bc_network_read(pProtoVal->socket, &headers, sizeof(headers));
        if (sz == sizeof(headers)) {
            if (MEMCMP(btc_util_get_genesis_block(BC_GENESIS), headers.prev_block, BTC_SZ_HASH256) == 0) {
                LOGD("genesis block!!\n");
                pProtoVal->height = 0;
            }
            pProtoVal->height++;
            LOGD("*** Height=%" PRIu32 "\n", pProtoVal->height);
            print_headers(&headers);
        } else {
            LOGD("fail: headers bc_network_read size(%ld)\n", sz);
            ret = false;
            break;
        }
    }

    if (ret) {
        //続きを要求する
        btc_util_hash256(pProtoVal->last_headers_bhash, (const uint8_t *)&headers, sizeof(struct headers_t) - sizeof(uint8_t));    //txn_countを除く
        send_getheaders(pProtoVal, pProtoVal->last_headers_bhash);
    }

    return ret;
}


/** 受信データ解析(merkleblock)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Len         パケット長
 * @retval      true    OK
 */
static bool recv_merkleblock(bc_protoval_t *pProtoVal, uint32_t Len)
{
    return recv_unknown(pProtoVal, Len);

#if 0
    int ret;

    //LOGD("  [merkleblock]\n");

    //解析の必要あり？
    //今のところ感じていないので、ここで直接見てみる。
    //print_headers((const struct headers_t *)pData);

    if (mProto.length > *pLen) {
        //まだデータが来る
        LOGD("m");
        mProto.length -= *pLen;
        *pLen = 0;
        ret = BC_PROTO_CONT;
        //LOGD("   rest: %d\n", mProto.length);
    }
    else {
        //もうデータは来ない
        LOGD("M");
        *pLen -= mProto.length;
        ret = BC_PROTO_FIN;
        //LOGD("   rest: 0\n");
    }

    if (pProtoVal->merkle_cnt) {
        pProtoVal->merkle_cnt--;
        //LOGD("  rest merkleblock: %d\n", pProtoVal->merkle_cnt);
        if (pProtoVal->merkle_cnt == 0) {
            //全部返ってきた --> 次のgetheaders
            send_getheaders(pProtoVal, pProtoVal->last_headers_bhash);
        }
    }

    return ret;
#endif
}


/** 受信データ解析(feefilter)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Len         パケット長
 * @retval      true    OK
 * @note        BIP133
 */
static bool recv_feefilter(bc_protoval_t *pProtoVal, uint32_t Len)
{
    uint64_t feerate;
    Len -= get64(pProtoVal->socket, &feerate);
    LOGD("   feerate: %" PRIu64 "\n", feerate);

    return Len == 0;
}


/** 受信データ解析(sendheaders)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Len         パケット長
 * @retval      true    OK
 * @note        BIP130
 */
static bool recv_sendheaders(bc_protoval_t *pProtoVal, uint32_t Len)
{
    return Len == 0;
}


/** 受信データ解析(sendcmpct)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Len         パケット長
 * @retval      true    OK
 * @note        BIP152
 */
static bool recv_sendcmpct(bc_protoval_t *pProtoVal, uint32_t Len)
{
    uint8_t announce;
    ssize_t sz = bc_network_read(pProtoVal->socket, &announce, 1);
    Len -= sz;
    LOGD("   announce: %d\n", announce);

    uint64_t version;
    Len -= get64(pProtoVal->socket, &version);
    LOGD("   version: %" PRIu64 "\n", version);

    return Len == 0;
}


/** 受信データ解析(cmpctblock)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Len         パケット長
 * @retval      true    OK
 * @note        BIP152
 */
// static bool recv_cmpctblock(bc_protoval_t *pProtoVal, uint32_t Len)
// {
//     return Len == 0;
// }


/** 受信データ解析(未処理)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Len         パケット長
 * @retval      true    OK
 */
static bool recv_unknown(bc_protoval_t *pProtoVal, uint32_t Len)
{
    LOGD("bc_network_read data: ");
    for (uint32_t lp = 0; lp < Len; lp++) {
        uint8_t c;
        bc_network_read(pProtoVal->socket, &c, 1);
        LOGD2("%02x", c);
    }
    LOGD2("\n\n");
    return true;
}


/** Bitcoinパケット送信(version)
 *
 * @param[in]       pProtoVal   protocol value
 * @return          送信結果(0..OK)
 */
static bool send_version(bc_protoval_t *pProtoVal)
{
    struct bc_proto_t *pProto = (struct bc_proto_t *)pProtoVal->buffer;
    uint8_t *p = pProto->payload;

    set_header(pProto, kCMD_VERSION);

    //version
    bc_misc_add(&p, BC_PROTOCOL_VERSION, sizeof(int32_t));
    //services
    bc_misc_add(&p, 0, sizeof(uint64_t));
    //timestamp
    bc_misc_add(&p, get_current_time(), sizeof(int64_t));
    //addr_recv
    add_netaddr(&p, 0, 127, 0, 0, 1, BC_PORT);
    //addr_from
    add_netaddr(&p, 0, 127, 0, 0, 1, BC_PORT);
    //nonce
    uint64_t rnd = rand();
    rnd <<= 32;
    rnd |= rand();
    bc_misc_add(&p, rnd, sizeof(uint64_t));
    //user_agent
    int ua_len = STRLEN(BC_VER_UA);
    add_varint(&p, ua_len);
    MEMCPY(p, BC_VER_UA, ua_len);
    p += ua_len;
    //start_height(0固定)
    bc_misc_add(&p, 0, sizeof(int32_t));
    //relay
    bc_misc_add(&p, 0, 1);

    //payload length
    pProto->length = p - pProto->payload;

    return send_data(pProtoVal, (struct bc_proto_t *)pProtoVal->buffer);
}


/** Bitcoinパケット送信(verack)
 *
 * @param[in]       pProtoVal   protocol value
 * @return          送信結果(0..OK)
 */
static bool send_verack(bc_protoval_t *pProtoVal)
{
    struct bc_proto_t *pProto = (struct bc_proto_t *)pProtoVal->buffer;

    set_header(pProto, kCMD_VERACK);
    pProto->length = 0;

    return send_data(pProtoVal, (struct bc_proto_t *)pProtoVal->buffer);
}


#if 0
/** Bitcoinパケット送信(ping)
 *
 * @param[in]       pProtoVal   protocol value
 * @return          送信結果(0..OK)
 */
static bool send_ping(bc_protoval_t *pProtoVal)
{
    struct bc_proto_t *pProto = (struct bc_proto_t *)pProtoVal->buffer;
    uint8_t *p = pProto->payload;

    set_header(pProto, kCMD_PING);
    //nonce
    pProtoVal->nonce_ping = rand();
    pProtoVal->nonce_ping <<= 32;
    pProtoVal->nonce_ping |= rand();
    bc_misc_add(&p, pProtoVal->nonce_ping, sizeof(uint64_t));
    pProto->length = sizeof(uint64_t);

    return send_data(pProtoVal, (struct bc_proto_t *)pProtoVal->buffer);
}
#endif


/** Bitcoinパケット送信(pong)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       Nonce       送信するnonce(通常はpingと同じ値)
 * @return          送信結果(0..OK)
 */
static bool send_pong(bc_protoval_t *pProtoVal, uint64_t Nonce)
{
    struct bc_proto_t *pProto = (struct bc_proto_t *)pProtoVal->buffer;

    set_header(pProto, kCMD_PONG);
    pProto->length = 8;
    //nonce
    MEMCPY(pProto->payload, &Nonce, pProto->length);

    return send_data(pProtoVal, (struct bc_proto_t *)pProtoVal->buffer);
}


/** Bitcoinパケット送信(getblocks)
 *
 * @param[in]       pProtoVal   protocol value
 * @return          送信結果(0..OK)
 */
static bool send_getblocks(bc_protoval_t *pProtoVal, const uint8_t *pHash)
{
    struct bc_proto_t *pProto = (struct bc_proto_t *)pProtoVal->buffer;
    uint8_t *p = pProto->payload;

    set_header(pProto, kCMD_GETBLOCKS);

    //version
    bc_misc_add(&p, BC_PROTOCOL_VERSION, sizeof(int32_t));
    //hash count
    bc_misc_add(&p, 1, sizeof(uint8_t));        //varintだが1byte固定なので省略
    //block locator hashes
    MEMCPY(p, pHash, BTC_SZ_HASH256);
    p += BTC_SZ_HASH256;
    //hash_stop           :最大数
    MEMSET(p, 0, BTC_SZ_HASH256);
    p += BTC_SZ_HASH256;

    //payload length
    pProto->length = p - pProto->payload;

    return send_data(pProtoVal, (struct bc_proto_t *)pProtoVal->buffer);
}


/** Bitcoinパケット送信(getheaders)
 *
 * @param[in]       pProtoVal   protocol value
 * @return          送信結果(0..OK)
 */
static bool send_getheaders(bc_protoval_t *pProtoVal, const uint8_t *pHash)
{
    struct bc_proto_t *pProto = (struct bc_proto_t *)pProtoVal->buffer;
    uint8_t *p = pProto->payload;

    set_header(pProto, kCMD_GETHEADERS);

    //version
    bc_misc_add(&p, BC_PROTOCOL_VERSION, sizeof(int32_t));
    //hash count
    bc_misc_add(&p, 1, sizeof(uint8_t));        //varintだが1byte固定なので省略
    //block locator hashes
    MEMCPY(p, pHash, BTC_SZ_HASH256);
    p += BTC_SZ_HASH256;
    //hash_stop           :最大数
    MEMSET(p, 0, BTC_SZ_HASH256);
    p += BTC_SZ_HASH256;

    LOGD("    block locator hash(getheaders) : ");
    TXIDD(pHash);

    //payload length
    pProto->length = p - pProto->payload;

    return send_data(pProtoVal, (struct bc_proto_t *)pProtoVal->buffer);
}


/** Bitcoinパケット送信(getdata)
 *
 * @param[in]       pProtoVal   protocol value
 * @param[in]       pInv        取得要求するINV
 * @return          送信結果(0..OK)
 */
static bool send_getdata(bc_protoval_t *pProtoVal, const struct inv_t *pInv)
{
    struct bc_proto_t *pProto = (struct bc_proto_t *)pProtoVal->buffer;

    set_header(pProto, kCMD_GETDATA);

    uint8_t *p = pProto->payload;
    pProto->length = 1 + sizeof(struct inv_t);

    //inv
    *p = 1;
    p++;
    MEMCPY(p, pInv, sizeof(struct inv_t));

    return send_data(pProtoVal, (struct bc_proto_t *)pProtoVal->buffer);
}


/** Bitcoinパケット送信(filterload)
 *
 * @param[in]       pProtoVal   protocol value
 * @return          送信結果(0..OK)
 */
static bool send_filterload(bc_protoval_t *pProtoVal, const uint8_t *pPubKeyHash, size_t Len)
{
    struct bc_proto_t *pProto = (struct bc_proto_t *)pProtoVal->buffer;
    //struct bc_flash_wlt_t wlt;


    set_header(pProto, kCMD_FILTERLOAD);

    struct bloom bloom;
    bloom_init(&bloom, BLOOM_ELEMENTS, BLOOM_RATE, BLOOM_TWEAK);
    bloom_add(&bloom, pPubKeyHash, Len);

    //filter
    uint8_t *p = pProto->payload;
    add_varint(&p, bloom.bytes);
    MEMCPY(p, bloom.bf, bloom.bytes);
    p += bloom.bytes;
    //nHashFuncs
    bc_misc_add(&p, bloom.hashes, sizeof(uint32_t));
    //nTweak
    bc_misc_add(&p, bloom.tweak, sizeof(uint32_t));
    //nFlags
    //  0: BLOOM_UPDATE_NONE means the filter is not adjusted when a match is found.
    //  1: BLOOM_UPDATE_ALL  means if the filter matches any data element in a scriptPubKey the outpoint is serialized and inserted into the filter.
    //  2: BLOOM_UPDATE_P2PUBKEY_ONLY means the outpoint is inserted into the filter only if a data element in the scriptPubKey is matched, and that script is of the standard "pay to pubkey" or "pay to multisig" forms.
    bc_misc_add(&p, BLOOM_UPDATE_ALL, sizeof(uint8_t));
    bloom_free(&bloom);

    //payload length
    pProto->length = p - pProto->payload;

    return send_data(pProtoVal, (struct bc_proto_t *)pProtoVal->buffer);
}


static bool send_mempool(bc_protoval_t *pProtoVal)
{
    struct bc_proto_t *pProto = (struct bc_proto_t *)pProtoVal->buffer;

    set_header(pProto, kCMD_MEMPOOL);
    pProto->length = 0;

    return send_data(pProtoVal, (struct bc_proto_t *)pProtoVal->buffer);
}

