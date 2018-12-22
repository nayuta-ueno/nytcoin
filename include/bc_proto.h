/**************************************************************************
 * @file    bc_proto.c
 * @brief   Bitcoinパケット制御
 **************************************************************************/
#ifndef BC_PROTO_H__
#define BC_PROTO_H__

#include <stdint.h>
#include <stdbool.h>

#define PTARM_USE_PRINTFUNC
#include "bc_misc.h"
#include "btc.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define SZ_SEND_BUF             (3096)


/**************************************************************************
 * types
 **************************************************************************/

typedef struct bc_protoval_t {
    volatile bool   loop;

    int         socket;

    /** true:起動後のgetheaders完了 */
    bool        synced;

    /** getheaders-->headers-->getdata後のmerkleblock数(カウントダウン) */
    uint8_t     merkle_cnt;

    /** ブロック高 */
    uint32_t    height;

    uint64_t    nonce_ping;

    /** headersで最後に読んだBlock Hash */
    uint8_t     last_headers_bhash[BTC_SZ_HASH256];

    /** 送信バッファ */
    uint8_t     buffer[SZ_SEND_BUF];
} bc_protoval_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

/** 開始
 *
 * @param[in]       pProtoVal   protocol value
 * @return      開始結果
 */
void bc_start(bc_protoval_t *pProtoVal);


/** 受信データ処理
 *
 * @param[in]       pProtoVal   protocol value
 */
bool bc_read_message(bc_protoval_t *pProtoVal);

#endif /* BC_PROTO_H__ */
