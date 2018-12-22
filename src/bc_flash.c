/**
 * @file    bc_flash.c
 * @brief   FLASH管理
 */
#include "user_config.h"

#include <stdio.h>
#include <inttypes.h>

#include "bc_flash.h"
#include "bc_proto.h"

#define LOG_TAG     "flash"
#include "utl_log.h"
#include "btc.h"


/**************************************************************************
 * macros
 **************************************************************************/


/**************************************************************************
 * types
 **************************************************************************/


/**************************************************************************
 * const variables
 **************************************************************************/

//エンディアンを逆順にし忘れないように注意！
const uint32_t kBlockHeight = 1447141;
const uint8_t kBlockHashStart[] = {
    0x5e, 0xf3, 0xd3, 0x02, 0x93, 0x7a, 0x07, 0xc7,
    0x5d, 0x87, 0xc8, 0x1e, 0xae, 0xd5, 0x3b, 0x6f,
    0xfe, 0x95, 0x9d, 0x46, 0xf8, 0xc6, 0xa6, 0x28,
    0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};


/**************************************************************************
 * static variables
 **************************************************************************/


/**************************************************************************
 * prototypes
 **************************************************************************/


/**************************************************************************
 * public functions
 **************************************************************************/

// void bc_flash_generate_wallet(const uint8_t *pSeed)
// {
//     uint8_t seed[BTC_SZ_EKEY_SEED];

//     FILE *fp = fopen(FILE_SEED, "r");
//     if (fp != NULL) {
//         sz = fread(seed, sizeof(seed), 1, mFp);
//     } else {
// }


void bc_flash_save_last_bhash(uint32_t Height, const uint8_t *pHash)
{
    LOGD("height=%" PRIu32 "\n", Height);

    FILE  *fp = fopen(FNAME_BLOCK, "w");
    fseek(fp, 0, SEEK_SET);
    fwrite(&Height, sizeof(uint32_t), 1, fp);
    fwrite(pHash, 1, BTC_SZ_HASH256, fp);
    fclose(fp);
}


void bc_flash_get_last_bhash(uint32_t *pHeight, uint8_t *pHash)
{
    FILE  *fp = fopen(FNAME_BLOCK, "r");
    uint8_t data[sizeof(uint32_t) + BTC_SZ_HASH256];
    size_t sz;
    if (fp != NULL) {
        sz = fread(data, sizeof(data), 1, fp);
        fclose(fp);
    } else {
        sz = 0;
    }
    if (sz == 1) {
        *pHeight = *(uint32_t *)data;
        MEMCPY(pHash, data + sizeof(uint32_t), BTC_SZ_HASH256);
        LOGD("height=%" PRIu32 "\n", *pHeight);
    } else {
        fp = fopen(FNAME_BLOCK, "w");
        *pHeight = kBlockHeight;
        MEMCPY(pHash, kBlockHashStart, BTC_SZ_HASH256);
        bc_flash_save_last_bhash(*pHeight, pHash);
        LOGD("initialize height=%" PRIu32 "\n", *pHeight);
    }
}


/**************************************************************************
 * private functions
 **************************************************************************/
