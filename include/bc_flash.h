/**
 * @file    bc_flash.h
 * @brief   FLASH管理ヘッダ
 */
#ifndef BC_FLASH_H__
#define BC_FLASH_H__

#include "bc_misc.h"
#include "bc_proto.h"

#include "btc.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define BC_FLASH_START          (0x200)             ///< ユーザ用FLASH開始セクタ番号
#define BC_FLASH_END            (0x3fb)             ///< ユーザ用FLASH終了セクタ番号
#define BC_FLASH_WALLET_SZ32    (14)                ///< 4byte alignでメモリ確保する時のサイズ

#define BC_FLASH_WRT_IGNORE     (1)                 ///< FLASH書込み未実施
#define BC_FLASH_WRT_DONE       (0)                 ///< FLASH書込み正常
#define BC_FLASH_WRT_FAIL       (-1)                ///< FLASH書込み失敗

#define BC_FLASH_TYPE_TXA       (0)                 ///< TX(a)
#define BC_FLASH_TYPE_TXB       (1)                 ///< TX(b)
#define BC_FLASH_TYPE_FLASH     (2)                 ///< FLASH


/**************************************************************************
 * types
 **************************************************************************/

/** @struct bc_flash_wlt_t
 */
struct bc_flash_wlt_t {
    uint8_t     pubkey[BTC_SZ_PUBKEY];          ///< 所有者公開鍵
};


/**************************************************************************
 * prototypes
 **************************************************************************/

/** @brief  最後に取得したBlock Hash更新
 * 
 * @param[in]   Height      保存するBlock Height
 * @param[in]   pHash       保存するBlock Hash
 */
void bc_flash_save_last_bhash(uint32_t Height, const uint8_t *pHash);


/** @brief  最後に取得したBlock Hash取得
 * 
 * @param[out]  pHeight     [戻り値]Block Height
 * @param[out]  pHash       [戻り値]Block Hash
 */
void bc_flash_get_last_bhash(uint32_t *pHeight, uint8_t *pHash);

#endif /* BC_FLASH_H__ */
