#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define LOG_TAG "main"
#include "btc.h"
#include "utl_log.h"

#include "bc_network.h"


/**************************************************************************
 * entry point
 **************************************************************************/

int main(int argc, char *argv[])
{
    bool retval;

    utl_log_init_stdout();
    btc_init(BTC_TESTNET, true);

    retval = bc_network_connect();
    if (!retval) {
        LOGE("fail: tcp_connect()\n");
        return -1;
    }

    btc_term();
    return 0;
}
