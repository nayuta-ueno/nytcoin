#ifndef USER_CONFIG_H__
#define USER_CONFIG_H__


/**************************************************************************
 * macros
 **************************************************************************/

#define BC_VER_UA               "/nytcoin:0.00/test:0.0/"
#define FNAME_BLOCK             "block.nyt"
#define FNAME_SEED              "seed.nyt"

//#define MAINNET
#define TESTNET

//#define USERPEER


#ifdef USERPEER
#define PEER_ADDR_STR           "52.243.61.218"
#define PEER_PORT_STR           "18333"
#define NODE_PORT               18333
#endif

#endif /* USER_CONFIG_H__ */
