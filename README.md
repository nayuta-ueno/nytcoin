# nytcoin

## settings

edit `include/user_config.h`

* `BC_VER_UA`
  * user agent

* `FNAME_BLOCK`
  * save last load block information

* `FNAME_SEED`
  * not used

* `MAINNET`, `TESTNET`
  * select which you want to use
  * WARNING!!: `MAINNET` not TESTED

* `USERPEER`
  * uncomment if you connect private node
    * `PEER_ADDR_STR`
      * private node address
    * `PEER_PORT_STR`
      * private node port number
    * `NODE_PORT`
      * `nytcoin` port number

## build

```bash
make
```

## execute

```bash
./nytcoin
```
