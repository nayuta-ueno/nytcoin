#ifndef BC_CONNECT_H__
#define BC_CONNECT_H__


/**************************************************************************
 * prototypes
 **************************************************************************/

bool bc_network_connect(void);
ssize_t bc_network_read(int fd, void *buf, size_t nbytes);

#endif /* BC_CONNECT_H__ */
