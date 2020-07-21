/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 *
 */

#ifndef TP_SOCKET_H_
#define TP_SOCKET_H_

/*!
 @file
 @brief This file contains socket APIs used by tests.
 */

/*!
 @addtogroup pal_socket_test
 @{
 */

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DELAY 0xFFFFFFFF

typedef uint32_t tp_socket;

/** tp_sock_domain - communication domain
 *
 * @TP_AF_INET - Internet IP protocol
 */
enum tp_sock_domain {
    TP_AF_INET    = 1
};


/** tp_sock_type - Socket types
 *
 * @TP_SOCK_DGRAM - datagram (conn.less) socket
 * @TP_SOCK_STREAM - stream (connection) socket
 */
enum tp_sock_type {
    TP_SOCK_DGRAM    = 1,
    TP_SOCK_STREAM    = 2
};

/** test_pal_sock_protocol - protocol types
 *
 * @TP_IPPROTO_TCP - TCP socket
 * @TP_IPPROTO_UDP - UDP socket
 */
enum tp_sock_protocol {
    TP_IPPROTO_TCP    = 1,
    TP_IPPROTO_UDP    = 2
};

/******************************************************************************/
/*!
 * @brief This function creates an endpoint for communication.
 *
 *
 * @return 0 on success.
 * @return 1 on failure.
 */
uint32_t Test_PalSocket(
 /*! Socket structure pointer.*/
 tp_socket *s,
 /*! Specifies a communication domain.*/
 enum tp_sock_domain domain,
 /*! Indicated type, which specifies the communication semantics.*/
 enum tp_sock_type type,
 /*! Specifies a particular protocol to be used with the socket.*/
 enum tp_sock_protocol protocol,
 /*! Specifies receive timeout in milliseconds.*/
 const uint32_t recvTimeout_ms
);

/******************************************************************************/
/*!
 * @brief This function closes an endpoint for communication.
 *
 *
 * @return 0 on success.
 * @return 1 on failure.
 */
uint32_t Test_PalCloseSocket(
 /*! Socket handler to be closed.*/
 tp_socket s
);

/******************************************************************************/
/*!
 * @brief This function initiates a connection on a socket.
 *
 *
 * @return 0 on success.
 * @return 1 on failure.
 */
uint32_t Test_PalConnect(
 /*! Socket handler.*/
 tp_socket s,
 /*! Destination IP address.*/
 const uint8_t *addr,
 /*! Destination port number.*/
 uint32_t port
);

/******************************************************************************/
/*!
 * @brief This function assigns the local address to the socket.
 *
 *
 * @return 0 on success.
 * @return 1 on failure.
 */
uint32_t Test_PalBind(
 /*! Socket handler.*/
 tp_socket s,
 /*! Socket local port number.*/
 uint32_t port
);

/******************************************************************************/
/*!
 * @brief This function listens for incoming connection on socket.
 *
 *
 * @return 0 on success.
 * @return 1 on failure.
 */
uint32_t Test_PalListen(
 /*! Socket handler.*/
 tp_socket s,
 /*! Puts a limit on the number of simultaneously connected clients.*/
 uint32_t backlog
);

/******************************************************************************/
/*!
 * @brief This function accept connection on a socket.
 *
 *
 * @return 0 on success.
 * @return 1 on failure.
 */
uint32_t Test_PalAccept(
 /*! The listening socket on which new connections are to be accepted.*/
 tp_socket s,
 /*! Handle of the accepted socket created.*/
 tp_socket *acptS,
 /*! IP Addr of the socket from which a connection was accepted.*/
 uint8_t *addr,
 /*! Port number of the socket from which a connection was accepted.*/
 uint32_t *port
);

/******************************************************************************/
/*!
 * @brief This function disable reads and writes on a connected TCP socket.
 *
 *
 * @return 0 on success.
 * @return 1 on failure.
 */
uint32_t Test_PalShutdown(
 /*! Socket handler.*/
 tp_socket s
);

/******************************************************************************/
/*!
 * @brief This function sends messages via a specified socket.
 *
 *
 * @return Number of bytes sent on success.
 * @return 0 on failure.
 */
uint32_t Test_PalSend(
 /*! Active connected socket-descriptor.*/
 tp_socket s,
 /*! Pointer to data buffer prepared by user.*/
 const uint8_t *buf,
 /*! Buffer size.*/
 size_t len
);

/******************************************************************************/
/*!
 * @brief This function sends messages via a specified socket.
 *
 *
 * @return Number of bytes sent on success.
 * @return 0 on failure.
 */
uint32_t Test_PalSendTo(
 /*! Active connected socket-descriptor.*/
 tp_socket s,
 /*! Pointer to data buffer prepared by user.*/
 const uint8_t *buf,
 /*! Buffer size.*/
 size_t len,
 /*! IP address.*/
 const uint8_t *addr,
 /*! Port number.*/
 uint32_t port
);

/******************************************************************************/
/*!
 * @brief This function sends messages via a specified socket.
 *
 *
 * @return Number of bytes recv on success.
 * @return 0 on failure.
 */
uint32_t Test_PalRecvFrom(
 /*! Active socket-descriptor.*/
 tp_socket s,
 /*! Pointer to data buffer prepared by user.*/
 const uint8_t *buf,
 /*! Buffer size.*/
 size_t len,
 /*! Received IP address.*/
 uint8_t *addr,
 /*! Received port number.*/
 uint32_t *port
);

/******************************************************************************/
/*!
 * @brief This function sends messages via a specified socket.
 *
 *
 * @return Number of bytes recv for success, 0 for failure.
 */
uint32_t Test_PalRecv(
 /*! Active socket-descriptor.*/
 tp_socket s,
 /*! Pointer to data buffer prepared by user.*/
 const uint8_t *buf,
 /*! Buffer size.*/
 size_t len
);

/******************************************************************************/
/*!
 * @brief This function set the Byte Order and Endian of the host
 * to network long.
 *
 *
 * @return The converted value.
 */
uint32_t Test_PalHtonl(
 /*! Value to convert.*/
 uint32_t val
);

/******************************************************************************/
/*!
 * @brief This function set the Byte Order and Endian of the host
 * to network short.
 *
 *
 * @return The converted value.
 */
uint16_t Test_PalHtons(
 /*! Value to convert.*/
 uint16_t val
);

/******************************************************************************/
/*!
 * @brief This function set the Byte Order and Endian of the network
 * to host long.
 *
 *
 * @return The converted value.
 */
uint32_t Test_PalNtohl(
 /*! Value to convert.*/
 uint32_t val
);

/******************************************************************************/
/*!
 * @brief This function set the Byte Order and Endian of the network
 * to host short.
 *
 *
 * @return The converted value.
 */
uint16_t Test_PalNtohs(
 /*! Value to convert.*/
 uint16_t val
);

#ifdef __cplusplus
}
#endif
/*!
 @}
 */
#endif /* TP_SOCKET_H_ */
