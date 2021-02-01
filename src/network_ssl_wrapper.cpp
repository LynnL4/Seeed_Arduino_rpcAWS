/*
 * Copyright 2010-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * Additions Copyright 2016 Espressif Systems (Shanghai) PTE LTD
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
// #include "Seeed_rpcUnified.h"
// #include "rtl_wifi/ssl_client.h"

#include <sys/param.h>
#include <stdbool.h>
#include <string.h>
#include <timer_platform.h>
#include <network_interface.h>

#include "aws_iot_config.h"
#include "aws_iot_error.h"
#include "network_interface.h"
#include "network_platform.h"

#include "seeed_rpcUnified.h"
#include "rtl_wifi/ssl_client.h"
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <errno.h>

/*-----------------------------------------------------------------------------------------------------------------------------*/
/* This is the value used for ssl read timeout */
#define IOT_SSL_READ_TIMEOUT 10

extern const char *pers;

static void _iot_tls_set_connect_params(Network *pNetwork, char *pRootCALocation, char *pDeviceCertLocation,
                                        char *pDevicePrivateKeyLocation, char *pDestinationURL,
                                        uint16_t destinationPort, uint32_t timeout_ms, bool ServerVerificationFlag)
{
    pNetwork->tlsConnectParams.DestinationPort = destinationPort;
    pNetwork->tlsConnectParams.pDestinationURL = pDestinationURL;
    pNetwork->tlsConnectParams.pDeviceCertLocation = pDeviceCertLocation;
    pNetwork->tlsConnectParams.pDevicePrivateKeyLocation = pDevicePrivateKeyLocation;
    pNetwork->tlsConnectParams.pRootCALocation = pRootCALocation;
    pNetwork->tlsConnectParams.timeout_ms = timeout_ms;
    pNetwork->tlsConnectParams.ServerVerificationFlag = ServerVerificationFlag;
}

#ifdef __cplusplus
extern "C"
{
#endif

    IoT_Error_t iot_tls_init(Network *pNetwork, char *pRootCALocation, char *pDeviceCertLocation,
                             char *pDevicePrivateKeyLocation, char *pDestinationURL,
                             uint16_t destinationPort, uint32_t timeout_ms, bool ServerVerificationFlag)
    {
        _iot_tls_set_connect_params(pNetwork, pRootCALocation, pDeviceCertLocation, pDevicePrivateKeyLocation,
                                    pDestinationURL, destinationPort, timeout_ms, ServerVerificationFlag);

        pNetwork->connect = iot_tls_connect;
        pNetwork->read = iot_tls_read;
        pNetwork->write = iot_tls_write;
        pNetwork->disconnect = iot_tls_disconnect;
        pNetwork->isConnected = iot_tls_is_connected;
        pNetwork->destroy = iot_tls_destroy;

        pNetwork->tlsDataParams.flags = 0;

        return SUCCESS;
    }

    IoT_Error_t iot_tls_is_connected(Network *pNetwork)
    {
        uint32_t interval = millis() - pNetwork->tlsDataParams.conn_staus;
        if (pNetwork->tlsDataParams.connected && interval > 500)
        {
            uint8_t dummy;
            int res = recv(pNetwork->tlsDataParams.socket, &dummy, 0, MSG_DONTWAIT);
            switch (errno)
            {
            case EWOULDBLOCK:
            case ENOENT: //caused by vfs
                pNetwork->tlsDataParams.conn_staus = millis();
                pNetwork->tlsDataParams.connected = true;
                break;
            case ENOTCONN:
            case EPIPE:
            case ECONNRESET:
            case ECONNREFUSED:
            case ECONNABORTED:
                pNetwork->tlsDataParams.connected = false;
                IOT_INFO(TAG, "Disconnected: RES: %d, ERR: %d", res, errno);
                return FAILURE;
                break;
            default:
                IOT_INFO(TAG, "Unexpected: RES: %d, ERR: %d", res, errno);
                pNetwork->tlsDataParams.conn_staus = millis();
                pNetwork->tlsDataParams.connected = true;
                break;
            }
        }
        return SUCCESS;
    }

    IoT_Error_t iot_tls_connect(Network *pNetwork, TLSConnectParams *params)
    {
        if (pNetwork->tlsDataParams.ssl_client == NULL)
        {
            pNetwork->tlsDataParams.ssl_client = ssl_client_create();
        }

        sslclient_context *sslclient = (sslclient_context *)pNetwork->tlsDataParams.ssl_client;

        ssl_set_timeout(sslclient, pNetwork->tlsConnectParams.timeout_ms);

        int ret = start_ssl_client(sslclient,
                                   pNetwork->tlsConnectParams.pDestinationURL,
                                   pNetwork->tlsConnectParams.DestinationPort,
                                   pNetwork->tlsConnectParams.timeout_ms,
                                   pNetwork->tlsConnectParams.pRootCALocation,
                                   pNetwork->tlsConnectParams.pDeviceCertLocation,
                                   pNetwork->tlsConnectParams.pDevicePrivateKeyLocation,
                                   NULL, NULL);
        if (ret < 0)
        {
            IOT_ERROR(TAG, "start_ssl_client: %d", ret);
            return SSL_CONNECTION_ERROR;
        }
        pNetwork->tlsDataParams.socket = ssl_get_socket(sslclient);
        pNetwork->tlsDataParams.connected = true;
        return SUCCESS;
    }

    IoT_Error_t iot_tls_write(Network *pNetwork, unsigned char *pMsg, size_t len, Timer *timer, size_t *written_len)
    {
        size_t written_so_far;
        bool isErrorFlag = false;
        int frags, ret = 0;
        TLSDataParams *tlsDataParams = &(pNetwork->tlsDataParams);
        sslclient_context *sslclient = (sslclient_context *)pNetwork->tlsDataParams.ssl_client;
        IOT_DEBUG(TAG, "write %d", len);
        for (written_so_far = 0, frags = 0;
             written_so_far < len && !has_timer_expired(timer); written_so_far += ret, frags++)
        {
            while (!has_timer_expired(timer) &&
                   (ret = send_ssl_data(sslclient, pMsg + written_so_far, len - written_so_far)) <= 0)
            {
                if (ret < 0)
                {
                    IOT_ERROR(TAG, "failed! mbedtls_ssl_write returned -0x%x", errno);
                    /* All other negative return values indicate connection needs to be reset.
                * Will be caught in ping request so ignored here */
                    isErrorFlag = true;
                    break;
                }
            }
            if (isErrorFlag)
            {
                break;
            }
            delay(20);
        }

        *written_len = written_so_far;

        if (isErrorFlag)
        {
            return NETWORK_SSL_WRITE_ERROR;
        }
        else if (has_timer_expired(timer) && written_so_far != len)
        {
            return NETWORK_SSL_WRITE_TIMEOUT_ERROR;
        }

        return SUCCESS;
    }

    IoT_Error_t iot_tls_read(Network *pNetwork, unsigned char *pMsg, size_t len, Timer *timer, size_t *read_len)
    {
        TLSDataParams *tlsDataParams = &(pNetwork->tlsDataParams);
        sslclient_context *sslclient = (sslclient_context *)pNetwork->tlsDataParams.ssl_client;
        uint32_t read_timeout;
        size_t rxLen = 0;
        int ret;

        while (len > 0)
        {
            IOT_DEBUG(TAG, "read %d", len);
            /* Make sure we never block on read for longer than timer has left,
         but also that we don't block indefinitely (ie read_timeout > 0) */

            ret = get_ssl_receive(sslclient, pMsg, len);
            IOT_DEBUG(TAG, "mbedtls_ssl_read ret:%d, len:%d", ret, len);

            if (ret > 0)
            {
                rxLen += ret;
                pMsg += ret;
                len -= ret;
            }
            else if (ret == 0)
            {
                return NETWORK_SSL_READ_ERROR;
            }

            // Evaluate timeout after the read to make sure read is done at least once
            if (has_timer_expired(timer))
            {
                IOT_DEBUG(TAG, "timeout rxlen:%d", rxLen);
                break;
            }
        }

        if (len == 0)
        {
            *read_len = rxLen;
            return SUCCESS;
        }

        if (rxLen == 0)
        {

            return NETWORK_SSL_NOTHING_TO_READ;
        }
        else
        {
            return NETWORK_SSL_READ_TIMEOUT_ERROR;
        }
    }

    IoT_Error_t iot_tls_disconnect(Network *pNetwork)
    {
        if (pNetwork->tlsDataParams.socket >= 0)
        {
            close(pNetwork->tlsDataParams.socket);
            pNetwork->tlsDataParams.socket = -1;
            pNetwork->tlsDataParams.connected = false;
        }
        sslclient_context *sslclient = (sslclient_context *)pNetwork->tlsDataParams.ssl_client;
        stop_ssl_socket(sslclient, NULL, NULL, NULL);
        return SUCCESS;
    }

    IoT_Error_t iot_tls_destroy(Network *pNetwork)
    {
        sslclient_context *sslclient = (sslclient_context *)pNetwork->tlsDataParams.ssl_client;
        ssl_client_destroy(sslclient);
        pNetwork->tlsDataParams.ssl_client = NULL;
        return SUCCESS;
    }

#ifdef __cplusplus
}
#endif
