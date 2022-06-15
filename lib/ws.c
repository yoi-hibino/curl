/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "curl_setup.h"

#ifdef USE_WEBSOCKETS

#include "urldata.h"
#include "dynbuf.h"
#include "rand.h"
#include "curl_base64.h"
#include "sendf.h"
#include "multiif.h"
#include "ws.h"
#include "easyif.h"
#include "transfer.h"
#include "nonblock.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

CURLcode Curl_ws_request(struct Curl_easy *data, REQTYPE *req)
{
  int i;
  CURLcode result = CURLE_OK;
  unsigned char rand[16];
  char *randstr;
  size_t randlen;
  char keyheader[80];
  struct SingleRequest *k = &data->req;
  const char *heads[]= {
    /* The request MUST contain an |Upgrade| header field whose value
       MUST include the "websocket" keyword. */
    "Upgrade: websocket",
    /* The request MUST contain a |Connection| header field whose value
       MUST include the "Upgrade" token. */
    "Connection: Upgrade",
    /* The request MUST include a header field with the name
       |Sec-WebSocket-Version|. The value of this header field MUST be
       13. */
    "Sec-WebSocket-Version: 13",
    /* The request MUST include a header field with the name
       |Sec-WebSocket-Key|. The value of this header field MUST be a nonce
       consisting of a randomly selected 16-byte value that has been
       base64-encoded (see Section 4 of [RFC4648]). The nonce MUST be selected
       randomly for each connection. */
    &keyheader[0],
    NULL
  };

  /* 16 bytes random */
  result = Curl_rand(data, (unsigned char *)rand, sizeof(rand));
  if(result)
    return result;
  result = Curl_base64_encode((char *)rand, sizeof(rand), &randstr, &randlen);
  if(result)
    return result;
  msnprintf(keyheader, sizeof(keyheader), "Sec-WebSocket-Key: %s",
            randstr);
  for(i = 0; !result && heads[i]; i++) {
#ifdef USE_HYPER
    result = Curl_hyper_header(data, req, heads[i]);
#else
    (void)data;
    result = Curl_dyn_addf(req, "%s\r\n", heads[i]);
#endif
  }
  free(randstr);
  k->upgr101 = UPGR101_WS;
  return result;
}

CURLcode Curl_ws_accept(struct Curl_easy *data)
{
  struct SingleRequest *k = &data->req;
  struct HTTP *ws = data->req.p.http;
  struct connectdata *conn = data->conn;
  CURLcode result;

  /* Verify the Sec-WebSocket-Accept response */

  /* If the response includes a |Sec-WebSocket-Extensions| header field and
     this header field indicates the use of an extension that was not present
     in the client's handshake (the server has indicated an extension not
     requested by the client), the client MUST Fail the WebSocket Connection.
  */

  /* If the response includes a |Sec-WebSocket-Protocol| header field
     and this header field indicates the use of a subprotocol that was
     not present in the client's handshake (the server has indicated a
     subprotocol not requested by the client), the client MUST Fail
     the WebSocket Connection. */

  /* 4 bytes random */
  result = Curl_rand(data, (unsigned char *)&ws->ws.mask, sizeof(ws->ws.mask));
  if(result)
    return result;

  infof(data, "Switching to WebSockets; mask %02x%02x%02x%02x",
        ws->ws.mask[0], ws->ws.mask[1], ws->ws.mask[2], ws->ws.mask[3]);
  k->upgr101 = UPGR101_RECEIVED;

  if(data->set.connect_only)
    /* switch off non-blocking sockets */
    (void)curlx_nonblock(conn->sock[FIRSTSOCKET], FALSE);

  return result;
}

#define WSBIT_FIN 0x80
#define WSBIT_OPCODE_CONT  0
#define WSBIT_OPCODE_TEXT  (1)
#define WSBIT_OPCODE_BIN   (2)
#define WSBIT_OPCODE_CLOSE (8)
#define WSBIT_OPCODE_PING  (9)
#define WSBIT_OPCODE_PONG  (10)
#define WSBIT_OPCODE_MASK  (0xf)

#define WSBIT_MASK 0x80

static CURLcode ws_decode(struct Curl_easy *data,
                          unsigned char *pkt,
                          size_t ilen,
                          unsigned char **out,
                          size_t *olen,
                          unsigned int *flags)
{
  bool fin = pkt[0] & WSBIT_FIN;
  unsigned char opcode = pkt[0] & WSBIT_OPCODE_MASK;
  size_t total = 0;
  size_t len;

  infof(data, "WS: received FIN bit %u", (int)fin);
  *flags = 0;
  switch(opcode) {
  case WSBIT_OPCODE_CONT:
    if(!fin)
      *flags |= CURLWS_CONT;
    infof(data, "WS: received OPCODE CONT");
    break;
  case WSBIT_OPCODE_TEXT:
    infof(data, "WS: received OPCODE TEXT");
    *flags |= CURLWS_TEXT;
    break;
  case WSBIT_OPCODE_BIN:
    infof(data, "WS: received OPCODE BINARY");
    *flags |= CURLWS_BINARY;
    break;
  case WSBIT_OPCODE_CLOSE:
    infof(data, "WS: received OPCODE CLOSE");
    *flags |= CURLWS_CLOSE;
    break;
  case WSBIT_OPCODE_PING:
    infof(data, "WS: received OPCODE PING");
    *flags |= CURLWS_PING;
    break;
  case WSBIT_OPCODE_PONG:
    infof(data, "WS: received OPCODE PONG");
    *flags |= CURLWS_PONG;
    break;
  }

  if(pkt[1] & WSBIT_MASK) {
    /* A client MUST close a connection if it detects a masked frame. */
    failf(data, "WS: masked input frame");
    return CURLE_RECV_ERROR;
  }
  len = pkt[1];
  if(len == 126) {
    len = (pkt[2] << 8) | pkt[3];
    total += 2;
  }
  else if(len == 127) {
    failf(data, "WS: too large frame received");
    return CURLE_RECV_ERROR;
  }
  /* point to the payload */
  *out = &pkt[total + 2];
  /* return the payload length */
  *olen = len;
  total += 2 + len;
  infof(data, "WS: received %u bytes payload", len);
  if(total != ilen) {
    infof(data, "WS: decoded %u bytes, expected %u",
          (int)total, (int)ilen);
    return CURLE_RECV_ERROR;
  }
  return CURLE_OK;
}

CURLcode curl_ws_recv(struct Curl_easy *data, void *buffer, size_t buflen,
                      size_t *nread, unsigned int *recvflags)
{
  size_t bytes;
  CURLcode result;

  *recvflags = 0;
  /* get a download buffer */
  result = Curl_preconnect(data);
  if(result)
    return result;

  do {
    result = curl_easy_recv(data, data->state.buffer,
                            data->set.buffer_size, &bytes);
    if(result)
      return result;

    if(bytes) {
      unsigned char *out;
      size_t olen;
      infof(data, "WS: got %u websocket bytes to decode", (int)bytes);
      result = ws_decode(data, (unsigned char *)data->state.buffer,
                         bytes, &out, &olen, recvflags);
      if(result)
        return result;

      /* auto-respond to PINGs */
      if(*recvflags & CURLWS_PING) {
        infof(data, "WS: auto-respond to PING with a PONG");
        /* send back the exact same content as a PONG */
        result = curl_ws_send(data, out, olen, &bytes, CURLWS_PONG);
        if(result)
          return result;
        continue; /* get the next packet */
      }

      if(olen < buflen) {
        /* copy the payload to the user buffer */
        memcpy(buffer, out, olen);
        *nread = olen;
      }
    }
    else
      *nread = bytes;
    break;
  } while(1);
  return CURLE_OK;
}

/***
    RFC 6455 Section 5.2

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+
*/

static size_t ws_packet(struct Curl_easy *data,
                        const unsigned char *payload, size_t len,
                        unsigned int flags)
{
  struct HTTP *ws = data->req.p.http;
  unsigned char *out = (unsigned char *)data->state.ulbuf;
  unsigned char firstbyte = 0;
  int outi;
  unsigned char opcode;
  unsigned int xori;
  unsigned int i;
  if(flags & CURLWS_TEXT) {
    opcode = WSBIT_OPCODE_TEXT;
    infof(data, "WS: send OPCODE TEXT");
  }
  else if(flags & CURLWS_CLOSE) {
    opcode = WSBIT_OPCODE_CLOSE;
    infof(data, "WS: send OPCODE CLOSE");
  }
  else if(flags & CURLWS_PING) {
    opcode = WSBIT_OPCODE_PING;
    infof(data, "WS: send OPCODE PING");
  }
  else if(flags & CURLWS_PONG) {
    opcode = WSBIT_OPCODE_PING;
    infof(data, "WS: send OPCODE PONG");
  }
  else {
    opcode = WSBIT_OPCODE_BIN;
    infof(data, "WS: send OPCODE BINARY");
  }

  if(!(flags & CURLWS_CONT)) {
    /* if not marked as continuing, assume this is the final fragment */
    firstbyte |= WSBIT_FIN | opcode;
    ws->ws.contfragment = FALSE;
  }
  else if(ws->ws.contfragment) {
    /* the previous fragment was not a final one and this isn't either, keep a
       CONT opcode and no FIN bit */
    firstbyte |= WSBIT_OPCODE_CONT;
  }
  else {
    ws->ws.contfragment = TRUE;
  }
  out[0] = firstbyte;
  if(len > 126) {
    /* no support for > 16 bit fragment sizes */
    out[1] = 126 | WSBIT_MASK;
    out[2] = (len >> 8) & 0xff;
    out[3] = len & 0xff;
    outi = 4;
  }
  else {
    out[1] = (unsigned char)len | WSBIT_MASK;
    outi = 2;
  }

  infof(data, "WS: send FIN bit %u (byte %02x)",
        firstbyte & WSBIT_FIN ? 1 : 0,
        firstbyte);
  infof(data, "WS: send payload len %u", (int)len);

  /* 4 bytes mask */
  memcpy(&out[outi], &ws->ws.mask, 4);

  if(data->set.upload_buffer_size < (len + 10))
    return 0;

  /* pass over the mask */
  outi += 4;

  /* append payload after the mask, XOR appropriately */
  for(i = 0, xori = 0; i < len; i++, outi++) {
    out[outi] = payload[i] ^ ws->ws.mask[xori];
    xori++;
    xori &= 3;
  }

  /* return packet size */
  return outi;
}

CURLcode curl_ws_send(struct Curl_easy *data, const void *buffer,
                      size_t buflen, size_t *sent,
                      unsigned int sendflags)
{
  size_t bytes;
  CURLcode result;
  size_t plen;
  char *out;

  if(buflen > MAX_WS_SIZE) {
    failf(data, "too large packet");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  if(data->set.ws_raw_mode && Curl_is_in_callback(data)) {
    /* raw mode sends exactly what was requested, and this is from within
       the write callback */
    ssize_t written;
    result = Curl_write(data, data->conn->writesockfd, buffer, buflen,
                        &written);
    fprintf(stderr, "WS: wanted to send %u bytes, sent %u bytes\n",
            (int)buflen, (int)written);
    bytes = written;
  }
  else {
    result = Curl_get_upload_buffer(data);
    if(result)
      return result;

    plen = ws_packet(data, buffer, buflen, sendflags);

    out = data->state.ulbuf;
    result = Curl_senddata(data, out, plen, &bytes);
    (void)sendflags;
  }
  *sent = bytes;

  return result;
}

#else

CURL_EXTERN CURLcode curl_ws_recv(CURL *curl, void *buffer, size_t buflen,
                                  size_t *nread, unsigned int *recvflags)
{
  (void)curl;
  (void)buffer;
  (void)buflen;
  (void)nread;
  (void)recvflags;
  return CURLE_OK;
}

CURL_EXTERN CURLcode curl_ws_send(CURL *curl, const void *buffer,
                                  size_t buflen, size_t *sent,
                                  unsigned int sendflags)
{
  (void)curl;
  (void)buffer;
  (void)buflen;
  (void)sent;
  (void)sendflags;
  return CURLE_OK;
}

#endif /* USE_WEBSOCKETS */
