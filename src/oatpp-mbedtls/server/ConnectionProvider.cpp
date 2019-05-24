/***************************************************************************
 *
 * Project         _____    __   ____   _      _
 *                (  _  )  /__\ (_  _)_| |_  _| |_
 *                 )(_)(  /(__)\  )( (_   _)(_   _)
 *                (_____)(__)(__)(__)  |_|    |_|
 *
 *
 * Copyright 2018-present, Leonid Stryzhevskyi <lganzzzo@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#include "ConnectionProvider.hpp"

#include "oatpp/core/utils/ConversionUtils.hpp"

#include "mbedtls/error.h"

namespace oatpp { namespace mbedtls { namespace server {

ConnectionProvider::ConnectionProvider(const std::shared_ptr<Config>& config, v_word16 port)
  : m_config(config)
  , m_port(port)
  , m_closed(false)
{

  setProperty(PROPERTY_HOST, "127.0.0.1");
  setProperty(PROPERTY_PORT, oatpp::utils::conversion::int32ToStr(port));

  instantiateServer();

}

std::shared_ptr<ConnectionProvider> ConnectionProvider::createShared(const std::shared_ptr<Config>& config, v_word16 port){
  return std::shared_ptr<ConnectionProvider>(new ConnectionProvider(config, port));
}

ConnectionProvider::~ConnectionProvider() {
  close();
}

void ConnectionProvider::instantiateServer(){

  p_char8 host = getProperty(PROPERTY_HOST).getData();
  p_char8 port = getProperty(PROPERTY_PORT).getData();

  auto res = mbedtls_net_bind(&m_serverHandle, (const char*) host, (const char*) port, MBEDTLS_NET_PROTO_TCP);

  if(res != 0) {
    OATPP_LOGD("[oatpp::mbedtls::server::ConnectionProvider::instantiateServer()]", "Error. Call to mbedtls_net_bind() failed. Return value=%d", res);
    throw std::runtime_error("[oatpp::mbedtls::server::ConnectionProvider::instantiateServer()]: Error. Call to mbedtls_net_bind() failed.");
  }

}

void ConnectionProvider::close() {
  if(!m_closed) {
    m_closed = true;
    mbedtls_net_free(&m_serverHandle);
  }
}

std::shared_ptr<oatpp::data::stream::IOStream> ConnectionProvider::getConnection(){

  auto* clientHandle = new mbedtls_net_context();

  auto res = mbedtls_net_accept(&m_serverHandle, clientHandle, NULL, 0, NULL);
  if(res != 0) {
    delete clientHandle;
    return nullptr;
  }

  auto * tlsHandle = new mbedtls_ssl_context();
  mbedtls_ssl_init(tlsHandle);

  res = mbedtls_ssl_setup(tlsHandle, m_config->getTLSConfig());
  if(res != 0) {
    mbedtls_net_free(clientHandle);
    mbedtls_ssl_free(tlsHandle);
    delete clientHandle;
    delete tlsHandle;
    return nullptr;
  }

  mbedtls_ssl_set_bio(tlsHandle, clientHandle, mbedtls_net_send, mbedtls_net_recv, NULL);

  /*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
  /* TODO - remove this loop from here.             */
  /* It should NOT block accepting thread.          */
  /*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
  while((res = mbedtls_ssl_handshake(tlsHandle)) != 0 ) {
    if(res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE) {
      v_char8 buff[512];
      mbedtls_strerror(res, (char*)&buff, 512);
      OATPP_LOGD("[oatpp::mbedtls::server::ConnectionProvider::getConnection()]", "Error. Handshake failed. Return value=%d. '%s'", res, buff);
      mbedtls_net_free(clientHandle);
      mbedtls_ssl_free(tlsHandle);
      delete clientHandle;
      delete tlsHandle;
      return nullptr;
    }
  }

  return Connection::createShared(tlsHandle, clientHandle);

}

}}}