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

#include "./ConnectionProvider.hpp"

#include "oatpp/network/server/SimpleTCPConnectionProvider.hpp"
#include "oatpp/core/utils/ConversionUtils.hpp"

#include "mbedtls/error.h"

namespace oatpp { namespace mbedtls { namespace server {

ConnectionProvider::ConnectionProvider(const std::shared_ptr<Config>& config,
                                       const std::shared_ptr<oatpp::network::ServerConnectionProvider>& streamProvider)
  : m_config(config)
  , m_streamProvider(streamProvider)
{

  setProperty(PROPERTY_HOST, streamProvider->getProperty(PROPERTY_HOST).toString());
  setProperty(PROPERTY_PORT, streamProvider->getProperty(PROPERTY_PORT).toString());

}

std::shared_ptr<ConnectionProvider> ConnectionProvider::createShared(const std::shared_ptr<Config>& config,
                                                                     const std::shared_ptr<oatpp::network::ServerConnectionProvider>& streamProvider){
  return std::shared_ptr<ConnectionProvider>(new ConnectionProvider(config, streamProvider));
}

std::shared_ptr<ConnectionProvider> ConnectionProvider::createShared(const std::shared_ptr<Config>& config, v_word16 port) {
  return createShared(config, oatpp::network::server::SimpleTCPConnectionProvider::createShared(port));
}

ConnectionProvider::~ConnectionProvider() {
  close();
}

void ConnectionProvider::close() {
  m_streamProvider->close();
}

std::shared_ptr<oatpp::data::stream::IOStream> ConnectionProvider::getConnection(){

  std::shared_ptr<IOStream> stream = m_streamProvider->getConnection();

  auto * tlsHandle = new mbedtls_ssl_context();
  mbedtls_ssl_init(tlsHandle);

  auto res = mbedtls_ssl_setup(tlsHandle, m_config->getTLSConfig());
  if(res != 0) {
    mbedtls_ssl_free(tlsHandle);
    delete tlsHandle;
    return nullptr;
  }

  oatpp::mbedtls::Connection::setTLSStreamBIOCallbacks(tlsHandle, stream.get());

  /*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
  /* TODO - remove this loop from here.             */
  /* It should NOT block accepting thread.          */
  /*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
  while((res = mbedtls_ssl_handshake(tlsHandle)) != 0 ) {
    if(res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE) {
      v_char8 buff[512];
      mbedtls_strerror(res, (char*)&buff, 512);
      OATPP_LOGD("[oatpp::mbedtls::server::ConnectionProvider::getConnection()]", "Error. Handshake failed. Return value=%d. '%s'", res, buff);
      mbedtls_ssl_free(tlsHandle);
      delete tlsHandle;
      return nullptr;
    }
  }

  return Connection::createShared(tlsHandle, stream);

}

}}}