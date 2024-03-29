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

#include "oatpp/network/tcp/server/ConnectionProvider.hpp"
#include "oatpp/core/utils/ConversionUtils.hpp"

#include "mbedtls/error.h"

namespace oatpp { namespace mbedtls { namespace server {

void ConnectionProvider::ConnectionInvalidator::invalidate(const std::shared_ptr<data::stream::IOStream> &connection){

  auto c = std::static_pointer_cast<oatpp::mbedtls::Connection>(connection);

  /********************************************
   * WARNING!!!
   *
   * c->closeTLS(); <--- DO NOT
   *
   * DO NOT CLOSE or DELETE TLS handles here.
   * Remember - other threads can still be
   * waiting for TLS events.
   ********************************************/

  /* Invalidate underlying transport */
  auto s = c->getTransportStream();
  s.invalidator->invalidate(s.object);

}

ConnectionProvider::ConnectionProvider(const std::shared_ptr<Config>& config,
                                       const std::shared_ptr<oatpp::network::ServerConnectionProvider>& streamProvider)
  : m_connectionInvalidator(std::make_shared<ConnectionInvalidator>())
  , m_config(config)
  , m_streamProvider(streamProvider)
{

  setProperty(PROPERTY_HOST, streamProvider->getProperty(PROPERTY_HOST).toString());
  setProperty(PROPERTY_PORT, streamProvider->getProperty(PROPERTY_PORT).toString());

}

std::shared_ptr<ConnectionProvider> ConnectionProvider::createShared(const std::shared_ptr<Config>& config,
                                                                     const std::shared_ptr<network::ServerConnectionProvider>& streamProvider)
{
  return std::shared_ptr<ConnectionProvider>(new ConnectionProvider(config, streamProvider));
}

std::shared_ptr<ConnectionProvider> ConnectionProvider::createShared(const std::shared_ptr<Config>& config,
                                                                     const network::Address& address,
                                                                     bool useExtendedConnections)
{
  return createShared(
    config,
    network::tcp::server::ConnectionProvider::createShared(address, useExtendedConnections)
  );
}

ConnectionProvider::~ConnectionProvider() {
  stop();
}

void ConnectionProvider::stop() {
  m_streamProvider->stop();
}

provider::ResourceHandle<data::stream::IOStream> ConnectionProvider::get() {

  auto stream = m_streamProvider->get();

  if (!stream) {
    return nullptr;
  }

  auto *tlsHandle = new mbedtls_ssl_context();
  mbedtls_ssl_init(tlsHandle);

  auto res = mbedtls_ssl_setup(tlsHandle, m_config->getTLSConfig());
  if (res != 0) {
    mbedtls_ssl_free(tlsHandle);
    delete tlsHandle;
    return nullptr;
  }

  return provider::ResourceHandle<data::stream::IOStream>(
    std::make_shared<Connection>(tlsHandle, stream, false),
    m_connectionInvalidator
    );

}

}}}
