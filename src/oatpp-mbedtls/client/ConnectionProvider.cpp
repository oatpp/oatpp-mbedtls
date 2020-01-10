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

#include "oatpp/network/client/SimpleTCPConnectionProvider.hpp"

#include "oatpp-mbedtls/Connection.hpp"

namespace oatpp { namespace mbedtls { namespace client {

ConnectionProvider::ConnectionProvider(const std::shared_ptr<Config>& config,
                                       const std::shared_ptr<oatpp::network::ClientConnectionProvider>& streamProvider)
  : m_config(config)
  , m_streamProvider(streamProvider)
{

  setProperty(PROPERTY_HOST, streamProvider->getProperty(PROPERTY_HOST).toString());
  setProperty(PROPERTY_PORT, streamProvider->getProperty(PROPERTY_PORT).toString());

}

std::shared_ptr<ConnectionProvider> ConnectionProvider::createShared(const std::shared_ptr<Config>& config,
                                                                     const std::shared_ptr<oatpp::network::ClientConnectionProvider>& streamProvider) {
  return std::shared_ptr<ConnectionProvider>(new ConnectionProvider(config, streamProvider));
}

std::shared_ptr<ConnectionProvider> ConnectionProvider::createShared(const std::shared_ptr<Config>& config, const oatpp::String& host, v_word16 port) {
  return createShared(config, oatpp::network::client::SimpleTCPConnectionProvider::createShared(host, port));
}

std::shared_ptr<oatpp::data::stream::IOStream> ConnectionProvider::getConnection(){

  auto stream = m_streamProvider->getConnection();

  auto * tlsHandle = new mbedtls_ssl_context();
  mbedtls_ssl_init(tlsHandle);

  auto res = mbedtls_ssl_setup(tlsHandle, m_config->getTLSConfig());
  if(res != 0) {
    mbedtls_ssl_free(tlsHandle);
    delete tlsHandle;
    OATPP_LOGD("[oatpp::mbedtls::client::ConnectionProvider::getConnection()]", "Error. Call to mbedtls_ssl_setup() failed. Return value=%d", res);
    throw std::runtime_error("[oatpp::mbedtls::client::ConnectionProvider::getConnection()]: Error. Call to mbedtls_ssl_setup() failed.");
  }

  res = mbedtls_ssl_set_hostname(tlsHandle, (const char*) getProperty(PROPERTY_HOST).getData());
  if(res != 0) {
    mbedtls_ssl_free(tlsHandle);
    delete tlsHandle;
    OATPP_LOGD("[oatpp::mbedtls::client::ConnectionProvider::getConnection()]", "Error. Call to mbedtls_ssl_set_hostname() failed. Return value=%d", res);
    throw std::runtime_error("[oatpp::mbedtls::client::ConnectionProvider::getConnection()]: Error. Call to mbedtls_ssl_set_hostname() failed.");
  }

  auto connection = std::make_shared<Connection>(tlsHandle, stream, false);
  connection->initContexts();
  return connection;

}

oatpp::async::CoroutineStarterForResult<const std::shared_ptr<oatpp::data::stream::IOStream>&> ConnectionProvider::getConnectionAsync() {

  class ConnectCoroutine : public oatpp::async::CoroutineWithResult<ConnectCoroutine, const std::shared_ptr<oatpp::data::stream::IOStream>&> {
  private:
    std::shared_ptr<Config> m_config;
    std::shared_ptr<oatpp::network::ClientConnectionProvider> m_streamProvider;
  private:
    mbedtls_ssl_context* m_tlsHandle;
    std::shared_ptr<oatpp::data::stream::IOStream> m_stream;
    std::shared_ptr<Connection> m_connection;
  public:

    ConnectCoroutine(const std::shared_ptr<Config>& config, const std::shared_ptr<oatpp::network::ClientConnectionProvider>& streamProvider)
      : m_config(config)
      , m_streamProvider(streamProvider)
      , m_tlsHandle(new mbedtls_ssl_context())
    {
      mbedtls_ssl_init(m_tlsHandle);
    }

    ~ConnectCoroutine() {
      if(m_tlsHandle != nullptr) {
        mbedtls_ssl_free(m_tlsHandle);
        delete m_tlsHandle;
      }
    }

    Action act() override {
      /* get transport stream */
      return m_streamProvider->getConnectionAsync().callbackTo(&ConnectCoroutine::onConnected);
    }

    Action onConnected(const std::shared_ptr<oatpp::data::stream::IOStream>& stream) {
      /* transport stream obtained */
      m_stream = stream;
      return yieldTo(&ConnectCoroutine::secureConnection);
    }

    Action secureConnection() {

      auto res = mbedtls_ssl_setup(m_tlsHandle, m_config->getTLSConfig());
      if(res != 0) {
        OATPP_LOGD("[oatpp::mbedtls::client::ConnectionProvider::getConnectionAsync()]", "Error. Call to mbedtls_ssl_setup() failed. Return value=%d", res);
        return error<Error>("[oatpp::mbedtls::client::ConnectionProvider::getConnectionAsync()]: Error. Call to mbedtls_ssl_setup() failed.");
      }

      res = mbedtls_ssl_set_hostname(m_tlsHandle, (const char*) m_streamProvider->getProperty(PROPERTY_HOST).getData());
      if(res != 0) {
        OATPP_LOGD("[oatpp::mbedtls::client::ConnectionProvider::getConnectionAsync()]", "Error. Call to mbedtls_ssl_set_hostname() failed. Return value=%d", res);
        return error<Error>("[oatpp::mbedtls::client::ConnectionProvider::getConnectionAsync()]: Error. Call to mbedtls_ssl_set_hostname() failed.");
      }

      m_connection = std::make_shared<Connection>(m_tlsHandle, m_stream, false);
      m_tlsHandle = nullptr;

      m_connection->setOutputStreamIOMode(oatpp::data::stream::IOMode::ASYNCHRONOUS);
      m_connection->setInputStreamIOMode(oatpp::data::stream::IOMode::ASYNCHRONOUS);

      return m_connection->initContextsAsync().next(yieldTo(&ConnectCoroutine::onSuccess));

    }

    Action onSuccess() {
      return _return(m_connection);
    }


  };

  return ConnectCoroutine::startForResult(m_config, m_streamProvider);

}

}}}
