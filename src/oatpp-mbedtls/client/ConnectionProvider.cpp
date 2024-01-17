/***************************************************************************
 *
 * Project         _____    __   ____   _      _
 *                (  _  )  /__\ (_  _)_| |_  _| |_
 *                 )(_)(  /(__)\  )( (_   _)(_   _)
 *                (_____)(__)(__)(__)  |_|    |_|
 *
 *
 * Copyright 2018-present, Leonid Stryzhevskyi <lganzzzo@gmail.com>
 *                         Benedikt-Alexander Mokroß <bam@icognize.de>
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

#include "oatpp/network/tcp/client/ConnectionProvider.hpp"

#include "oatpp-mbedtls/Connection.hpp"

namespace oatpp { namespace mbedtls { namespace client {

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
                                       const std::shared_ptr<oatpp::network::ClientConnectionProvider>& streamProvider)
  : m_connectionInvalidator(std::make_shared<ConnectionInvalidator>())
  , m_config(config)
  , m_streamProvider(streamProvider)
{

  setProperty(PROPERTY_HOST, streamProvider->getProperty(PROPERTY_HOST).toString());
  setProperty(PROPERTY_PORT, streamProvider->getProperty(PROPERTY_PORT).toString());

}

std::shared_ptr<ConnectionProvider> ConnectionProvider::createShared(const std::shared_ptr<Config>& config,
                                                                     const std::shared_ptr<network::ClientConnectionProvider>& streamProvider)
{
  return std::shared_ptr<ConnectionProvider>(new ConnectionProvider(config, streamProvider));
}

std::shared_ptr<ConnectionProvider> ConnectionProvider::createShared(const std::shared_ptr<Config>& config,
                                                                     const network::Address& address)
{
  return createShared(
    config,
    network::tcp::client::ConnectionProvider::createShared(address)
  );
}

void ConnectionProvider::stop() {
  m_streamProvider->stop();
}

provider::ResourceHandle<data::stream::IOStream> ConnectionProvider::get(){

  v_int32 flags;
  auto stream = m_streamProvider->get();

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

  if(m_config->shouldThrowOnVerificationFailed()) {
    if ((flags = mbedtls_ssl_get_verify_result(tlsHandle)) != 0) {
      char vrfy_buf[512];
      mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "", flags);
      OATPP_LOGE("[oatpp::mbedtls::client::ConnectionProvider::getConnection()]",
                 "Server certificate verification failed: %s",
                 vrfy_buf);
      mbedtls_ssl_free(tlsHandle);
      throw std::runtime_error("[oatpp::mbedtls::client::ConnectionProvider::getConnection()]: Error. Server certificate verification failed.");
    }
  }

  return provider::ResourceHandle<data::stream::IOStream>(connection, m_connectionInvalidator);

}

oatpp::async::CoroutineStarterForResult<const provider::ResourceHandle<data::stream::IOStream>&> ConnectionProvider::getAsync() {

  class ConnectCoroutine : public oatpp::async::CoroutineWithResult<ConnectCoroutine, const provider::ResourceHandle<data::stream::IOStream>&> {
  private:
    std::shared_ptr<ConnectionInvalidator> m_connectionInvalidator;
    std::shared_ptr<Config> m_config;
    std::shared_ptr<oatpp::network::ClientConnectionProvider> m_streamProvider;
  private:
    mbedtls_ssl_context* m_tlsHandle;
    provider::ResourceHandle<data::stream::IOStream> m_stream;
    std::shared_ptr<Connection> m_connection;
  public:

    ConnectCoroutine(const std::shared_ptr<ConnectionInvalidator>& connectionInvalidator,
                     const std::shared_ptr<Config>& config,
                     const std::shared_ptr<network::ClientConnectionProvider>& streamProvider)
      : m_connectionInvalidator(connectionInvalidator)
      , m_config(config)
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
      return m_streamProvider->getAsync().callbackTo(&ConnectCoroutine::onConnected);
    }

    Action onConnected(const provider::ResourceHandle<data::stream::IOStream>& stream) {
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

      return m_connection->initContextsAsync().next(yieldTo(&ConnectCoroutine::verifyServerCertificate));

    }

    Action verifyServerCertificate() {
      v_int32 flags;
      if( ( flags = mbedtls_ssl_get_verify_result( m_connection->getTlsHandle() ) ) != 0 )
      {
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "", flags );
        OATPP_LOGW("[oatpp::mbedtls::client::ConnectionProvider::getConnection()]", "Server certificate verification failed: %s", vrfy_buf);
      }

      return yieldTo(&ConnectCoroutine::onSuccess);
    }

    Action onSuccess() {
      return _return(provider::ResourceHandle<data::stream::IOStream>(m_connection, m_connectionInvalidator));
    }


  };

  return ConnectCoroutine::startForResult(m_connectionInvalidator, m_config, m_streamProvider);

}

}}}
