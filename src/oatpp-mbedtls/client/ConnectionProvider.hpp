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

#ifndef oatpp_mbedtls_client_ConnectionProvider_hpp
#define oatpp_mbedtls_client_ConnectionProvider_hpp

#include "oatpp-mbedtls/Config.hpp"

#include "oatpp/network/ConnectionProvider.hpp"

namespace oatpp { namespace mbedtls { namespace client {

/**
 * MbedTLS client connection provider.
 * Extends &id:oatpp::base::Countable;, &id:oatpp::network::ClientConnectionProvider;.
 */
class ConnectionProvider : public oatpp::network::ClientConnectionProvider {
private:
  std::shared_ptr<Config> m_config;
  std::shared_ptr<oatpp::network::ClientConnectionProvider> m_streamProvider;
public:
  /**
   * Constructor.
   * @param config - &id:oatpp::mbedtls::Config;.
   * @param host - host name without schema and port. Ex.: "oatpp.io", "127.0.0.1", "localhost".
   * @param port - server port.
   */
  ConnectionProvider(const std::shared_ptr<Config>& config, const std::shared_ptr<oatpp::network::ClientConnectionProvider>& streamProvider);
public:

  /**
   * Create shared ConnectionProvider.
   * @param config - &id:oatpp::mbedtls::Config;.
   * @param host - host name without schema and port. Ex.: "oatpp.io", "127.0.0.1", "localhost".
   * @param port - server port.
   * @return - `std::shared_ptr` to ConnectionProvider.
   */
  static std::shared_ptr<ConnectionProvider> createShared(const std::shared_ptr<Config>& config,
                                                          const std::shared_ptr<oatpp::network::ClientConnectionProvider>& streamProvider);

  static std::shared_ptr<ConnectionProvider> createShared(const std::shared_ptr<Config>& config, const oatpp::String& host, v_word16 port);

  /**
   * Implements &id:oatpp::network::ConnectionProvider::close;. Here does nothing.
   */
  void close() override {
    // DO NOTHING
  }

  /**
   * Get connection.
   * @return - `std::shared_ptr` to &id:oatpp::data::stream::IOStream;.
   */
  std::shared_ptr<IOStream> getConnection() override;

  /**
   * Get connection in asynchronous manner.
   * @return - &id:oatpp::async::CoroutineStarterForResult;.
   */
  oatpp::async::CoroutineStarterForResult<const std::shared_ptr<oatpp::data::stream::IOStream>&> getConnectionAsync() override;

};

}}}

#endif // oatpp_mbedtls_client_ConnectionProvider_hpp
