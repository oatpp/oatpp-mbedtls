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

#ifndef oatpp_mbedtls_server_ConnectionProvider_hpp
#define oatpp_mbedtls_server_ConnectionProvider_hpp

#include "oatpp-mbedtls/Connection.hpp"
#include "oatpp-mbedtls/Config.hpp"

#include "oatpp/network/server/SimpleTCPConnectionProvider.hpp"

namespace oatpp { namespace mbedtls { namespace server {

/**
 * MbedTLS server connection provider.
 * Extends &id:oatpp::base::Countable;, &id:oatpp::network::ServerConnectionProvider;.
 */
class ConnectionProvider : public oatpp::network::ServerConnectionProvider {
private:
  std::shared_ptr<Config> m_config;
  std::shared_ptr<oatpp::network::ServerConnectionProvider> m_streamProvider;
public:
  /**
   * Constructor.
   * @param config - &id:oatpp::mbedtls::Config;.
   * @param port - port to listen on.
   */
  ConnectionProvider(const std::shared_ptr<Config>& config,
                     const std::shared_ptr<oatpp::network::ServerConnectionProvider>& streamProvider);
public:

  /**
   * Create shared ConnectionProvider.
   * @param config - &id:oatpp::mbedtls::Config;.
   * @param port - port to listen on.
   */
  static std::shared_ptr<ConnectionProvider> createShared(const std::shared_ptr<Config>& config,
                                                          const std::shared_ptr<oatpp::network::ServerConnectionProvider>& streamProvider);

  static std::shared_ptr<ConnectionProvider> createShared(const std::shared_ptr<Config>& config, v_word16 port);

  /**
   * Virtual destructor.
   */
  ~ConnectionProvider();

  /**
   * Close all handles.
   */
  void close() override;

  /**
   * Get incoming connection.
   * @return &id:oatpp::data::stream::IOStream;.
   */
  std::shared_ptr<IOStream> getConnection() override;

  /**
   * No need to implement this.<br>
   * For Asynchronous IO in oatpp it is considered to be a good practice
   * to accept connections in a seperate thread with the blocking accept()
   * and then process connections in Asynchronous manner with non-blocking read/write.
   * <br>
   * *It may be implemented later*
   */
  oatpp::async::CoroutineStarterForResult<const std::shared_ptr<oatpp::data::stream::IOStream>&> getConnectionAsync() override {
    /*
     *  No need to implement this.
     *  For Asynchronous IO in oatpp it is considered to be a good practice
     *  to accept connections in a seperate thread with the blocking accept()
     *  and then process connections in Asynchronous manner with non-blocking read/write
     */
    throw std::runtime_error("oatpp::mbedtls::server::ConnectionProvider::getConnectionAsync not implemented.");
  }

};

}}}

#endif // oatpp_mbedtls_server_ConnectionProvider_hpp
