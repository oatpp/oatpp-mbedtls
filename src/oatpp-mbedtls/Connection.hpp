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

#ifndef oatpp_mbedtls_Connection_hpp
#define oatpp_mbedtls_Connection_hpp

#include "oatpp/core/data/stream/Stream.hpp"

#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"

namespace oatpp { namespace mbedtls {

/**
 * TLS Connection implementation based on Mbed TLS. Extends &id:oatpp::base::Countable; and &id:oatpp::data::stream::IOStream;.
 */
class Connection : public oatpp::base::Countable, public oatpp::data::stream::IOStream {
private:
  mbedtls_ssl_context* m_tlsHandle;
  std::shared_ptr<oatpp::data::stream::IOStream> m_stream;
private:
  static int writeCallback(void *ctx, const unsigned char *buf, size_t len);
  static int readCallback(void *ctx, unsigned char *buf, size_t len);
public:
  /**
   * Constructor.
   * @param tlsHandle - `mbedtls_ssl_context*`.
   * @param handle - `mbedtls_net_context*`.
   */
  Connection(mbedtls_ssl_context* tlsHandle, const std::shared_ptr<oatpp::data::stream::IOStream>& stream);
public:

  /**
   * Create shared connection.
   * @param tlsHandle - `mbedtls_ssl_context*`.
   * @param handle - `mbedtls_net_context*`.
   * @return - `std::shared_ptr` to Connection.
   */
  static std::shared_ptr<Connection> createShared(mbedtls_ssl_context* tlsHandle, const std::shared_ptr<oatpp::data::stream::IOStream>& stream){
    return std::make_shared<Connection>(tlsHandle, stream);
  }

  static void setTLSStreamBIOCallbacks(mbedtls_ssl_context* tlsHandle, oatpp::data::stream::IOStream* stream);

  /**
   * Virtual destructor.
   */
  ~Connection();

  /**
   * Implementation of &id:oatpp::data::stream::OutputStream::write; method.
   * @param buff - data to write to stream.
   * @param count - data size.
   * @return - actual amount of bytes written.
   */
  data::v_io_size write(const void *buff, data::v_io_size count) override;

  /**
   * Implementation of &id:oatpp::data::stream::InputStream::read; method.
   * @param buff - buffer to read data to.
   * @param count - buffer size.
   * @return - actual amount of bytes read.
   */
  data::v_io_size read(void *buff, data::v_io_size count) override;

  /**
   * Implementation of OutputStream must suggest async actions for I/O results.
   * Suggested Action is used for scheduling coroutines in async::Executor.
   * @param ioResult - result of the call to &l:OutputStream::write ();.
   * @return - &id:oatpp::async::Action;.
   */
  oatpp::async::Action suggestOutputStreamAction(data::v_io_size ioResult) override;

  /**
   * Implementation of InputStream must suggest async actions for I/O results.
   * Suggested Action is used for scheduling coroutines in async::Executor.
   * @param ioResult - result of the call to &l:InputStream::read ();.
   * @return - &id:oatpp::async::Action;.
   */
  oatpp::async::Action suggestInputStreamAction(data::v_io_size ioResult) override;

  /**
   * Set OutputStream I/O mode.
   * @param ioMode
   */
  void setOutputStreamIOMode(oatpp::data::stream::IOMode ioMode) override;

  /**
   * Set OutputStream I/O mode.
   * @return
   */
  oatpp::data::stream::IOMode getOutputStreamIOMode() override;

  /**
   * Set InputStream I/O mode.
   * @param ioMode
   */
  void setInputStreamIOMode(oatpp::data::stream::IOMode ioMode) override;

  /**
   * Get InputStream I/O mode.
   * @return
   */
  oatpp::data::stream::IOMode getInputStreamIOMode() override;

  /**
   * Close all handles.
   */
  void close();

  /**
   * Get TLS handle.
   * @return - `mbedtls_ssl_context*`.
   */
  mbedtls_ssl_context* getTlsHandle() {
    return m_tlsHandle;
  }

  /**
   * Get socket handle.
   * @return - `mbedtls_net_context*`.
   */
  std::shared_ptr<oatpp::data::stream::IOStream> getStream() {
    return m_stream;
  }

};

}}

#endif // oatpp_mbedtls_Connection_hpp
