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

#include "oatpp/core/provider/Provider.hpp"
#include "oatpp/core/data/stream/Stream.hpp"

#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"

namespace oatpp { namespace mbedtls {

/**
 * TLS Connection implementation based on Mbed TLS. Extends &id:oatpp::base::Countable; and &id:oatpp::data::stream::IOStream;.
 */
class Connection : public oatpp::base::Countable, public oatpp::data::stream::IOStream {
private:

  class IOLockGuard {
  private:
    Connection* m_connection;
    async::Action* m_checkAction;
    bool m_locked;
  public:

    IOLockGuard(Connection* connection, async::Action* checkAction);
    ~IOLockGuard();

    bool unpackAndCheck();

  };

private:

  class ConnectionContext : public oatpp::data::stream::Context {
  private:
    static std::mutex HANDSHAKE_MUTEX;
  private:
    Connection* m_connection;
    data::stream::StreamType m_streamType;
  public:

    ConnectionContext(Connection* connection, data::stream::StreamType streamType, Properties&& properties);

    void init() override;

    async::CoroutineStarter initAsync() override;

    bool isInitialized() const override;

    data::stream::StreamType getStreamType() const override;

  };

private:
  mbedtls_ssl_context* m_tlsHandle;
  provider::ResourceHandle<data::stream::IOStream> m_stream;
  std::atomic<bool> m_initialized;
private:
  async::Action* m_ioAction;
  concurrency::SpinLock m_ioLock;

  void packIOAction(async::Action* action);
  async::Action* unpackIOAction();
private:
  ConnectionContext* m_inContext;
  ConnectionContext* m_outContext;
private:
  static void setTLSStreamBIOCallbacks(mbedtls_ssl_context* tlsHandle, Connection* connection);
  static int writeCallback(void *ctx, const unsigned char *buf, size_t len);
  static int readCallback(void *ctx, unsigned char *buf, size_t len);
public:

  /**
   * Constructor.
   * @param tlsHandle - `mbedtls_ssl_context*`.
   * @param stream - underlying transport stream. &id:oatpp::data::stream::IOStream;.
   * @param initialized - is stream initialized (do we have handshake already).
   */
  Connection(mbedtls_ssl_context* tlsHandle, const provider::ResourceHandle<data::stream::IOStream>& stream, bool initialized);

  /**
   * Virtual destructor.
   */
  ~Connection();

  /**
   * Write operation callback.
   * @param data - pointer to data.
   * @param count - size of the data in bytes.
   * @param action - async specific action. If action is NOT &id:oatpp::async::Action::TYPE_NONE;, then
   * caller MUST return this action on coroutine iteration.
   * @return - actual number of bytes written. 0 - to indicate end-of-file.
   */
  v_io_size write(const void *data, v_buff_size count, async::Action& action) override;

  /**
   * Read operation callback.
   * @param buffer - pointer to buffer.
   * @param count - size of the buffer in bytes.
   * @param action - async specific action. If action is NOT &id:oatpp::async::Action::TYPE_NONE;, then
   * caller MUST return this action on coroutine iteration.
   * @return - actual number of bytes written to buffer. 0 - to indicate end-of-file.
   */
  oatpp::v_io_size read(void *buff, v_buff_size count, async::Action& action) override;

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
   * Get output stream context.
   * @return - &id:oatpp::data::stream::Context;.
   */
  oatpp::data::stream::Context& getOutputStreamContext() override;

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
   * Get input stream context. <br>
   * @return - &id:oatpp::data::stream::Context;.
   */
  oatpp::data::stream::Context& getInputStreamContext() override;

  /**
   * Close TLS handles.
   */
  void closeTLS();

  /**
   * Get TLS handle.
   * @return - `mbedtls_ssl_context*`.
   */
  mbedtls_ssl_context* getTlsHandle() {
    return m_tlsHandle;
  }

  /**
   * Get the underlying transport stream.
   * @return - underlying transport stream. &id:oatpp::data::stream::IOStream;.
   */
  provider::ResourceHandle<data::stream::IOStream> getTransportStream();

public:
  class SslHandshakeError : public std::runtime_error {
  private:
    v_int32 m_errorCode;
    const char* m_message;
  public:

    /**
     * Constructor.
     * @param errorCode - error code.
     * @param message - error message.
     */
    SslHandshakeError(v_int32 errorCode, const char* message);

    /**
     * Get error code.
     * @return - error code.
     */
    v_int32 getErrorCode() const;

    /**
     * Get error message.
     * @return - error message.
     */
    const char* getMessage() const;
  };

};

}}

#endif // oatpp_mbedtls_Connection_hpp
