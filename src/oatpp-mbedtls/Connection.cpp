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

#include "Connection.hpp"

#include "mbedtls/error.h"

#include <thread>
#include <chrono>

namespace oatpp { namespace mbedtls {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ConnectionContext

std::mutex Connection::ConnectionContext::HANDSHAKE_MUTEX;

Connection::ConnectionContext::ConnectionContext(Connection* connection, data::stream::StreamType streamType, Properties&& properties)
  : Context(std::forward<Properties>(properties))
  , m_connection(connection)
  , m_streamType(streamType)
{}

void Connection::ConnectionContext::init() {

  if(m_connection->m_initialized) {
    return;
  }

  m_connection->m_initialized = true;

  auto inIOMode = m_connection->getInputStreamIOMode();
  auto outIOMode = m_connection->getOutputStreamIOMode();

  m_connection->setInputStreamIOMode(data::stream::IOMode::NON_BLOCKING);
  m_connection->setOutputStreamIOMode(data::stream::IOMode::NON_BLOCKING);

  int res = -1;
  while(true) {

    {

      std::lock_guard<std::mutex> lock(HANDSHAKE_MUTEX);

      res = mbedtls_ssl_handshake(m_connection->m_tlsHandle);

      if(res == 0) {
        break;
      } else if (res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE) {
//        v_char8 buff[512];
//        mbedtls_strerror(res, (char *) &buff, 512);
//        OATPP_LOGE("[oatpp::mbedtls::Connection::ConnectionContext::init()]", "Error. Handshake failed. Return value=%d. '%s'", res, buff);
        break;
      }

    }

    if (res == MBEDTLS_ERR_SSL_WANT_READ || res == MBEDTLS_ERR_SSL_WANT_WRITE) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

  }

  m_connection->setInputStreamIOMode(inIOMode);
  m_connection->setOutputStreamIOMode(outIOMode);

}

async::CoroutineStarter Connection::ConnectionContext::initAsync() {

  class HandshakeCoroutine : public oatpp::async::Coroutine<HandshakeCoroutine> {
  private:
    Connection* m_connection;
  public:

    HandshakeCoroutine(Connection* connection)
      : m_connection(connection)
    {}

    Action act() override {

      if(m_connection->m_initialized) {
        return finish();
      }

      std::lock_guard<std::mutex> lock(HANDSHAKE_MUTEX);

      /* handshake iteration */
      auto res = mbedtls_ssl_handshake(m_connection->m_tlsHandle);

      switch(res) {

        case MBEDTLS_ERR_SSL_WANT_READ:
          /* reschedule to EventIOWorker */
          return m_connection->suggestInputStreamAction(oatpp::data::IOError::WAIT_RETRY_READ);

        case MBEDTLS_ERR_SSL_WANT_WRITE:
          /* reschedule to EventIOWorker */
          return m_connection->suggestOutputStreamAction(oatpp::data::IOError::WAIT_RETRY_WRITE);

        case 0:
          /* Handshake successful */
          m_connection->m_initialized = true;
          return finish();

      }

//      v_char8 buff[512];
//      mbedtls_strerror(res, (char*)&buff, 512);
//      OATPP_LOGD("[oatpp::mbedtls::Connection::ConnectionContext::initAsync()]", "Error. Handshake failed. Return value=%d. '%s'", res, buff);

      return error<Error>("[oatpp::mbedtls::Connection::ConnectionContext::initAsync()]: Error. Handshake failed.");

    }

  };

  if(m_connection->m_initialized) {
    return nullptr;
  }

  return HandshakeCoroutine::start(m_connection);

}

bool Connection::ConnectionContext::isInitialized() const {
  return m_connection->m_initialized;
}

data::stream::StreamType Connection::ConnectionContext::getStreamType() const {
  return m_streamType;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Connection

int Connection::writeCallback(void *ctx, const unsigned char *buf, size_t len) {

  auto stream = static_cast<IOStream*>(ctx);

  auto res = stream->write(buf, len);

  if(res == oatpp::data::IOError::RETRY_READ || res == oatpp::data::IOError::WAIT_RETRY_READ ||
     res == oatpp::data::IOError::RETRY_WRITE || res == oatpp::data::IOError::WAIT_RETRY_WRITE) {
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  }

  return (int)res;
}

int Connection::readCallback(void *ctx, unsigned char *buf, size_t len) {

  auto stream = static_cast<IOStream*>(ctx);

  auto res = stream->read(buf, len);

  if(res == oatpp::data::IOError::RETRY_READ || res == oatpp::data::IOError::WAIT_RETRY_READ ||
     res == oatpp::data::IOError::RETRY_WRITE || res == oatpp::data::IOError::WAIT_RETRY_WRITE) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  return (int)res;

}

void Connection::setTLSStreamBIOCallbacks(mbedtls_ssl_context* tlsHandle, oatpp::data::stream::IOStream* stream) {
  mbedtls_ssl_set_bio(tlsHandle, stream, writeCallback, readCallback, NULL);
}

Connection::Connection(mbedtls_ssl_context* tlsHandle, const std::shared_ptr<oatpp::data::stream::IOStream>& stream, bool initialized)
  : m_tlsHandle(tlsHandle)
  , m_stream(stream)
  , m_initialized(initialized)
{

  auto& streamInContext = stream->getInputStreamContext();
  data::stream::Context::Properties inProperties;
  for(const auto& pair : streamInContext.getProperties().getAll_Unsafe()) {
    inProperties.put(pair.first, pair.second);
  }

  inProperties.put("tls", "mbedtls");
  inProperties.getAll();
  m_inContext = new ConnectionContext(this, streamInContext.getStreamType(), std::move(inProperties));


  auto& streamOutContext = stream->getOutputStreamContext();
  if(streamInContext == streamOutContext) {
    m_outContext = m_inContext;
  } else {

    data::stream::Context::Properties outProperties;
    for(const auto& pair : streamOutContext.getProperties().getAll_Unsafe()) {
      outProperties.put(pair.first, pair.second);
    }

    outProperties.put("tls", "mbedtls");
    outProperties.getAll();
    m_outContext = new ConnectionContext(this, streamOutContext.getStreamType(), std::move(outProperties));

  }

}

Connection::~Connection(){

  if(m_inContext == m_outContext) {
    delete m_inContext;
  } else {
    delete m_inContext;
    delete m_outContext;
  }
  close();
  mbedtls_ssl_free(m_tlsHandle);
  delete m_tlsHandle;
}

data::v_io_size Connection::write(const void *buff, v_buff_size count){

  auto result = mbedtls_ssl_write(m_tlsHandle, (const unsigned char *) buff, (size_t)count);

  if(result >= 0) {
    return result;
  }

  switch(result) {
    case MBEDTLS_ERR_SSL_WANT_READ:
      return oatpp::data::IOError::WAIT_RETRY_READ;

    case MBEDTLS_ERR_SSL_WANT_WRITE:
      return oatpp::data::IOError::WAIT_RETRY_WRITE;

    case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
      return oatpp::data::IOError::RETRY_WRITE;

    case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
      return oatpp::data::IOError::RETRY_WRITE;

  }

  return data::IOError::BROKEN_PIPE;

}

data::v_io_size Connection::read(void *buff, v_buff_size count){

  auto result = mbedtls_ssl_read(m_tlsHandle, (unsigned char *) buff, (size_t)count);

  if(result >= 0) {
    return result;
  }

  switch(result) {
    case MBEDTLS_ERR_SSL_WANT_READ:
      return oatpp::data::IOError::WAIT_RETRY_READ;

    case MBEDTLS_ERR_SSL_WANT_WRITE:
      return oatpp::data::IOError::WAIT_RETRY_WRITE;

    case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
      return oatpp::data::IOError::RETRY_READ;

    case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
      return oatpp::data::IOError::RETRY_READ;

  }

  return data::IOError::BROKEN_PIPE;

}

oatpp::async::Action Connection::suggestOutputStreamAction(data::v_io_size ioResult) {
  switch (ioResult) {
    case oatpp::data::IOError::RETRY_READ:
      return m_stream->suggestInputStreamAction(ioResult);
    case oatpp::data::IOError::WAIT_RETRY_READ:
      return m_stream->suggestInputStreamAction(ioResult);
    default:
      return m_stream->suggestOutputStreamAction(ioResult);
  }
}

oatpp::async::Action Connection::suggestInputStreamAction(data::v_io_size ioResult) {
  switch (ioResult) {
    case oatpp::data::IOError::RETRY_WRITE:
      return m_stream->suggestOutputStreamAction(ioResult);
    case oatpp::data::IOError::WAIT_RETRY_WRITE:
      return m_stream->suggestOutputStreamAction(ioResult);
    default:
      return m_stream->suggestInputStreamAction(ioResult);
  }
}

void Connection::setOutputStreamIOMode(oatpp::data::stream::IOMode ioMode) {
  m_stream->setOutputStreamIOMode(ioMode);
}

oatpp::data::stream::IOMode Connection::getOutputStreamIOMode() {
  return m_stream->getOutputStreamIOMode();
}

oatpp::data::stream::Context& Connection::getOutputStreamContext() {
  return *m_outContext;
}

void Connection::setInputStreamIOMode(oatpp::data::stream::IOMode ioMode) {
  m_stream->setInputStreamIOMode(ioMode);
}

oatpp::data::stream::IOMode Connection::getInputStreamIOMode() {
  return m_stream->getInputStreamIOMode();
}

oatpp::data::stream::Context& Connection::getInputStreamContext() {
  return *m_inContext;
}

void Connection::close(){
  mbedtls_ssl_close_notify(m_tlsHandle);
}

}}
