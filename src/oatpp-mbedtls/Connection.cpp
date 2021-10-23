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

  m_connection->setInputStreamIOMode(data::stream::IOMode::ASYNCHRONOUS);
  m_connection->setOutputStreamIOMode(data::stream::IOMode::ASYNCHRONOUS);

  int res = -1;
  while(true) {

    {

      std::lock_guard<std::mutex> lock(HANDSHAKE_MUTEX);

      async::Action action;

      IOLockGuard ioGuard(m_connection, &action);

      res = mbedtls_ssl_handshake(m_connection->m_tlsHandle);

      if(!ioGuard.unpackAndCheck()) {
        OATPP_LOGE("[oatpp::mbedtls::Connection::ConnectionContext::init()]", "Error. Packed action check failed!!!");
        return;
      }

      //////////////////////////////////////////////////
      //**********************************************//
      //** NOTE: ASYNC ACTION IS INORED             **//
      //**********************************************//

      // Ignoring an async action is NOT correct !!!
      //
      // The Reason:
      // The connection is intentionally set to IOMode::ASYNCHRONOUS.
      // This is a workaround for MbedTLS in order NOT to
      // block accepting thread having HANDSHAKE_MUTEX locked.

//      if(!action.isNone()) {
//        OATPP_LOGE("[oatpp::mbedtls::Connection::ConnectionContext::init()]", "Error. Using Async stream as transport for blocking stream!!!");
//        break;
//      }

      //////////////////////////////////////////////////

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

      m_connection->m_initialized = true;
      return yieldTo(&HandshakeCoroutine::doInit);

    }

    Action doInit() {

      std::lock_guard<std::mutex> lock(HANDSHAKE_MUTEX);

      async::Action action;
      IOLockGuard ioGuard(m_connection, &action);

      /* handshake iteration */
      auto res = mbedtls_ssl_handshake(m_connection->m_tlsHandle);

      if(!ioGuard.unpackAndCheck()) {
        OATPP_LOGE("[oatpp::mbedtls::Connection::ConnectionContext::initAsync()]", "Error. Packed action check failed!!!");
        return error<Error>("[oatpp::mbedtls::Connection::ConnectionContext::initAsync()]: Error. Packed action check failed!!!");
      }

      if(!action.isNone()) {
        return action;
      }

      switch(res) {

        case MBEDTLS_ERR_SSL_WANT_READ:
          return repeat();

        case MBEDTLS_ERR_SSL_WANT_WRITE:
          return repeat();

        case 0:
          /* Handshake successful */
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
// IOLockGuard

Connection::IOLockGuard::IOLockGuard(Connection* connection, async::Action* checkAction)
  : m_connection(connection)
  , m_checkAction(checkAction)
{
  m_connection->packIOAction(m_checkAction);
  m_locked = true;
}

Connection::IOLockGuard::~IOLockGuard() {
  if(m_locked) {
    m_connection->m_ioLock.unlock();
  }
}

bool Connection::IOLockGuard::unpackAndCheck() {
  async::Action* check = m_connection->unpackIOAction();
  m_locked = false;
  return check == m_checkAction;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Connection

int Connection::writeCallback(void *ctx, const unsigned char *buf, size_t len) {

  auto connection = static_cast<Connection*>(ctx);
  async::Action* ioAction = connection->unpackIOAction();

  v_io_size res;
  if(ioAction && ioAction->isNone()) {
    res = connection->m_stream.object->write(buf, len, *ioAction);
    if(res == IOError::RETRY_READ || res == IOError::RETRY_WRITE) {
      res = MBEDTLS_ERR_SSL_WANT_WRITE;
    }
  } else if(ioAction == nullptr) {
    res = len; // NOTE: Ignore client notification on connection close;
  } else {
    res = MBEDTLS_ERR_SSL_WANT_WRITE;
  }

  connection->packIOAction(ioAction);

  return (int)res;

}

int Connection::readCallback(void *ctx, unsigned char *buf, size_t len) {


  auto connection = static_cast<Connection*>(ctx);
  async::Action* ioAction = connection->unpackIOAction();

  v_io_size res;
  if(ioAction && ioAction->isNone()) {
    res = connection->m_stream.object->read(buf, len, *ioAction);
    if(res == IOError::RETRY_READ || res == IOError::RETRY_WRITE) {
      res = MBEDTLS_ERR_SSL_WANT_READ;
    }
  } else {
    res = MBEDTLS_ERR_SSL_WANT_READ;
  }

  connection->packIOAction(ioAction);

  return (int)res;


}

void Connection::setTLSStreamBIOCallbacks(mbedtls_ssl_context* tlsHandle, Connection* connection) {
  mbedtls_ssl_set_bio(tlsHandle, connection, writeCallback, readCallback, NULL);
}

Connection::Connection(mbedtls_ssl_context* tlsHandle, const provider::ResourceHandle<data::stream::IOStream>& stream, bool initialized)
  : m_tlsHandle(tlsHandle)
  , m_stream(stream)
  , m_initialized(initialized)
  , m_ioAction(nullptr)
{

  setTLSStreamBIOCallbacks(m_tlsHandle, this);

  auto& streamInContext = stream.object->getInputStreamContext();

  data::stream::Context::Properties inProperties(streamInContext.getProperties());
  inProperties.put("tls", "mbedtls");
  inProperties.getAll();

  m_inContext = new ConnectionContext(this, streamInContext.getStreamType(), std::move(inProperties));


  auto& streamOutContext = stream.object->getOutputStreamContext();
  if(streamInContext == streamOutContext) {
    m_outContext = m_inContext;
  } else {

    data::stream::Context::Properties outProperties(streamOutContext.getProperties());
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
  closeTLS();
  mbedtls_ssl_free(m_tlsHandle);
  delete m_tlsHandle;
}

void Connection::packIOAction(async::Action* action) {
  m_ioLock.lock();
  m_ioAction = action;
}

async::Action* Connection::unpackIOAction() {
  auto result = m_ioAction;
  m_ioAction = nullptr;
  m_ioLock.unlock();
  return result;
}

v_io_size Connection::write(const void *buff, v_buff_size count, async::Action& action){

  IOLockGuard ioGuard(this, &action);

  auto result = mbedtls_ssl_write(m_tlsHandle, (const unsigned char *) buff, (size_t)count);

  if(!ioGuard.unpackAndCheck()) {
    OATPP_LOGE("[oatpp::mbedtls::Connection::write(...)]", "Error. Packed action check failed!!!");
    return oatpp::IOError::BROKEN_PIPE;
  }

  if(result < 0) {
    switch (result) {
      case MBEDTLS_ERR_SSL_WANT_READ:           return oatpp::IOError::RETRY_WRITE;
      case MBEDTLS_ERR_SSL_WANT_WRITE:          return oatpp::IOError::RETRY_WRITE;
      case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:   return oatpp::IOError::RETRY_WRITE;
      case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:  return oatpp::IOError::RETRY_WRITE;
      default:
        return oatpp::IOError::BROKEN_PIPE;
    }
  }

  return result;

}

v_io_size Connection::read(void *buff, v_buff_size count, async::Action& action){

  IOLockGuard ioGuard(this, &action);

  auto result = mbedtls_ssl_read(m_tlsHandle, (unsigned char *) buff, (size_t)count);

  if(!ioGuard.unpackAndCheck()) {
    OATPP_LOGE("[oatpp::mbedtls::Connection::read(...)]", "Error. Packed action check failed!!!");
    return oatpp::IOError::BROKEN_PIPE;
  }

  if(result < 0) {
    switch (result) {
      case MBEDTLS_ERR_SSL_WANT_READ:           return oatpp::IOError::RETRY_READ;
      case MBEDTLS_ERR_SSL_WANT_WRITE:          return oatpp::IOError::RETRY_READ;
      case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:   return oatpp::IOError::RETRY_READ;
      case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:  return oatpp::IOError::RETRY_READ;
      default:
        return oatpp::IOError::BROKEN_PIPE;
    }
  }

  return result;

}

void Connection::setOutputStreamIOMode(oatpp::data::stream::IOMode ioMode) {
  m_stream.object->setOutputStreamIOMode(ioMode);
}

oatpp::data::stream::IOMode Connection::getOutputStreamIOMode() {
  return m_stream.object->getOutputStreamIOMode();
}

oatpp::data::stream::Context& Connection::getOutputStreamContext() {
  return *m_outContext;
}

void Connection::setInputStreamIOMode(oatpp::data::stream::IOMode ioMode) {
  m_stream.object->setInputStreamIOMode(ioMode);
}

oatpp::data::stream::IOMode Connection::getInputStreamIOMode() {
  return m_stream.object->getInputStreamIOMode();
}

oatpp::data::stream::Context& Connection::getInputStreamContext() {
  return *m_inContext;
}

void Connection::closeTLS(){
  mbedtls_ssl_close_notify(m_tlsHandle);
}

provider::ResourceHandle<data::stream::IOStream> Connection::getTransportStream() {
  return m_stream;
}

}}
