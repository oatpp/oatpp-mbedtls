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

#include <unistd.h>
#include <fcntl.h>

namespace oatpp { namespace mbedtls {

Connection::Connection(mbedtls_ssl_context* tlsHandle, mbedtls_net_context* handle)
  : m_tlsHandle(tlsHandle)
  , m_handle(handle)
{
}

Connection::~Connection(){
  close();
  mbedtls_net_free(m_handle);
  mbedtls_ssl_free(m_tlsHandle);
  delete m_handle;
  delete m_tlsHandle;
}

data::v_io_size Connection::write(const void *buff, data::v_io_size count){

  auto result = mbedtls_ssl_write(m_tlsHandle, (const unsigned char *) buff, count);

  if(result >= 0) {
    return result;
  }

  if(result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE ||
     result == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS || result == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS)
  {
    return data::IOError::WAIT_RETRY;
  }

  return data::IOError::BROKEN_PIPE;

}

data::v_io_size Connection::read(void *buff, data::v_io_size count){

  auto result = mbedtls_ssl_read(m_tlsHandle, (unsigned char *) buff, count);

  if(result >= 0) {
    return result;
  }

  if(result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE ||
     result == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS || result == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS)
  {
    return data::IOError::WAIT_RETRY;
  }

  return data::IOError::BROKEN_PIPE;

}

void Connection::setStreamIOMode(oatpp::data::stream::IOMode ioMode) {

  switch(ioMode) {

    case oatpp::data::stream::IOMode::BLOCKING:
      if (mbedtls_net_set_block(m_handle) != 0) {
        throw std::runtime_error("[oatpp::mbedtls::Connection::setStreamIOMode()]: Error. Can't set stream I/O mode to IOMode::BLOCKING.");
      }
      break;

    case oatpp::data::stream::IOMode::NON_BLOCKING:
      if (mbedtls_net_set_nonblock(m_handle) != 0) {
        throw std::runtime_error("[oatpp::mbedtls::Connection::setStreamIOMode()]: Error. Can't set stream I/O mode to IOMode::NON_BLOCKING.");
      }
      break;

  }
}

oatpp::data::stream::IOMode Connection::getStreamIOMode() {

  auto flags = fcntl(m_handle->fd, F_GETFL);
  if (flags < 0) {
    throw std::runtime_error("[oatpp::mbedtls::Connection::getStreamIOMode()]: Error. Can't get socket flags.");
  }

  if((flags & O_NONBLOCK) > 0) {
    return oatpp::data::stream::IOMode::NON_BLOCKING;
  }

  return oatpp::data::stream::IOMode::BLOCKING;

}

oatpp::async::Action Connection::suggestOutputStreamAction(data::v_io_size ioResult) {

  if(ioResult > 0) {
    return oatpp::async::Action::createIORepeatAction(m_handle->fd, oatpp::async::Action::IOEventType::IO_EVENT_WRITE);
  }

  switch (ioResult) {
    case oatpp::data::IOError::WAIT_RETRY:
      return oatpp::async::Action::createIOWaitAction(m_handle->fd, oatpp::async::Action::IOEventType::IO_EVENT_WRITE);
    case oatpp::data::IOError::RETRY:
      return oatpp::async::Action::createIORepeatAction(m_handle->fd, oatpp::async::Action::IOEventType::IO_EVENT_WRITE);
  }

  throw std::runtime_error("[oatpp::mbedtls::Connection::suggestInputStreamAction()]: Error. Unable to suggest async action for I/O result.");

}

oatpp::async::Action Connection::suggestInputStreamAction(data::v_io_size ioResult) {

  if(ioResult > 0) {
    return oatpp::async::Action::createIORepeatAction(m_handle->fd, oatpp::async::Action::IOEventType::IO_EVENT_READ);
  }

  switch (ioResult) {
    case oatpp::data::IOError::WAIT_RETRY:
      return oatpp::async::Action::createIOWaitAction(m_handle->fd, oatpp::async::Action::IOEventType::IO_EVENT_READ);
    case oatpp::data::IOError::RETRY:
      return oatpp::async::Action::createIORepeatAction(m_handle->fd, oatpp::async::Action::IOEventType::IO_EVENT_READ);
  }

  throw std::runtime_error("[oatpp::mbedtls::Connection::suggestInputStreamAction()]: Error. Unable to suggest async action for I/O result.");


}

void Connection::setOutputStreamIOMode(oatpp::data::stream::IOMode ioMode) {
  setStreamIOMode(ioMode);
}

oatpp::data::stream::IOMode Connection::getOutputStreamIOMode() {
  return getStreamIOMode();
}

void Connection::setInputStreamIOMode(oatpp::data::stream::IOMode ioMode) {
  setStreamIOMode(ioMode);
}

oatpp::data::stream::IOMode Connection::getInputStreamIOMode() {
  return getStreamIOMode();
}


void Connection::close(){
  ::close(m_handle->fd);
  mbedtls_ssl_close_notify(m_tlsHandle);
}

}}