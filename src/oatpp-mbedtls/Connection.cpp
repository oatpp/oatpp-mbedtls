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

namespace oatpp { namespace mbedtls {

int Connection::writeCallback(void *ctx, const unsigned char *buf, size_t len) {

  auto stream = static_cast<IOStream*>(ctx);

  auto res = stream->write(buf, len);

  if(res == oatpp::data::IOError::RETRY || res == oatpp::data::IOError::WAIT_RETRY) {
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  }

  return (int)res;
}

int Connection::readCallback(void *ctx, unsigned char *buf, size_t len) {

  auto stream = static_cast<IOStream*>(ctx);

  auto res = stream->read(buf, len);

  if(res == oatpp::data::IOError::RETRY || res == oatpp::data::IOError::WAIT_RETRY) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  return (int)res;

}

void Connection::setTLSStreamBIOCallbacks(mbedtls_ssl_context* tlsHandle, oatpp::data::stream::IOStream* stream) {
  mbedtls_ssl_set_bio(tlsHandle, stream, writeCallback, readCallback, NULL);
}

Connection::Connection(mbedtls_ssl_context* tlsHandle, const std::shared_ptr<oatpp::data::stream::IOStream>& stream)
  : m_tlsHandle(tlsHandle)
  , m_stream(stream)
{
}

Connection::~Connection(){
  close();
  mbedtls_ssl_free(m_tlsHandle);
  delete m_tlsHandle;
}

data::v_io_size Connection::write(const void *buff, v_buff_size count){

  auto result = mbedtls_ssl_write(m_tlsHandle, (const unsigned char *) buff, (size_t)count);

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

data::v_io_size Connection::read(void *buff, v_buff_size count){

  auto result = mbedtls_ssl_read(m_tlsHandle, (unsigned char *) buff, (size_t)count);

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

oatpp::async::Action Connection::suggestOutputStreamAction(data::v_io_size ioResult) {
  return m_stream->suggestOutputStreamAction(ioResult);
}

oatpp::async::Action Connection::suggestInputStreamAction(data::v_io_size ioResult) {
  return m_stream->suggestInputStreamAction(ioResult);
}

void Connection::setOutputStreamIOMode(oatpp::data::stream::IOMode ioMode) {
  m_stream->setOutputStreamIOMode(ioMode);
}

oatpp::data::stream::IOMode Connection::getOutputStreamIOMode() {
  return m_stream->getOutputStreamIOMode();
}

void Connection::setInputStreamIOMode(oatpp::data::stream::IOMode ioMode) {
  m_stream->setInputStreamIOMode(ioMode);
}

oatpp::data::stream::IOMode Connection::getInputStreamIOMode() {
  return m_stream->getInputStreamIOMode();
}


void Connection::close(){
  mbedtls_ssl_close_notify(m_tlsHandle);
}

}}
