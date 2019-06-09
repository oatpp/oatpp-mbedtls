# oatpp-mbedtls [![Build Status](https://dev.azure.com/lganzzzo/lganzzzo/_apis/build/status/oatpp.oatpp-mbedtls?branchName=master)](https://dev.azure.com/lganzzzo/lganzzzo/_build/latest?definitionId=18&branchName=master)

**oatpp-mbedtls** - extension for [Oat++ Web Framework](https://github.com/oatpp/oatpp).  
It provides secure server and client connection providers for oatpp applications. Based on [MbedTLS](https://tls.mbed.org/).  
Supports both "Simple" and "Async" oatpp APIs.

See more:
- [Oat++ Website](https://oatpp.io/)
- [Oat++ Github Repository](https://github.com/oatpp/oatpp)
- [MbedTLS](https://tls.mbed.org/)

## Requires

- MbedTLS installed.

To install MbedTLS from source:

```bash
git clone -b 'mbedtls-2.16.1' --single-branch --depth 1 --recurse-submodules https://github.com/ARMmbed/mbedtls

cd mbedtls
mkdir build && cd build

cmake ..
make install
```

## APIs

### Server

#### ConnectionProvider

Create `ConnectionProvider`

```cpp
const char* serverCertificateFile = "path/to/server/certificate";
const char* serverPrivateKeyFile = "path/to/server/private/key";

/* Create Config */
auto config = oatpp::mbedtls::Config::createDefaultServerConfigShared(serverCertificateFile, serverPrivateKeyFile);

/* Create Secure Connection Provider */
auto connectionProvider = oatpp::mbedtls::server::ConnectionProvider::createShared(config, 443 /* port */);

/* Get Secure Connection Stream */
auto connection = connectionProvider->getConnection();
```

#### Custom Transport Stream

Create `ConnectionProvider` with custom transport stream.

```cpp
const char* serverCertificateFile = "path/to/server/certificate";
const char* serverPrivateKeyFile = "path/to/server/private/key";

/* Create Config */
auto config = oatpp::mbedtls::Config::createDefaultServerConfigShared(serverCertificateFile, serverPrivateKeyFile);

/* Create Transport Stream Provider */
/* Replace With Your Custom Transport Stream Provider */
auto transportStreamProvider = oatpp::network::server::SimpleTCPConnectionProvider::createShared(443 /* port */);

/* Create Secure Connection Provider */
auto connectionProvider = oatpp::mbedtls::server::ConnectionProvider::createShared(config, transportStreamProvider);

/* Get Secure Connection Stream over Custom Transport Stream */
auto connection = connectionProvider->getConnection();
```

**Note:** To use `oatpp-mbedtls` for server connections with custom transport stream you should implement:

- [oatpp::network::ServerConnectionProvider](https://oatpp.io/api/latest/oatpp/network/ConnectionProvider/#serverconnectionprovider).
- [oatpp::data::stream::IOStream](https://oatpp.io/api/latest/oatpp/core/data/stream/Stream/#iostream) - to be returned by `ConnectionProvider`.

### Client

#### ConnectionProvider

Create `ConnectionProvider`

```cpp
/* Create Config */
auto config = oatpp::mbedtls::Config::createDefaultClientConfigShared();

/* Create Secure Connection Provider */
auto connectionProvider = oatpp::mbedtls::client::ConnectionProvider::createShared(config, "httpbin.org", 443 /* port */);

/* Get Secure Connection Stream */
auto connection = connectionProvider->getConnection();
```

#### Custom Transport Stream

Create `ConnectionProvider` with custom transport stream.

```cpp
/* Create Config */
auto config = oatpp::mbedtls::Config::createDefaultClientConfigShared();

/* Create Transport Stream Provider */
/* Replace With Your Custom Transport Stream Provider */
auto transportStreamProvider = oatpp::network::client::SimpleTCPConnectionProvider::createShared("httpbin.org", 443 /* port */);

/* Create Secure Connection Provider */
auto connectionProvider = oatpp::mbedtls::client::ConnectionProvider::createShared(config, transportStreamProvider);

/* Get Secure Connection Stream over Custom Transport Stream */
auto connection = connectionProvider->getConnection();
```

**Note:** To use `oatpp-mbedtls` for client connections with custom transport stream you should implement:

- [oatpp::network::ClientConnectionProvider](https://oatpp.io/api/latest/oatpp/network/ConnectionProvider/#clientconnectionprovider).
- [oatpp::data::stream::IOStream](https://oatpp.io/api/latest/oatpp/core/data/stream/Stream/#iostream) - to be returned by `ConnectionProvider`.


## See more

- [oatpp-libressl](https://github.com/oatpp/oatpp-libressl)
