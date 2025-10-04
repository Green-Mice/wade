# Wade

**Keep your socks dry.**

HTTP client-server for Erlang.

---

## Quick Start (HTTP/1.1)

```erlang
%% Start server
wade_app:start(8080).

%% Add route
wade:route(get, "/hello/[name]", fun(Req) ->
    Name = wade:param(Req, name),
    "Hello " ++ Name ++ "!"
end, []).
```

Visit `http://localhost:8080/hello/world`

---

## API

**One function rules them all:**

```erlang
wade:route(Method, Path, Handler, RequiredParams, RequiredHeaders).
```

**Helpers:**
- `wade:param(Req, Key)` - URL parameters
- `wade:query(Req, Key)` - Query string
- `wade:body(Req, Key)` - POST data
- `wade:method(Req)` - HTTP method

---

## Examples

```erlang
%% Simple route
wade:route(get, "/", fun(_) -> "Hello!" end, []).

%% URL parameters
wade:route(get, "/user/[id]", fun(Req) ->
    wade:param(Req, id)
end, []).

%% POST with validation
wade:route(post, "/api", Handler, [name, email]).

%% Any HTTP method
wade:route(any, "/api/[resource]", Handler, []).

%% JSON response
wade:route(get, "/json", fun(_) ->
    {200, "{\"ok\": true}", [{"Content-Type", "application/json"}]}
end, []).
```

No XML. No complex routing. No wet socks.

---

# QUIC / HTTP/3

Wade QUIC is a pure Erlang implementation of QUIC (RFC 9000) and HTTP/3 (RFC 9114).

## Features

- QUIC transport (UDP, packet parsing, connection state machine)
- TLS 1.3 handshake and key derivation
- Streams (bidirectional and unidirectional)
- Flow control per-connection and per-stream
- HTTP/3 frame handling (HEADERS, DATA, SETTINGS)
- QPACK static table support
- Unified API with Wade routes (same as HTTP/1.1)

## Usage

### Start QUIC server

```erlang
wade:start_quic(8443, #{
    certfile => "cert.pem",
    keyfile => "key.pem"
}).

wade:route(get, "/hello", fun(Req) ->
    wade:reply(Req, 200, <<"Hello HTTP/3!">>)
end, []).
```

### Dual mode (HTTP/1.1 + HTTP/3)

```erlang
{ok, #{http := HTTPPid, quic := QUICPid}} =
    wade:start_quic(8080, 8443, #{
        certfile => "cert.pem",
        keyfile => "key.pem"
    }).
```

Routes apply to both protocols.

## Testing

```bash
# Generate test certificate
openssl req -x509 -newkey rsa:2048     -keyout priv/key.pem -out priv/cert.pem     -days 365 -nodes -subj '/CN=localhost'

# Test with curl (HTTP/3)
curl --http3-only -k https://localhost:8443/hello
```

---

## Install

Add to `rebar.config`:

```erlang
{deps, [wade]}.
```

