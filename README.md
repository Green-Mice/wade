# Wade

**Keep your socks dry.**

HTTP client-server for Erlang.

## Quick Start

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

## Install

Add to `rebar.config`:
```erlang
{deps, [wade]}.
```
