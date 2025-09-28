-module(basic_api).
-export([start/0]).

start() ->
    wade_app:start(),
    wade:route(get, "/hello/[name]", fun(Req) ->
        Name = wade:param(Req, name),
        {200, "\{\"message\":\"Hello " ++ Name ++ "!\"}", [{"Content-Type", "application/json"}]}
    end, []),
    wade:route(get, "/api/users", fun(_Req) ->
        {200, "\{\"users\":[\"Bob\", \"Charlie\", \"Alice\"]\}", [{"Content-Type", "application/json"}]}
    end, []),
    wade:route(post, "/api/users", fun(Req) ->
        Name = wade:body(Req, name),
        {200, "\{\"message\":\"Hello " ++ Name ++ "!\"}", [{"Content-Type", "application/json"}]}
    end, []).
