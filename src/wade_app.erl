%% wade_app.erl
%% OTP Application for Wade HTTP server
-module(wade_app).
-behaviour(application).

-export([start/2, stop/1]).

%% Convenience functions
-export([start/0, start/1, stop/0]).

%% Application callbacks
start(_StartType, _StartArgs) ->
    Port = application:get_env(wade, port, 8080),
    Options = application:get_env(wade, options, []),
    wade_sup:start_link(Port, Options).

stop(_State) ->
    ok.

%% Convenience API
start() ->
    start(8080).

start(Port) ->
    application:ensure_all_started(wade),
    case whereis(wade_sup) of
        undefined ->
            wade_sup:start_link(Port);
        _Pid ->
            {error, already_started}
    end.

stop() ->
    case whereis(wade_sup) of
        undefined -> 
            {error, not_running};
        _Pid ->
            supervisor:terminate_child(wade_sup, wade),
            ok
    end.
