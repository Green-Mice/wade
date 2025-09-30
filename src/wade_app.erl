%% @doc OTP Application for Wade HTTP server.
%% This module implements the OTP application behaviour for Wade,
%% providing lifecycle management and convenient start/stop functions.
%% 

-module(wade_app).
-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% Convenience functions
-export([start/0, start/1, stop/0]).

%%% =============================================================================
%%% Application callbacks
%%% =============================================================================

%% @private
%% @doc Start the Wade application.
%% Reads configuration from the application environment and starts
%% the Wade supervisor with the configured port and options.
start(_StartType, _StartArgs) ->
    Port = application:get_env(wade, port, 8080),
    Options = application:get_env(wade, options, []),
    wade_sup:start_link(Port, Options).

%% @private
%% @doc Stop the Wade application.
stop(_State) ->
    ok.

%%% =============================================================================
%%% Convenience API
%%% =============================================================================

%% @doc Start Wade with default port 8080.
%% Ensures all dependencies are started and then starts the Wade supervisor.
%% @return {ok, Pid} | {error, already_started} | {error, Reason}
%% @equiv start(8080)
start() ->
    start(8080).

%% @doc Start Wade on a specific port.
%% Ensures all dependencies are started before starting the Wade supervisor.
%% If Wade is already running, returns {error, already_started}.
%% @param Port The port number to listen on.
%% @return {ok, Pid} | {error, already_started} | {error, Reason}
start(Port) ->
    application:ensure_all_started(wade),
    case whereis(wade_sup) of
        undefined ->
            wade_sup:start_link(Port);
        _Pid ->
            {error, already_started}
    end.

%% @doc Stop the Wade server.
%% Terminates the Wade worker child under the supervisor.
%% If Wade is not running, returns {error, not_running}.
%% @return ok | {error, not_running}
stop() ->
    case whereis(wade_sup) of
        undefined ->
            {error, not_running};
        _Pid ->
            supervisor:terminate_child(wade_sup, wade),
            ok
    end.

