%% @doc OTP Supervisor for Wade HTTP server.
%% Manages the Wade server process with automatic restart capabilities.
%% Uses a one_for_one strategy with configurable restart limits.

-module(wade_sup).
-behaviour(supervisor).

%% API
-export([start_link/1, start_link/2]).

%% Supervisor callbacks
-export([init/1]).

%%% =============================================================================
%%% API
%%% =============================================================================

%% @doc Start the Wade supervisor with default options.
%% @param Port The port number for the HTTP server.
%% @return {ok, Pid} | {error, Reason}
%% @equiv start_link(Port, [])
start_link(Port) ->
    start_link(Port, []).

%% @doc Start the Wade supervisor with options.
%% Creates a supervisor that will manage the Wade HTTP server process.
%% The supervisor uses a one_for_one strategy, meaning if the Wade server
%% crashes, only that process is restarted (not affecting other potential children).
%% @param Port The port number for the HTTP server.
%% @param Options Additional server options (reserved for future use).
%% @return {ok, Pid} | {error, Reason}
start_link(Port, Options) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Port, Options]).

%%% =============================================================================
%%% Supervisor callbacks
%%% =============================================================================

%% @private
%% @doc Initialize the supervisor.
%% Sets up the child specification for the Wade server and configures
%% the supervision strategy with restart limits (max 10 restarts in 60 seconds).
init([Port, Options]) ->
    %% Child specification for wade gen_server
    WadeChild = #{
        id => wade,
        start => {wade, start_link, [Port, Options]},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [wade]
    },
    %% Supervisor strategy: one_for_one with restart limits
    SupFlags = #{
        strategy => one_for_one,
        intensity => 10,    %% Max 10 restarts
        period => 60        %% In 60 seconds
    },
    {ok, {SupFlags, [WadeChild]}}.

