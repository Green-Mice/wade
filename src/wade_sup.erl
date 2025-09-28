%% wade_sup.erl
%% OTP Supervisor for Wade HTTP server
-module(wade_sup).
-behaviour(supervisor).

-export([start_link/1, start_link/2]).
-export([init/1]).

%% Start supervisor
start_link(Port) ->
    start_link(Port, []).

start_link(Port, Options) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Port, Options]).

%% Supervisor callback
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
