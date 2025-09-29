-module(wade_ws_client).
-behaviour(gen_server).

-include("wade_ws_client.hrl").

-export([start_link/3, send_ws/2, close/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).


%%% API

start_link(Host, Port, Path) when is_list(Host); is_integer(Port); is_list(Path) ->
    gen_server:start_link(?MODULE, {Host, Port, Path}, []).

send_ws(Pid, Msg) when is_binary(Msg) ->
    gen_server:call(Pid, {send_ws, Msg}).

close(Pid) ->
    gen_server:call(Pid, close).

%%% gen_server callbacks

init({Host, Port, Path}) ->
    process_flag(trap_exit, true),
    case ssl:connect(Host, Port, [{active, false}, binary, {packet, 0}]) of
        {ok, Sock} ->
            Key16 = crypto:strong_rand_bytes(16),
            Key = base64:encode(Key16),
            UpgradeReq = build_upgrade_request(Host, Port, Path, Key),
            ok = ssl:send(Sock, UpgradeReq),
            ssl:setopts(Sock, [{active, once}]),
            {ok, #state{host=Host, port=Port, path=Path, socket=Sock, parent=self()}};
        Error ->
            {stop, Error}
    end.

handle_call({send_ws, Msg}, _From, State = #state{ws_established=true, socket=Sock}) ->
    Frame = wade:build_ws_frame(1, Msg),
    ssl:send(Sock, Frame),
    {reply, ok, State};
handle_call({send_ws, _}, _From, State) ->
    {reply, {error, not_connected}, State};

handle_call(close, _From, State = #state{socket=Sock}) ->
    ssl:close(Sock),
    {stop, normal, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({ssl, _Sock, Data}, State) ->
    NewBuffer = <<(State#state.recv_buffer)/binary, Data/binary>>,
    case wade:parse_ws_frame(NewBuffer) of
        {ok, Frames, Rest} ->
            lists:foreach(fun
                ({text, Msg}) -> State#state.parent ! {wade_ws_client, text, Msg};
                ({close, _}) -> State#state.parent ! {wade_ws_client, close};
                ({ping, Msg}) -> State#state.parent ! {wade_ws_client, ping, Msg};
                ({pong, Msg}) -> State#state.parent ! {wade_ws_client, pong, Msg};
                (_) -> ok
            end, Frames),
            ssl:setopts(State#state.socket, [{active, once}]),
            {noreply, State#state{recv_buffer=Rest, ws_established=true}};
        incomplete ->
            ssl:setopts(State#state.socket, [{active, once}]),
            {noreply, State#state{recv_buffer=NewBuffer}}
    end;

handle_info({ssl_closed, _Sock}, State) ->
    {stop, normal, State};

handle_info({ssl_error, _Sock, Reason}, State) ->
    {stop, Reason, State};

handle_info(Info, State) ->
    io:format("Unknown message received: ~p~n", [Info]),
    {noreply, State}.

terminate(_Reason, _State = #state{socket=Sock}) ->
    case Sock of 
        undefined -> ok;
        _ -> ssl:close(Sock)
    end.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%% Helpers

build_upgrade_request(Host, Port, Path, Key) ->
    ReqString = io_lib:format(
        "GET ~s HTTP/1.1\r\n" ++
        "Host: ~s:~p\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: ~s\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n",
        [Path, Host, Port, Key]),
    list_to_binary(ReqString).

