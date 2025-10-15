-module(wade_ws_client).
-behaviour(gen_server).

%% API
-export([start_link/3, send_ws/2, close/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {
    host,
    port,
    path,
    socket,
    parent,
    recv_buffer = <<>>,
    recv_pid = undefined,
    ws_established = false
}).

%%% =============================================================================
%%% API
%%% =============================================================================

start_link(Host, Port, Path) when is_list(Host); is_integer(Port); is_list(Path) ->
    gen_server:start_link(?MODULE, {Host, Port, Path}, []).

send_ws(Pid, {text, Msg}) when is_binary(Msg) ->
    gen_server:call(Pid, {send_ws, Msg});
send_ws(Pid, Msg) when is_binary(Msg) ->
    gen_server:call(Pid, {send_ws, Msg}).

close(Pid) ->
    gen_server:call(Pid, close).

%%% =============================================================================
%%% gen_server callbacks
%%% =============================================================================

init({Host, Port, Path}) ->
    process_flag(trap_exit, true),

    Parent = case get('$ancestors') of
        [P | _] when is_pid(P) -> P;
        [P | _] when is_atom(P) ->
            case whereis(P) of
                undefined -> self();
                Pid -> Pid
            end;
        _ -> self()
    end,
    io:format("WebSocket client starting, parent PID: ~p~n", [Parent]),

    application:ensure_all_started(certifi),

    CACerts = case catch certifi:cacerts() of
        {'EXIT', _} ->
            io:format("Warning: certifi:cacerts() failed~n"),
            system;
        Certs when is_list(Certs) -> Certs;
        _ ->
            io:format("Warning: certifi returned unexpected value~n"),
            system
    end,

    SSLOpts = case CACerts of
        system ->
            [
                {active, false},
                binary,
                {packet, 0},
                {verify, verify_none}
            ];
        CertList ->
            [
                {active, false},
                binary,
                {packet, 0},
                {verify, verify_peer},
                {cacerts, CertList},
                {server_name_indication, Host},
                {customize_hostname_check, [
                    {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
                ]}
            ]
    end,

    case ssl:connect(Host, Port, SSLOpts) of
        {ok, Sock} ->
            Key16 = crypto:strong_rand_bytes(16),
            Key = base64:encode(Key16),
            UpgradeReq = build_upgrade_request(Host, Port, Path, Key),
            ok = ssl:send(Sock, UpgradeReq),

            case ssl:recv(Sock, 0, 10000) of
                {ok, Response} ->
                    case parse_upgrade_response(Response) of
                        ok ->
                            io:format("WebSocket upgrade successful to ~s:~p~s~n", [Host, Port, Path]),
                            io:format("Will send messages to parent: ~p~n", [Parent]),

                            RecvPid = spawn_link(fun() -> receiver_loop(Sock, self(), <<>>) end),

                            {ok, #state{
                                host = Host,
                                port = Port,
                                path = Path,
                                socket = Sock,
                                parent = Parent,
                                recv_pid = RecvPid,
                                ws_established = true
                            }};
                        {error, Reason} ->
                            ssl:close(Sock),
                            {stop, {upgrade_failed, Reason}}
                    end;
                {error, Reason} ->
                    ssl:close(Sock),
                    {stop, {recv_failed, Reason}}
            end;
        Error ->
            {stop, Error}
    end.

receiver_loop(Sock, Parent, Buffer) ->
    case ssl:recv(Sock, 4096, infinity) of
        {ok, Data} ->
            NewBuffer = <<Buffer/binary, Data/binary>>,
            {Frames, Rest} = parse_ws_frames(NewBuffer, []),
            %% Send frames individually to parent immediately
            lists:foreach(fun(Frame) ->
                Type = frame_type(Frame),
                Data2 = frame_data(Frame),
                Parent ! {wade_ws_client, Type, Data2}
            end, Frames),
            receiver_loop(Sock, Parent, Rest);
        {error, closed} ->
            Parent ! {wade_ws_client, close},
            exit(normal);
        {error, Reason} ->
            Parent ! {wade_ws_client, close},
            exit(Reason)
    end.

handle_call({send_ws, Msg}, _From, State = #state{ws_established = true, socket = Sock}) ->
    Frame = build_ws_frame(1, Msg),
    case ssl:send(Sock, Frame) of
        ok -> {reply, ok, State};
        Error -> {reply, Error, State}
    end;

handle_call({send_ws, _}, _From, State) ->
    {reply, {error, not_connected}, State};

handle_call(close, _From, State = #state{socket = Sock}) ->
    ssl:close(Sock),
    {stop, normal, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'EXIT', Pid, Reason}, State = #state{recv_pid = Pid}) ->
    io:format("[wade_ws_client] Receiver process exited: ~p~n", [Reason]),
    %% Notify parent about close, cleanup state, stop gracefully
    State#state.parent ! {wade_ws_client, close},
    {stop, normal, State};

handle_info({'EXIT', _OtherPid, _Reason}, State) ->
    %% Ignore other exits
    {noreply, State};

handle_info(Info, State) ->
    io:format("[wade_ws_client] Unknown info: ~p~n", [Info]),
    {noreply, State}.

terminate(_Reason, #state{socket = Sock}) ->
    case Sock of
        undefined -> ok;
        _ -> ssl:close(Sock)
    end.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%% =============================================================================
%%% Internal functions
%%% =============================================================================

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

parse_upgrade_response(Response) ->
    case binary:match(Response, <<"HTTP/1.1 101">>) of
        nomatch -> {error, no_101_response};
        _ -> ok
    end.

parse_ws_frames(<<>>, Acc) ->
    {lists:reverse(Acc), <<>>};
parse_ws_frames(Buffer, Acc) ->
    case parse_single_ws_frame(Buffer) of
        {ok, Frame, Rest} -> parse_ws_frames(Rest, [Frame | Acc]);
        incomplete -> {lists:reverse(Acc), Buffer};
        {error, _} -> {lists:reverse(Acc), <<>>}
    end.

parse_single_ws_frame(<<Fin:1, _Rsv:3, Opcode:4, _Mask:1, PayloadLen:7, Rest/binary>>) ->
    case get_payload_length(PayloadLen, Rest) of
        {ok, Length, Rest2} ->
            if byte_size(Rest2) >= 4 + Length ->
                <<MaskKey:4/binary, MaskedPayload:Length/binary, Rest3/binary>> = Rest2,
                Payload = unmask_payload(MaskedPayload, MaskKey),
                Frame = {Fin, Opcode, Payload},
                {ok, Frame, Rest3};
               true -> incomplete
            end;
        incomplete -> incomplete
    end;
parse_single_ws_frame(_) ->
    incomplete.

get_payload_length(126, <<Length:16, Rest/binary>>) ->
    {ok, Length, Rest};
get_payload_length(127, <<Length:64, Rest/binary>>) ->
    {ok, Length, Rest};
get_payload_length(Len, Rest) when Len < 126 ->
    {ok, Len, Rest};
get_payload_length(_, _) ->
    incomplete.

unmask_payload(Payload, MaskKey) ->
    unmask_payload(Payload, MaskKey, 0, <<>>).

unmask_payload(<<>>, _MaskKey, _Idx, Acc) ->
    Acc;
unmask_payload(<<Byte, Rest/binary>>, MaskKey, Idx, Acc) ->
    MaskByte = binary:at(MaskKey, Idx rem 4),
    UnmaskedByte = Byte bxor MaskByte,
    unmask_payload(Rest, MaskKey, Idx + 1, <<Acc/binary, UnmaskedByte>>).

frame_type({_Fin, 1, _Payload}) -> text;
frame_type({_Fin, 2, _Payload}) -> binary;
frame_type({_Fin, 8, _Payload}) -> close;
frame_type({_Fin, 9, _Payload}) -> ping;
frame_type({_Fin, 10, _Payload}) -> pong;
frame_type(_) -> unknown.

frame_data({_Fin, _Opcode, Payload}) ->
    Payload.

build_ws_frame(Opcode, Payload) when is_binary(Payload) ->
    Len = byte_size(Payload),
    MaskKey = crypto:strong_rand_bytes(4),
    MaskedPayload = mask_payload(Payload, MaskKey),

    {LenField, ExtLen} = if
        Len < 126 -> {Len, <<>>};
        Len < 65536 -> {126, <<Len:16>>};
        true -> {127, <<Len:64>>}
    end,

    <<1:1, 0:3, Opcode:4, 1:1, LenField:7, ExtLen/binary, MaskKey/binary, MaskedPayload/binary>>.

mask_payload(Payload, MaskKey) ->
    mask_payload(Payload, MaskKey, 0, <<>>).

mask_payload(<<>>, _MaskKey, _Idx, Acc) ->
    Acc;
mask_payload(<<Byte, Rest/binary>>, MaskKey, Idx, Acc) ->
    MaskByte = binary:at(MaskKey, Idx rem 4),
    MaskedByte = Byte bxor MaskByte,
    mask_payload(Rest, MaskKey, Idx + 1, <<Acc/binary, MaskedByte>>).

