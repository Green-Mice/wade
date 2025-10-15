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
    ws_established = false
}).

%%% =============================================================================
%%% API
%%% =============================================================================

%% @doc Start a WebSocket client connection.
%% Establishes an SSL connection to the specified host and port, then performs
%% the WebSocket upgrade handshake.
%% @param Host The hostname or IP address (string).
%% @param Port The port number (integer).
%% @param Path The WebSocket path (string), e.g., "/ws".
%% @return {ok, Pid} | {error, Reason}
start_link(Host, Port, Path) when is_list(Host); is_integer(Port); is_list(Path) ->
    gen_server:start_link(?MODULE, {Host, Port, Path}, []).

%% @doc Send a WebSocket message to the server.
%% The message is sent as a text frame.
%% @param Pid The client process PID.
%% @param Msg The message to send (binary).
%% @return ok | {error, not_connected}
send_ws(Pid, Msg) when is_binary(Msg) ->
    gen_server:call(Pid, {send_ws, Msg}).

%% @doc Close the WebSocket connection gracefully.
%% @param Pid The client process PID.
%% @return ok
close(Pid) ->
    gen_server:call(Pid, close).

%%% =============================================================================
%%% gen_server callbacks
%%% =============================================================================

%% @private
%% @doc Initialize the WebSocket client.
%% Establishes an SSL connection and sends the WebSocket upgrade request.
init({Host, Port, Path}) ->
    process_flag(trap_exit, true),
    
    % Get the parent process that spawned us
    Parent = case get('$ancestors') of
        [P | _] -> P;
        _ -> self()
    end,
    io:format("WebSocket client starting, parent: ~p~n", [Parent]),
    
    % Ensure certifi is loaded
    application:ensure_all_started(certifi),
    
    % Get CA certs
    CACerts = case catch certifi:cacerts() of
        {'EXIT', _} ->
            io:format("Warning: certifi:cacerts() failed, using system defaults~n"),
            % Try to use system certificates as fallback
            system;
        Certs when is_list(Certs) ->
            Certs;
        _ ->
            io:format("Warning: certifi:cacerts() returned unexpected value, using system defaults~n"),
            system
    end,
    
    % Build SSL options
    SSLOpts = case CACerts of
        system ->
            % Use system certificates
            [
                {active, false},
                binary,
                {packet, 0},
                {verify, verify_none} % Less secure but works without certifi
            ];
        CertList ->
            % Use certifi certificates
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
            
            % Wait for upgrade response
            case ssl:recv(Sock, 0, 10000) of
                {ok, Response} ->
                    case parse_upgrade_response(Response) of
                        ok ->
                            ssl:setopts(Sock, [{active, once}]),
                            io:format("WebSocket upgrade successful to ~s:~p~s~n", [Host, Port, Path]),
                            io:format("Will send messages to parent: ~p~n", [Parent]),
                            {ok, #state{
                                host = Host,
                                port = Port,
                                path = Path,
                                socket = Sock,
                                parent = Parent,
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

%% @private
%% @doc Handle synchronous calls.
handle_call({send_ws, Msg}, _From, State = #state{ws_established = true, socket = Sock}) ->
    Frame = build_ws_frame(1, Msg),
    case ssl:send(Sock, Frame) of
        ok ->
            {reply, ok, State};
        Error ->
            {reply, Error, State}
    end;

handle_call({send_ws, _}, _From, State) ->
    {reply, {error, not_connected}, State};

handle_call(close, _From, State = #state{socket = Sock}) ->
    ssl:close(Sock),
    {stop, normal, ok, State}.

%% @private
%% @doc Handle asynchronous casts.
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
%% @doc Handle info messages.
handle_info({ssl, _Sock, Data}, State) ->
    NewBuffer = <<(State#state.recv_buffer)/binary, Data/binary>>,
    {Frames, Rest} = parse_ws_frames(NewBuffer, []),
    
    % Send frames to parent process
    lists:foreach(fun(Frame) ->
        Type = frame_type(Frame),
        Data2 = frame_data(Frame),
        io:format("Sending to parent ~p: {wade_ws_client, ~p, ~p}~n", [State#state.parent, Type, Data2]),
        State#state.parent ! {wade_ws_client, Type, Data2}
    end, Frames),
    
    ssl:setopts(State#state.socket, [{active, once}]),
    {noreply, State#state{recv_buffer = Rest}};

handle_info({ssl_closed, _Sock}, State) ->
    State#state.parent ! {wade_ws_client, close},
    {stop, normal, State};

handle_info({ssl_error, _Sock, Reason}, State) ->
    io:format("SSL error: ~p~n", [Reason]),
    State#state.parent ! {wade_ws_client, close},
    {stop, Reason, State};

handle_info(Info, State) ->
    io:format("Unknown message received: ~p~n", [Info]),
    {noreply, State}.

%% @private
%% @doc Clean up before termination.
terminate(_Reason, #state{socket = Sock}) ->
    case Sock of
        undefined -> ok;
        _ -> ssl:close(Sock)
    end.

%% @private
%% @doc Handle code changes.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%% =============================================================================
%%% Internal functions
%%% =============================================================================

%% @doc Build the HTTP upgrade request for WebSocket.
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

%% @doc Parse WebSocket upgrade response
parse_upgrade_response(Response) ->
    case binary:match(Response, <<"HTTP/1.1 101">>) of
        nomatch ->
            {error, no_101_response};
        _ ->
            ok
    end.

%% @doc Parse WebSocket frames from buffer
parse_ws_frames(<<>>, Acc) ->
    {lists:reverse(Acc), <<>>};
parse_ws_frames(Buffer, Acc) ->
    case parse_single_ws_frame(Buffer) of
        {ok, Frame, Rest} ->
            parse_ws_frames(Rest, [Frame | Acc]);
        incomplete ->
            {lists:reverse(Acc), Buffer};
        {error, _} ->
            {lists:reverse(Acc), <<>>}
    end.

%% @doc Parse a single WebSocket frame
parse_single_ws_frame(<<Fin:1, _Rsv:3, Opcode:4, Mask:1, PayloadLen:7, Rest/binary>>) ->
    case get_payload_length(PayloadLen, Rest) of
        {ok, Length, Rest2} ->
            case Mask of
                0 ->
                    % Unmasked frame (from server)
                    if
                        byte_size(Rest2) >= Length ->
                            <<Payload:Length/binary, Rest3/binary>> = Rest2,
                            Frame = {Fin, Opcode, Payload},
                            {ok, Frame, Rest3};
                        true ->
                            incomplete
                    end;
                1 ->
                    % Masked frame (from client - shouldn't happen)
                    if
                        byte_size(Rest2) >= 4 + Length ->
                            <<MaskKey:4/binary, MaskedPayload:Length/binary, Rest3/binary>> = Rest2,
                            Payload = unmask_payload(MaskedPayload, MaskKey),
                            Frame = {Fin, Opcode, Payload},
                            {ok, Frame, Rest3};
                        true ->
                            incomplete
                    end
            end;
        incomplete ->
            incomplete
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

frame_data({_Fin, Opcode, Payload}) when Opcode == 1 ->
    binary_to_list(Payload);
frame_data({_Fin, _Opcode, Payload}) ->
    Payload.

%% @doc Build WebSocket frame
build_ws_frame(Opcode, Payload) when is_binary(Payload) ->
    Len = byte_size(Payload),
    MaskKey = crypto:strong_rand_bytes(4),
    MaskedPayload = mask_payload(Payload, MaskKey),
    
    {LenField, ExtLen} = if
        Len < 126 ->
            {Len, <<>>};
        Len < 65536 ->
            {126, <<Len:16>>};
        true ->
            {127, <<Len:64>>}
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

