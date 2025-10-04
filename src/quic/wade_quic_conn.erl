%% @doc QUIC connection state machine
%% Manages connection lifecycle, packet processing, and stream multiplexing
-module(wade_quic_conn).
-behaviour(gen_statem).

-include("wade_quic.hrl").

-export([
    start_link/1,
    handle_packet/3,
    create_stream/2,
    close/1,
    send_data/3
]).

-export([
    init/1,
    callback_mode/0,
    initial/3,
    handshake/3,
    established/3,
    closing/3,
    draining/3,
    terminate/3,
    code_change/4
]).

%% =============================================================================
%% Public API
%% =============================================================================

-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Options) ->
    gen_statem:start_link(?MODULE, Options, []).

-spec handle_packet(pid(), #quic_header{}, binary()) -> ok.
handle_packet(Pid, Header, Payload) ->
    gen_statem:cast(Pid, {packet, Header, Payload}).

-spec create_stream(pid(), bidi | uni) -> {ok, integer()} | {error, term()}.
create_stream(Pid, Type) ->
    gen_statem:call(Pid, {create_stream, Type}).

-spec close(pid()) -> ok.
close(Pid) ->
    gen_statem:call(Pid, close).

-spec send_data(pid(), integer(), binary()) -> ok | {error, term()}.
send_data(Pid, StreamID, Data) ->
    gen_statem:call(Pid, {send_data, StreamID, Data}).

%% =============================================================================
%% gen_statem callbacks
%% =============================================================================

callback_mode() -> state_functions.

init(Options) ->
    process_flag(trap_exit, true),
    
    %% Generate connection IDs
    LocalCID = crypto:strong_rand_bytes(8),
    DestCID = maps:get(dest_conn_id, Options),
    
    %% Initialize crypto state
    CryptoState = wade_quic_crypto:init_server(LocalCID, DestCID),
    
    State = #conn_state{
        role = server,
        state = initial,
        remote_ip = maps:get(remote_ip, Options),
        remote_port = maps:get(remote_port, Options),
        local_conn_ids = [LocalCID],
        remote_conn_ids = [DestCID],
        dest_conn_id = DestCID,
        src_conn_id = LocalCID,
        crypto_state = CryptoState,
        routes = maps:get(routes, Options, []),
        certfile = maps:get(certfile, Options),
        keyfile = maps:get(keyfile, Options),
        alpn = maps:get(alpn, Options, [<<"h3">>]),
        last_activity = erlang:system_time(millisecond)
    },
    
    %% Start idle timeout timer
    {ok, initial, State, [{state_timeout, State#conn_state.idle_timeout, idle_timeout}]}.

%% =============================================================================
%% State: initial
%% =============================================================================

initial(cast, {packet, Header, Payload}, State) ->
    case Header#quic_header.packet_type of
        initial ->
            handle_initial_packet(Header, Payload, State);
        _ ->
            io:format("Unexpected packet type in initial state: ~p~n", 
                     [Header#quic_header.packet_type]),
            {keep_state, State}
    end;

initial(EventType, Event, State) ->
    handle_common_event(EventType, Event, State).

%% =============================================================================
%% State: handshake
%% =============================================================================

handshake(cast, {packet, Header, Payload}, State) ->
    case Header#quic_header.packet_type of
        handshake ->
            handle_handshake_packet(Header, Payload, State);
        initial ->
            %% Client might retransmit Initial packets
            handle_initial_packet(Header, Payload, State);
        _ ->
            io:format("Unexpected packet type in handshake state: ~p~n",
                     [Header#quic_header.packet_type]),
            {keep_state, State}
    end;

handshake(EventType, Event, State) ->
    handle_common_event(EventType, Event, State).

%% =============================================================================
%% State: established
%% =============================================================================

established(cast, {packet, Header, Payload}, State) ->
    case Header#quic_header.packet_type of
        one_rtt ->
            handle_1rtt_packet(Header, Payload, State);
        _ ->
            io:format("Unexpected packet type in established state: ~p~n",
                     [Header#quic_header.packet_type]),
            {keep_state, State}
    end;

established({call, From}, {create_stream, Type}, State) ->
    {StreamID, NewState} = allocate_stream_id(Type, State),
    
    %% Start stream process
    case wade_quic_stream:start_link(#{
        stream_id => StreamID,
        conn_pid => self(),
        type => Type,
        direction => local
    }) of
        {ok, StreamPid} ->
            Streams = maps:put(StreamID, StreamPid, State#conn_state.streams),
            {keep_state, NewState#conn_state{streams = Streams}, 
             [{reply, From, {ok, StreamID}}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

established({call, From}, {send_data, StreamID, Data}, State) ->
    case maps:get(StreamID, State#conn_state.streams, undefined) of
        undefined ->
            {keep_state, State, [{reply, From, {error, stream_not_found}}]};
        StreamPid ->
            Result = wade_quic_stream:send_data(StreamPid, Data),
            {keep_state, State, [{reply, From, Result}]}
    end;

established(EventType, Event, State) ->
    handle_common_event(EventType, Event, State).

%% =============================================================================
%% State: closing
%% =============================================================================

closing(state_timeout, close_complete, State) ->
    {stop, normal, State};

closing(EventType, Event, State) ->
    handle_common_event(EventType, Event, State).

%% =============================================================================
%% State: draining
%% =============================================================================

draining(state_timeout, drain_complete, State) ->
    {stop, normal, State};

draining(_EventType, _Event, State) ->
    %% Ignore all events in draining state
    {keep_state, State}.

%% =============================================================================
%% Common event handlers
%% =============================================================================

handle_common_event({call, From}, close, State) ->
    %% Send CONNECTION_CLOSE frame
    CloseFrame = #quic_frame{
        type = connection_close,
        data = #connection_close_frame{
            error_code = ?ERROR_NO_ERROR,
            frame_type = undefined,
            reason = <<"Connection closed">>
        }
    },
    send_frames([CloseFrame], State),
    
    {next_state, closing, State, [
        {reply, From, ok},
        {state_timeout, 1000, close_complete}
    ]};

handle_common_event(state_timeout, idle_timeout, State) ->
    io:format("Connection idle timeout~n"),
    {stop, idle_timeout, State};

handle_common_event(info, {'EXIT', Pid, Reason}, State) ->
    %% Stream process died
    io:format("Stream process ~p exited: ~p~n", [Pid, Reason]),
    Streams = maps:filter(fun(_, P) -> P =/= Pid end, State#conn_state.streams),
    {keep_state, State#conn_state{streams = Streams}};

handle_common_event(_EventType, _Event, State) ->
    {keep_state, State}.

terminate(_Reason, _State, _Data) ->
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%% =============================================================================
%% Packet Handlers
%% =============================================================================

%% @doc Handle Initial packet
handle_initial_packet(_Header, Payload, State) ->
    %% Unprotect packet (for now, skip actual decryption)
    case wade_quic_packet:unprotect_packet(
        Payload, 
        get_crypto_keys(initial, State), 
        State#conn_state.largest_received_packet
    ) of
        {ok, DecryptedPayload, _PacketNumber} ->
            %% Parse frames
            case wade_quic_frame:parse_all(DecryptedPayload) of
                {ok, Frames} ->
                    process_frames(Frames, State),
                    
                    %% Check if we have CRYPTO data to process
                    CryptoFrames = [F || #quic_frame{type = crypto} = F <- Frames],
                    
                    case CryptoFrames of
                        [] ->
                            {keep_state, update_activity(State)};
                        _ ->
                            %% Process TLS handshake
                            NewState = process_crypto_frames(CryptoFrames, initial, State),
                            
                            %% Send Initial response with server hello
                            send_initial_response(NewState),
                            
                            %% Transition to handshake state
                            {next_state, handshake, update_activity(NewState)}
                    end;
                {error, Reason} ->
                    io:format("Failed to parse frames: ~p~n", [Reason]),
                    {keep_state, State}
            end;
        {error, Reason} ->
            io:format("Failed to unprotect packet: ~p~n", [Reason]),
            {keep_state, State}
    end.

%% @doc Handle Handshake packet
handle_handshake_packet(_Header, Payload, State) ->
    case wade_quic_packet:unprotect_packet(
        Payload,
        get_crypto_keys(handshake, State),
        State#conn_state.largest_received_packet
    ) of
        {ok, DecryptedPayload, _PacketNumber} ->
            case wade_quic_frame:parse_all(DecryptedPayload) of
                {ok, Frames} ->
                    process_frames(Frames, State),
                    
                    CryptoFrames = [F || #quic_frame{type = crypto} = F <- Frames],
                    
                    case CryptoFrames of
                        [] ->
                            {keep_state, update_activity(State)};
                        _ ->
                            NewState = process_crypto_frames(CryptoFrames, handshake, State),
                            
                            %% Check if handshake is complete
                            case is_handshake_complete(NewState) of
                                true ->
                                    %% Send HANDSHAKE_DONE frame
                                    send_handshake_done(NewState),
                                    
                                    io:format("QUIC handshake complete~n"),
                                    {next_state, established, update_activity(NewState)};
                                false ->
                                    {keep_state, update_activity(NewState)}
                            end
                    end;
                {error, Reason} ->
                    io:format("Failed to parse handshake frames: ~p~n", [Reason]),
                    {keep_state, State}
            end;
        {error, Reason} ->
            io:format("Failed to unprotect handshake packet: ~p~n", [Reason]),
            {keep_state, State}
    end.

%% @doc Handle 1-RTT packet (application data)
handle_1rtt_packet(_Header, Payload, State) ->
    case wade_quic_packet:unprotect_packet(
        Payload,
        get_crypto_keys(application, State),
        State#conn_state.largest_received_packet
    ) of
        {ok, DecryptedPayload, _PacketNumber} ->
            case wade_quic_frame:parse_all(DecryptedPayload) of
                {ok, Frames} ->
                    NewState = process_frames(Frames, State),
                    
                    %% Send ACK if needed
                    case should_send_ack(NewState) of
                        true -> send_ack(NewState);
                        false -> ok
                    end,
                    
                    {keep_state, update_activity(NewState)};
                {error, Reason} ->
                    io:format("Failed to parse 1-RTT frames: ~p~n", [Reason]),
                    {keep_state, State}
            end;
        {error, Reason} ->
            io:format("Failed to unprotect 1-RTT packet: ~p~n", [Reason]),
            {keep_state, State}
    end.

%% =============================================================================
%% Frame Processing
%% =============================================================================

%% @doc Process all frames in a packet
process_frames(Frames, State) ->
    lists:foldl(fun process_frame/2, State, Frames).

%% @doc Process individual frame
process_frame(#quic_frame{type = padding}, State) ->
    State;

process_frame(#quic_frame{type = ping}, State) ->
    %% Ping is ACK-eliciting, handled by ACK logic
    State;

process_frame(#quic_frame{type = ack, data = AckFrame}, State) ->
    %% Process ACK frame - update loss detection
    handle_ack_frame(AckFrame, State);

process_frame(#quic_frame{type = crypto}, State) ->
    %% CRYPTO frames are handled separately
    State;

process_frame(#quic_frame{type = stream, data = StreamFrame}, State) ->
    handle_stream_frame(StreamFrame, State);

process_frame(#quic_frame{type = max_data, data = MaxData}, State) ->
    State#conn_state{max_data_remote = MaxData};

process_frame(#quic_frame{type = max_stream_data, data = #{stream_id := SID, max_data := MaxData}}, State) ->
    case maps:get(SID, State#conn_state.streams, undefined) of
        undefined -> State;
        StreamPid ->
            wade_quic_stream:update_max_data(StreamPid, MaxData),
            State
    end;

process_frame(#quic_frame{type = max_streams_bidi, data = MaxStreams}, State) ->
    State#conn_state{max_streams_bidi = MaxStreams};

process_frame(#quic_frame{type = max_streams_uni, data = MaxStreams}, State) ->
    State#conn_state{max_streams_uni = MaxStreams};

process_frame(#quic_frame{type = connection_close, data = CloseFrame}, State) ->
    io:format("Connection close received: ~p~n", [CloseFrame]),
    %% Transition to draining state
    gen_statem:cast(self(), transition_to_draining),
    State;

process_frame(#quic_frame{type = handshake_done}, State) ->
    %% Client should not send HANDSHAKE_DONE (server-only frame)
    io:format("Received HANDSHAKE_DONE from client (protocol violation)~n"),
    State;

process_frame(Frame, State) ->
    io:format("Unhandled frame type: ~p~n", [Frame#quic_frame.type]),
    State.

%% @doc Handle STREAM frame
handle_stream_frame(#stream_frame{stream_id = StreamID} = Frame, State) ->
    case maps:get(StreamID, State#conn_state.streams, undefined) of
        undefined ->
            %% New remote-initiated stream
            case create_remote_stream(StreamID, State) of
                {ok, StreamPid, NewState} ->
                    wade_quic_stream:handle_frame(StreamPid, Frame),
                    NewState;
                {error, _Reason} ->
                    %% Send STREAM_LIMIT_ERROR or ignore
                    State
            end;
        StreamPid ->
            %% Existing stream
            wade_quic_stream:handle_frame(StreamPid, Frame),
            State
    end.

%% @doc Handle ACK frame
handle_ack_frame(#ack_frame{largest_acked = LargestAcked, ack_ranges = Ranges}, State) ->
    %% Remove acked packets from sent list
    AckedPackets = expand_ack_ranges(Ranges, LargestAcked),
    NewAcked = lists:usort(State#conn_state.acked_packets ++ AckedPackets),
    
    %% Update congestion control, loss detection, etc.
    State#conn_state{acked_packets = NewAcked}.

%% @doc Expand ACK ranges to list of packet numbers
expand_ack_ranges(Ranges, LargestAcked) ->
    lists:flatmap(
        fun({First, Last}) ->
            lists:seq(Last, First)
        end,
        Ranges
    ) ++ [LargestAcked].

%% =============================================================================
%% Crypto Processing
%% =============================================================================

%% @doc Process CRYPTO frames for TLS handshake
process_crypto_frames(CryptoFrames, Level, State) ->
    %% Collect all crypto data
    CryptoData = lists:foldl(
        fun(#quic_frame{data = #crypto_frame{data = Data}}, Acc) ->
            <<Acc/binary, Data/binary>>
        end,
        <<>>,
        CryptoFrames
    ),
    
    %% Process TLS handshake messages
    case wade_quic_crypto:process_handshake(CryptoData, Level, State#conn_state.crypto_state) of
        {ok, NewCryptoState, ResponseData} ->
            %% Send response if needed
            case ResponseData of
                <<>> -> ok;
                _ -> send_crypto_data(ResponseData, Level, State)
            end,
            State#conn_state{crypto_state = NewCryptoState};
        {error, Reason} ->
            io:format("TLS handshake error: ~p~n", [Reason]),
            State
    end.

%% @doc Check if TLS handshake is complete
is_handshake_complete(State) ->
    wade_quic_crypto:is_complete(State#conn_state.crypto_state).

%% =============================================================================
%% Sending Functions
%% =============================================================================

%% @doc Send Initial response packet
send_initial_response(State) ->
    %% Build server hello CRYPTO data
    CryptoData = wade_quic_crypto:build_server_hello(State#conn_state.crypto_state),
    
    CryptoFrame = #quic_frame{
        type = crypto,
        data = #crypto_frame{
            offset = 0,
            length = byte_size(CryptoData),
            data = CryptoData
        }
    },
    
    AckFrame = build_ack_frame(State),
    
    case wade_quic_packet:build_initial(
        State#conn_state.dest_conn_id,
        State#conn_state.src_conn_id,
        <<>>,  % Empty token
        [AckFrame, CryptoFrame]
    ) of
        {ok, Packet} ->
            send_packet(Packet, State);
        {error, Reason} ->
            io:format("Failed to build Initial packet: ~p~n", [Reason])
    end.

%% @doc Send HANDSHAKE_DONE frame
send_handshake_done(State) ->
    Frame = #quic_frame{type = handshake_done, data = undefined},
    send_frames([Frame], State).

%% @doc Send ACK frame
send_ack(State) ->
    AckFrame = build_ack_frame(State),
    send_frames([AckFrame], State).

%% @doc Send frames in 1-RTT packet
send_frames(Frames, State) ->
    case wade_quic_packet:build_1rtt(
        State#conn_state.dest_conn_id,
        State#conn_state.next_packet_number,
        Frames
    ) of
        {ok, Packet} ->
            %% Protect packet
            {ok, ProtectedPacket} = wade_quic_packet:protect_packet(
                Packet,
                get_crypto_keys(application, State),
                State#conn_state.next_packet_number
            ),
            send_packet(ProtectedPacket, State),
            
            %% Increment packet number
            State#conn_state{next_packet_number = State#conn_state.next_packet_number + 1};
        {error, Reason} ->
            io:format("Failed to build packet: ~p~n", [Reason]),
            State
    end.

%% @doc Send CRYPTO data in appropriate packet type
send_crypto_data(Data, Level, State) ->
    CryptoFrame = #quic_frame{
        type = crypto,
        data = #crypto_frame{
            offset = 0,
            length = byte_size(Data),
            data = Data
        }
    },
    
    case Level of
        initial ->
            send_initial_response(State);
        handshake ->
            case wade_quic_packet:build_handshake(
                State#conn_state.dest_conn_id,
                State#conn_state.src_conn_id,
                [CryptoFrame]
            ) of
                {ok, Packet} -> send_packet(Packet, State);
                {error, Reason} -> 
                    io:format("Failed to build handshake packet: ~p~n", [Reason])
            end;
        application ->
            send_frames([CryptoFrame], State)
    end.

%% @doc Actually send packet via UDP
send_packet(Packet, State) ->
    wade_quic:send_packet(
        State#conn_state.remote_ip,
        State#conn_state.remote_port,
        Packet
    ).

%% =============================================================================
%% Helper Functions
%% =============================================================================

%% @doc Build ACK frame from connection state
build_ack_frame(State) ->
    LargestReceived = State#conn_state.largest_received_packet,
    #quic_frame{
        type = ack,
        data = #ack_frame{
            largest_acked = LargestReceived,
            ack_delay = 0,
            ack_ranges = [{LargestReceived, LargestReceived}],
            ecn_counts = undefined
        }
    }.

%% @doc Allocate new stream ID
allocate_stream_id(bidi, State) ->
    StreamID = State#conn_state.next_stream_id_bidi,
    NewState = State#conn_state{next_stream_id_bidi = StreamID + 4},
    {StreamID, NewState};
allocate_stream_id(uni, State) ->
    StreamID = State#conn_state.next_stream_id_uni,
    NewState = State#conn_state{next_stream_id_uni = StreamID + 4},
    {StreamID, NewState}.

%% @doc Create remote-initiated stream
create_remote_stream(StreamID, State) ->
    case wade_quic_stream:start_link(#{
        stream_id => StreamID,
        conn_pid => self(),
        type => if (StreamID band 2) =:= 0 -> bidi; true -> uni end,
        direction => remote
    }) of
        {ok, StreamPid} ->
            Streams = maps:put(StreamID, StreamPid, State#conn_state.streams),
            {ok, StreamPid, State#conn_state{streams = Streams}};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Get crypto keys for encryption level
get_crypto_keys(Level, State) ->
    maps:get(Level, State#conn_state.crypto_state, undefined).

%% @doc Update last activity timestamp
update_activity(State) ->
    State#conn_state{last_activity = erlang:system_time(millisecond)}.

%% @doc Check if we should send ACK
should_send_ack(State) ->
    %% Simple heuristic: send ACK every packet for now
    %% TODO: Implement proper ACK delay logic
    State#conn_state.largest_received_packet >= 0.
