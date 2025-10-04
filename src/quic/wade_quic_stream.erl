%% @doc QUIC stream management
%% Handles individual stream lifecycle, flow control, and data buffering
-module(wade_quic_stream).
-behaviour(gen_server).

-include("wade_quic.hrl").

-export([
    start_link/1,
    send_data/2,
    handle_frame/2,
    update_max_data/2,
    close/1
]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

%% =============================================================================
%% Public API
%% =============================================================================

-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Options) ->
    gen_server:start_link(?MODULE, Options, []).

-spec send_data(pid(), binary()) -> ok | {error, term()}.
send_data(Pid, Data) ->
    gen_server:call(Pid, {send_data, Data}).

-spec handle_frame(pid(), #stream_frame{}) -> ok.
handle_frame(Pid, Frame) ->
    gen_server:cast(Pid, {frame, Frame}).

-spec update_max_data(pid(), integer()) -> ok.
update_max_data(Pid, MaxData) ->
    gen_server:cast(Pid, {update_max_data, MaxData}).

-spec close(pid()) -> ok.
close(Pid) ->
    gen_server:call(Pid, close).

%% =============================================================================
%% gen_server callbacks
%% =============================================================================

init(Options) ->
    StreamID = maps:get(stream_id, Options),
    ConnPid = maps:get(conn_pid, Options),
    Type = maps:get(type, Options),
    Direction = maps:get(direction, Options),
    
    State = #stream_state{
        stream_id = StreamID,
        conn_pid = ConnPid,
        type = Type,
        direction = Direction,
        state = idle,
        max_data_local = 1048576,  % 1MB default
        max_data_remote = 1048576
    },
    
    {ok, State}.

handle_call({send_data, Data}, _From, State) ->
    case can_send(State, byte_size(Data)) of
        true ->
            NewState = queue_send_data(Data, State),
            {reply, ok, NewState};
        false ->
            {reply, {error, flow_control_blocked}, State}
    end;

handle_call(close, _From, State) ->
    %% Send FIN flag with last data
    NewState = send_fin(State),
    {reply, ok, NewState#stream_state{state = half_closed_local}};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({frame, Frame}, State) ->
    NewState = handle_stream_frame(Frame, State),
    {noreply, NewState};

handle_cast({update_max_data, MaxData}, State) ->
    NewState = State#stream_state{max_data_remote = MaxData},
    %% Try to send queued data if we were blocked
    FinalState = try_send_queued(NewState),
    {noreply, FinalState};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% =============================================================================
%% Internal Functions
%% =============================================================================

%% @doc Handle incoming STREAM frame
handle_stream_frame(#stream_frame{offset = Offset, data = Data, fin = Fin}, State) ->
    %% Check if data is in sequence
    case Offset of
        Offset when Offset =:= State#stream_state.recv_offset ->
            %% In-order data, deliver immediately
            NewState = deliver_data(Data, State),
            
            case Fin of
                true ->
                    %% Stream finished by remote
                    handle_remote_fin(NewState);
                false ->
                    NewState#stream_state{recv_offset = Offset + byte_size(Data)}
            end;
        
        Offset when Offset > State#stream_state.recv_offset ->
            %% Out-of-order data, buffer it
            buffer_out_of_order(Offset, Data, Fin, State);
        
        _ ->
            %% Duplicate or old data, ignore
            State
    end.

%% @doc Deliver data to HTTP/3 layer
deliver_data(Data, State) ->
    %% For now, just accumulate in recv_buffer
    %% TODO: Pass to wade_h3 handler
    NewBuffer = <<(State#stream_state.recv_buffer)/binary, Data/binary>>,
    
    %% Update flow control
    NewDataReceived = State#stream_state.data_received + byte_size(Data),
    NewState = State#stream_state{
        recv_buffer = NewBuffer,
        data_received = NewDataReceived
    },
    
    %% Check if we need to send MAX_STREAM_DATA
    case should_send_max_stream_data(NewState) of
        true -> send_max_stream_data_frame(NewState);
        false -> NewState
    end.

%% @doc Buffer out-of-order data
buffer_out_of_order(Offset, _Data, Fin, State) ->
    %% Simple implementation: just store in recv_buffer with offset tracking
    %% TODO: Implement proper gap tracking and reassembly
    io:format("Out-of-order data at offset ~p (expected ~p)~n", 
             [Offset, State#stream_state.recv_offset]),
    State#stream_state{fin_received = Fin}.

%% @doc Handle FIN flag from remote
handle_remote_fin(State) ->
    NewState = State#stream_state{fin_received = true},
    
    case State#stream_state.state of
        half_closed_local ->
            %% Both sides closed, stream is done
            NewState#stream_state{state = closed};
        _ ->
            NewState#stream_state{state = half_closed_remote}
    end.

%% @doc Check if we can send data (flow control)
can_send(State, DataSize) ->
    NewDataSent = State#stream_state.data_sent + DataSize,
    NewDataSent =< State#stream_state.max_data_remote.

%% @doc Queue data for sending
queue_send_data(Data, State) ->
    NewBuffer = <<(State#stream_state.send_buffer)/binary, Data/binary>>,
    NewState = State#stream_state{send_buffer = NewBuffer},
    
    %% Immediately try to send
    try_send_queued(NewState).

%% @doc Try to send queued data
try_send_queued(State) when State#stream_state.send_buffer =:= <<>> ->
    State;
try_send_queued(State) ->
    BufferSize = byte_size(State#stream_state.send_buffer),
    MaxSend = State#stream_state.max_data_remote - State#stream_state.data_sent,
    
    case MaxSend > 0 of
        true ->
            SendSize = min(BufferSize, MaxSend),
            <<DataToSend:SendSize/binary, Remaining/binary>> = State#stream_state.send_buffer,
            
            %% Build STREAM frame
            Frame = #stream_frame{
                stream_id = State#stream_state.stream_id,
                offset = State#stream_state.data_sent,
                length = SendSize,
                fin = false,
                data = DataToSend
            },
            
            %% Send via connection
            send_stream_frame(Frame, State),
            
            State#stream_state{
                send_buffer = Remaining,
                data_sent = State#stream_state.data_sent + SendSize,
                state = open
            };
        false ->
            %% Flow control blocked
            State
    end.

%% @doc Send FIN flag
send_fin(State) ->
    %% Send remaining data with FIN flag
    case try_send_queued(State) of
        #stream_state{send_buffer = <<>>} = NewState ->
            %% All data sent, send FIN
            Frame = #stream_frame{
                stream_id = NewState#stream_state.stream_id,
                offset = NewState#stream_state.data_sent,
                length = 0,
                fin = true,
                data = <<>>
            },
            send_stream_frame(Frame, NewState),
            NewState#stream_state{fin_sent = true};
        NewState ->
            %% Still have data to send, FIN will be sent with last data
            NewState#stream_state{fin_sent = true}
    end.

%% @doc Send STREAM frame via connection
send_stream_frame(Frame, State) ->
    QuicFrame = #quic_frame{type = stream, data = Frame},
    wade_quic_conn:send_frames(State#stream_state.conn_pid, [QuicFrame]).

%% @doc Check if we should send MAX_STREAM_DATA
should_send_max_stream_data(State) ->
    %% Send when we've consumed 50% of the window
    Consumed = State#stream_state.data_received,
    MaxData = State#stream_state.max_data_local,
    Consumed > (MaxData div 2).

%% @doc Send MAX_STREAM_DATA frame
send_max_stream_data_frame(State) ->
    %% Increase window
    NewMaxData = State#stream_state.max_data_local * 2,
    
    Frame = #quic_frame{
        type = max_stream_data,
        data = #{
            stream_id => State#stream_state.stream_id,
            max_data => NewMaxData
        }
    },
    
    wade_quic_conn:send_frames(State#stream_state.conn_pid, [Frame]),
    State#stream_state{max_data_local = NewMaxData}.

