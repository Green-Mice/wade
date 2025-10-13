%% @doc Server-Sent Events (SSE) support for Wade.
%% This module provides utilities for creating SSE endpoints and streaming events
%% to clients following the Server-Sent Events specification.
%%
%% SSE is a simple HTTP-based protocol for server-to-client streaming:
%% - Uses standard HTTP (no protocol upgrade needed)
%% - Unidirectional: server → client
%% - Automatic reconnection by browsers
%% - Text-based event format
%%
%% Features:
%%   - Simple event streaming
%%   - Named events with custom types
%%   - Event IDs for resumption
%%   - Keep-alive (heartbeat) support
%%   - Connection management
%%
%% @end

-module(wade_sse).
-behaviour(gen_server).

%% API
-export([
    start_link/2,
    send_event/2,
    send_event/3,
    send_event/4,
    close/1,
    get_client_count/1
]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(sse_state, {
    socket :: port(),
    handler :: fun(),
    event_id = 0 :: non_neg_integer(),
    heartbeat_interval = 30000 :: non_neg_integer(),
    heartbeat_ref :: reference() | undefined
}).

-record(sse_conn, {
    pid :: pid(),
    socket :: port()
}).

%%% =============================================================================
%%% API
%%% =============================================================================

%% @doc Start an SSE connection handler.
%% This is typically called from a Wade route handler after setting up SSE headers.
%% @param Socket The TCP socket for the connection.
%% @param HandlerFun A function that will be called with the SSE connection: fun(#sse_conn{}) -> ok.
%% @return {ok, pid()} | {error, term()}
-spec start_link(port(), fun()) -> {ok, pid()} | {error, term()}.
start_link(Socket, HandlerFun) ->
    gen_server:start_link(?MODULE, {Socket, HandlerFun}, []).

%% @doc Send a simple event with data only.
%% @param Conn #sse_conn{} record or pid().
%% @param Data The event data (binary or string).
%% @return ok
-spec send_event(#sse_conn{} | pid(), binary() | string()) -> ok.
send_event(#sse_conn{pid = Pid}, Data) ->
    send_event(Pid, Data);
send_event(Pid, Data) when is_pid(Pid) ->
    gen_server:cast(Pid, {send_event, undefined, Data, undefined}).

%% @doc Send a named event with data.
%% @param Conn #sse_conn{} record or pid().
%% @param EventType The event type/name (binary or string).
%% @param Data The event data (binary or string).
%% @return ok
-spec send_event(#sse_conn{} | pid(), binary() | string(), binary() | string()) -> ok.
send_event(#sse_conn{pid = Pid}, EventType, Data) ->
    send_event(Pid, EventType, Data);
send_event(Pid, EventType, Data) when is_pid(Pid) ->
    gen_server:cast(Pid, {send_event, EventType, Data, undefined}).

%% @doc Send a complete event with type, data, and ID.
%% @param Conn #sse_conn{} record or pid().
%% @param EventType The event type/name (binary or string or undefined).
%% @param Data The event data (binary or string).
%% @param EventId The event ID (binary or string or undefined).
%% @return ok
-spec send_event(#sse_conn{} | pid(), binary() | string() | undefined, 
                 binary() | string(), binary() | string() | undefined) -> ok.
send_event(#sse_conn{pid = Pid}, EventType, Data, EventId) ->
    send_event(Pid, EventType, Data, EventId);
send_event(Pid, EventType, Data, EventId) when is_pid(Pid) ->
    gen_server:cast(Pid, {send_event, EventType, Data, EventId}).

%% @doc Close the SSE connection gracefully.
%% @param Conn #sse_conn{} record or pid().
%% @return ok
-spec close(#sse_conn{} | pid()) -> ok.
close(#sse_conn{pid = Pid}) ->
    close(Pid);
close(Pid) when is_pid(Pid) ->
    gen_server:cast(Pid, close).

%% @doc Get the number of active SSE clients (for monitoring).
%% This is a placeholder - in production you'd use a registry or ETS.
%% @param _Ref Any reference (unused in this implementation).
%% @return integer()
-spec get_client_count(term()) -> integer().
get_client_count(_Ref) ->
    %% In a real implementation, this would query a registry/ETS table
    length(erlang:processes()).

%%% =============================================================================
%%% gen_server Callbacks
%%% =============================================================================

%% @private
init({Socket, HandlerFun}) ->
    process_flag(trap_exit, true),
    
    %% Send SSE headers
    Headers = [
        "HTTP/1.1 200 OK\r\n",
        "Content-Type: text/event-stream\r\n",
        "Cache-Control: no-cache\r\n",
        "Connection: keep-alive\r\n",
        "Access-Control-Allow-Origin: *\r\n",
        "\r\n"
    ],
    gen_tcp:send(Socket, Headers),
    
    %% Set socket options
    inet:setopts(Socket, [{active, false}, {packet, 0}]),
    
    %% Start heartbeat timer
    HeartbeatRef = erlang:send_after(30000, self(), heartbeat),
    
    %% Call handler with connection info
    Conn = #sse_conn{pid = self(), socket = Socket},
    spawn_link(fun() -> HandlerFun(Conn) end),
    
    {ok, #sse_state{
        socket = Socket,
        handler = HandlerFun,
        heartbeat_ref = HeartbeatRef
    }}.

%% @private
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

%% @private
handle_cast({send_event, EventType, Data, EventId}, State) ->
    case format_sse_event(EventType, Data, EventId) of
        {ok, FormattedEvent} ->
            gen_tcp:send(State#sse_state.socket, FormattedEvent),
            {noreply, State};
        {error, _Reason} ->
            {noreply, State}
    end;

handle_cast(close, State) ->
    {stop, normal, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
handle_info(heartbeat, State) ->
    %% Send a comment as heartbeat to keep connection alive
    gen_tcp:send(State#sse_state.socket, ": heartbeat\n\n"),
    
    %% Schedule next heartbeat
    HeartbeatRef = erlang:send_after(State#sse_state.heartbeat_interval, self(), heartbeat),
    {noreply, State#sse_state{heartbeat_ref = HeartbeatRef}};

handle_info({tcp_closed, _Socket}, State) ->
    {stop, normal, State};

handle_info({tcp_error, _Socket, _Reason}, State) ->
    {stop, normal, State};

handle_info(_Info, State) ->
    {noreply, State}.

%% @private
terminate(_Reason, State) ->
    %% Cancel heartbeat timer
    case State#sse_state.heartbeat_ref of
        undefined -> ok;
        Ref -> erlang:cancel_timer(Ref)
    end,
    
    %% Close socket
    catch gen_tcp:close(State#sse_state.socket),
    ok.

%% @private
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%% =============================================================================
%%% Internal Functions
%%% =============================================================================

%% @private
-spec format_sse_event(binary() | string() | undefined, 
                       binary() | string(), 
                       binary() | string() | undefined) -> 
    {ok, binary()} | {error, term()}.
format_sse_event(EventType, Data, EventId) ->
    try
        %% Convert to binary
        DataBin = to_binary(Data),
        
        %% Build event
        Event = lists:flatten([
            %% Event type (optional)
            case EventType of
                undefined -> [];
                _ -> ["event: ", to_binary(EventType), "\n"]
            end,
            
            %% Data (can be multiline)
            format_data_lines(DataBin),
            
            %% Event ID (optional)
            case EventId of
                undefined -> [];
                _ -> ["id: ", to_binary(EventId), "\n"]
            end,
            
            %% Blank line to end event
            "\n"
        ]),
        
        {ok, iolist_to_binary(Event)}
    catch
        _:Reason ->
            {error, Reason}
    end.

%% @doc Format data field, handling multiline data.
%% Each line must be prefixed with "data: ".
%% @private
-spec format_data_lines(binary()) -> iolist().
format_data_lines(DataBin) ->
    Lines = binary:split(DataBin, <<"\n">>, [global]),
    [["data: ", Line, "\n"] || Line <- Lines].

%% @doc Convert various types to binary.
%% @private
-spec to_binary(binary() | string() | atom() | integer()) -> binary().
to_binary(Val) when is_binary(Val) -> Val;
to_binary(Val) when is_list(Val) -> list_to_binary(Val);
to_binary(Val) when is_atom(Val) -> atom_to_binary(Val, utf8);
to_binary(Val) when is_integer(Val) -> integer_to_binary(Val);
to_binary(Val) -> iolist_to_binary(io_lib:format("~p", [Val])).

