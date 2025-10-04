%% @doc Wade QUIC transport layer - UDP socket management and connection dispatch
%% Handles incoming QUIC packets and routes them to appropriate connection processes.
-module(wade_quic).
-behaviour(gen_server).

-include("wade_quic.hrl").

-export([
    start_link/2,
    stop/0,
    get_connection/1,
    send_packet/3
]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(quic_state, {
    socket :: gen_udp:socket(),
    port :: integer(),
    connections = #{} :: #{binary() => pid()},  % ConnectionID -> wade_quic_conn Pid
    routes = [] :: list(),
    certfile :: string(),
    keyfile :: string(),
    alpn = [<<"h3">>] :: [binary()]
}).

%% =============================================================================
%% Public API
%% =============================================================================

-spec start_link(integer(), map()) -> {ok, pid()} | {error, term()}.
start_link(Port, Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Port, Options], []).

-spec stop() -> ok.
stop() ->
    gen_server:call(?MODULE, stop).

-spec get_connection(binary()) -> {ok, pid()} | {error, not_found}.
get_connection(ConnID) ->
    gen_server:call(?MODULE, {get_connection, ConnID}).

-spec send_packet(inet:ip_address(), inet:port_number(), binary()) -> ok.
send_packet(IP, Port, Packet) ->
    gen_server:cast(?MODULE, {send_packet, IP, Port, Packet}).

%% =============================================================================
%% gen_server callbacks
%% =============================================================================

init([Port, Options]) ->
    process_flag(trap_exit, true),
    
    %% Open UDP socket with QUIC-specific options
    SocketOpts = [
        binary,
        {active, true},
        {reuseaddr, true},
        {recbuf, 2097152},  % 2MB receive buffer
        {sndbuf, 2097152}   % 2MB send buffer
    ],
    
    case gen_udp:open(Port, SocketOpts) of
        {ok, Socket} ->
            io:format("Wade QUIC server started on UDP port ~p~n", [Port]),
            {ok, #quic_state{
                socket = Socket,
                port = Port,
                certfile = maps:get(certfile, Options, "cert.pem"),
                keyfile = maps:get(keyfile, Options, "key.pem"),
                routes = maps:get(routes, Options, []),
                alpn = maps:get(alpn, Options, [<<"h3">>])
            }};
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call({get_connection, ConnID}, _From, State) ->
    case maps:get(ConnID, State#quic_state.connections, undefined) of
        undefined -> {reply, {error, not_found}, State};
        Pid -> {reply, {ok, Pid}, State}
    end;

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({send_packet, IP, Port, Packet}, State) ->
    gen_udp:send(State#quic_state.socket, IP, Port, Packet),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({udp, Socket, IP, Port, Packet}, State) when Socket =:= State#quic_state.socket ->
    %% Parse QUIC packet header to extract Connection ID
    case wade_quic_packet:parse_header(Packet) of
        {ok, #quic_header{dest_conn_id = DestCID, packet_type = Type} = Header, Payload} ->
            NewState = route_packet(IP, Port, Header, Payload, Type, DestCID, State),
            {noreply, NewState};
        
        {error, version_negotiation, SupportedVersions} ->
            %% Send Version Negotiation packet
            send_version_negotiation(State#quic_state.socket, IP, Port, Packet, SupportedVersions),
            {noreply, State};
        
        {error, Reason} ->
            io:format("Failed to parse QUIC packet: ~p~n", [Reason]),
            {noreply, State}
    end;

handle_info({'EXIT', Pid, Reason}, State) ->
    %% Connection process died, remove it
    io:format("Connection process ~p exited: ~p~n", [Pid, Reason]),
    NewConnections = maps:filter(
        fun(_, ConnPid) -> ConnPid =/= Pid end,
        State#quic_state.connections
    ),
    {noreply, State#quic_state{connections = NewConnections}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    gen_udp:close(State#quic_state.socket),
    %% Gracefully close all connections
    maps:foreach(
        fun(_, Pid) -> 
            catch wade_quic_conn:close(Pid)
        end,
        State#quic_state.connections
    ),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% =============================================================================
%% Internal Functions
%% =============================================================================

%% @doc Route packet to appropriate connection or create new one
route_packet(IP, Port, Header, Payload, initial, DestCID, State) ->
    %% Initial packet - new connection
    case maps:get(DestCID, State#quic_state.connections, undefined) of
        undefined ->
            %% Create new connection
            ConnOpts = #{
                remote_ip => IP,
                remote_port => Port,
                dest_conn_id => DestCID,
                certfile => State#quic_state.certfile,
                keyfile => State#quic_state.keyfile,
                alpn => State#quic_state.alpn,
                routes => State#quic_state.routes
            },
            
            case wade_quic_conn:start_link(ConnOpts) of
                {ok, ConnPid} ->
                    link(ConnPid),
                    wade_quic_conn:handle_packet(ConnPid, Header, Payload),
                    State#quic_state{
                        connections = maps:put(DestCID, ConnPid, State#quic_state.connections)
                    };
                {error, Reason} ->
                    io:format("Failed to create connection: ~p~n", [Reason]),
                    State
            end;
        
        ConnPid ->
            %% Connection exists, forward packet
            wade_quic_conn:handle_packet(ConnPid, Header, Payload),
            State
    end;

route_packet(_IP, _Port, Header, Payload, _Type, DestCID, State) ->
    %% Handshake, 0-RTT, or 1-RTT packet - forward to existing connection
    case maps:get(DestCID, State#quic_state.connections, undefined) of
        undefined ->
            io:format("Received packet for unknown connection: ~p~n", [DestCID]),
            State;
        ConnPid ->
            wade_quic_conn:handle_packet(ConnPid, Header, Payload),
            State
    end.

%% @doc Send Version Negotiation packet
send_version_negotiation(Socket, IP, Port, OriginalPacket, SupportedVersions) ->
    case wade_quic_packet:build_version_negotiation(OriginalPacket, SupportedVersions) of
        {ok, VNPacket} ->
            gen_udp:send(Socket, IP, Port, VNPacket);
        {error, _Reason} ->
            ok
    end.
