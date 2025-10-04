%% @doc HTTP/3 protocol implementation.
%% Maps HTTP semantics onto QUIC streams.
-module(wade_h3).
-behaviour(gen_server).

%% Include headers
-include("wade.hrl").
-include("wade_quic.hrl").

%% HTTP/3 frame types
-define(H3_FRAME_DATA,            16#00).
-define(H3_FRAME_HEADERS,         16#01).
-define(H3_FRAME_CANCEL_PUSH,     16#03).
-define(H3_FRAME_SETTINGS,        16#04).
-define(H3_FRAME_PUSH_PROMISE,    16#05).
-define(H3_FRAME_GOAWAY,          16#07).
-define(H3_FRAME_MAX_PUSH_ID,     16#0d).

%% HTTP/3 settings
-define(H3_SETTING_QPACK_MAX_TABLE_CAPACITY,    16#01).
-define(H3_SETTING_MAX_FIELD_SECTION_SIZE,      16#06).
-define(H3_SETTING_QPACK_BLOCKED_STREAMS,       16#07).

%% Public API
-export([
    start_link/1,
    handle_stream_data/3,
    send_response/5
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

%% @type h3_state()
-record(h3_state, {
    conn_pid :: pid(),
    control_stream_id :: integer() | undefined,
    qpack_encoder_stream_id :: integer() | undefined,
    qpack_decoder_stream_id :: integer() | undefined,
    requests = #{} :: #{integer() => map()},  % StreamID -> Request state
    settings = #{} :: map(),
    routes = [] :: list()
}).

%%=============================================================================
%% Public API
%%=============================================================================

%% @doc Start the HTTP/3 server.
%% @param Options Map containing connection PID and routes.
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Options) ->
    gen_server:start_link(?MODULE, Options, []).

%% @doc Handle incoming stream data.
%% @param Pid Server PID.
%% @param StreamID QUIC stream ID.
%% @param Data Binary data received.
-spec handle_stream_data(pid(), integer(), binary()) -> ok.
handle_stream_data(Pid, StreamID, Data) ->
    gen_server:cast(Pid, {stream_data, StreamID, Data}).

%% @doc Send an HTTP/3 response.
%% @param Pid Server PID.
%% @param StreamID QUIC stream ID.
%% @param StatusCode HTTP status code.
%% @param Headers List of {binary(), binary()} tuples.
%% @param Body Binary response body.
-spec send_response(pid(), integer(), integer(), [{binary(), binary()}], binary()) -> ok.
send_response(Pid, StreamID, StatusCode, Headers, Body) ->
    gen_server:call(Pid, {send_response, StreamID, StatusCode, Headers, Body}).

%%=============================================================================
%% gen_server callbacks
%%=============================================================================

%% @doc Initialize the server state.
init(Options) ->
    State = #h3_state{
        conn_pid = maps:get(conn_pid, Options),
        routes = maps:get(routes, Options, []),
        settings = #{
            ?H3_SETTING_QPACK_MAX_TABLE_CAPACITY => 0,  % No dynamic table for now
            ?H3_SETTING_MAX_FIELD_SECTION_SIZE => 16384,
            ?H3_SETTING_QPACK_BLOCKED_STREAMS => 0
        }
    },
    %% Create control stream and send SETTINGS
    {ok, ControlStreamID} = wade_quic_conn:create_stream(State#h3_state.conn_pid, uni),
    send_settings(ControlStreamID, State),
    {ok, State#h3_state{control_stream_id = ControlStreamID}}.

%% @doc Handle synchronous calls (e.g., send_response).
handle_call({send_response, StreamID, StatusCode, Headers, Body}, _From, State) ->
    Result = do_send_response(StreamID, StatusCode, Headers, Body, State),
    {reply, Result, State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

%% @doc Handle asynchronous messages (e.g., stream data).
handle_cast({stream_data, StreamID, Data}, State) ->
    NewState = process_stream_data(StreamID, Data, State),
    {noreply, NewState};
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @doc Handle other messages (e.g., timeouts).
handle_info(_Info, State) ->
    {noreply, State}.

%% @doc Clean up on termination.
terminate(_Reason, _State) ->
    ok.

%% @doc Handle code upgrades.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%=============================================================================
%% Internal functions
%%=============================================================================

%% @doc Process data from a stream.
process_stream_data(StreamID, Data, State) ->
    %% Get or create request state
    ReqState = maps:get(StreamID, State#h3_state.requests, #{
        buffer => <<>>,
        headers_received => false,
        headers => [],
        body => <<>>
    }),
    NewBuffer = <<(maps:get(buffer, ReqState))/binary, Data/binary>>,
    case maps:get(headers_received, ReqState) of
        false ->
            %% Try to parse HEADERS frame
            case parse_h3_frame(NewBuffer) of
                {ok, {?H3_FRAME_HEADERS, HeadersData}, Rest} ->
                    %% Decode QPACK headers
                    case wade_h3_qpack:decode(HeadersData) of
                        {ok, Headers} ->
                            %% Headers complete, check for body
                            NewReqState = ReqState#{
                                headers_received => true,
                                headers => Headers,
                                buffer => Rest
                            },
                            %% If there's remaining data, it's the body
                            FinalReqState = process_body_data(Rest, NewReqState, State),
                            Requests = maps:put(StreamID, FinalReqState, State#h3_state.requests),
                            State#h3_state{requests = Requests};
                        {error, _Reason} ->
                            %% QPACK decode error
                            State
                    end;
                {incomplete} ->
                    %% Need more data
                    Requests = maps:put(StreamID, ReqState#{buffer => NewBuffer},
                                       State#h3_state.requests),
                    State#h3_state{requests = Requests};
                {error, _} ->
                    State
            end;
        true ->
            %% Headers already received, this is body data
            case parse_h3_frame(NewBuffer) of
                {ok, {?H3_FRAME_DATA, BodyData}, Rest} ->
                    ExistingBody = maps:get(body, ReqState),
                    NewReqState = ReqState#{
                        body => <<ExistingBody/binary, BodyData/binary>>,
                        buffer => Rest
                    },
                    %% Check if request is complete (FIN flag would be set at QUIC layer)
                    %% For now, assume we have the complete body
                    case Rest of
                        <<>> ->
                            %% Request complete, dispatch to handler
                            dispatch_request(StreamID, NewReqState, State);
                        _ ->
                            Requests = maps:put(StreamID, NewReqState, State#h3_state.requests),
                            State#h3_state{requests = Requests}
                    end;
                {incomplete} ->
                    Requests = maps:put(StreamID, ReqState#{buffer => NewBuffer},
                                       State#h3_state.requests),
                    State#h3_state{requests = Requests};
                {error, _} ->
                    State
            end
    end.

%% @doc Process body data frames.
process_body_data(<<>>, ReqState, _State) ->
    ReqState;
process_body_data(Data, ReqState, State) ->
    case parse_h3_frame(Data) of
        {ok, {?H3_FRAME_DATA, BodyData}, Rest} ->
            ExistingBody = maps:get(body, ReqState),
            NewReqState = ReqState#{
                body => <<ExistingBody/binary, BodyData/binary>>,
                buffer => Rest
            },
            process_body_data(Rest, NewReqState, State);
        _ ->
            ReqState#{buffer => Data}
    end.

%% @doc Dispatch request to appropriate handler.
dispatch_request(StreamID, ReqState, State) ->
    Headers = maps:get(headers, ReqState),
    Body = maps:get(body, ReqState),
    %% Extract HTTP method, path, etc. from headers
    Method = proplists:get_value(<<":method">>, Headers, <<"GET">>),
    Path = proplists:get_value(<<":path">>, Headers, <<"/">>),
    io:format("HTTP/3 Request: ~s ~s~n", [Method, Path]),
    %% Build Wade request record
    WadeReq = #req{
        method = method_to_atom(Method),
        path = binary_to_list(Path),
        query = [],  % TODO: Parse query string from path
        body = parse_body_for_wade(Body),
        headers = headers_to_proplist(Headers),
        params = []
    },
    %% Match against routes
    Routes = State#h3_state.routes,
    case match_route(Routes, WadeReq) of
        {ok, Handler, PathParams} ->
            ReqWithParams = WadeReq#req{params = PathParams},
            Response = Handler(ReqWithParams),
            %% Send response
            {Status, RespHeaders, RespBody} = normalize_response(Response),
            do_send_response(StreamID, Status, RespHeaders, RespBody, State);
        not_found ->
            do_send_response(StreamID, 404, [], <<"Not Found">>, State)
    end,
    %% Remove request from state
    Requests = maps:remove(StreamID, State#h3_state.requests),
    State#h3_state{requests = Requests}.

%% @doc Send HTTP/3 response.
do_send_response(StreamID, StatusCode, Headers, Body, State) ->
    %% Build response headers
    StatusBin = integer_to_binary(StatusCode),
    RespHeaders = [
        {<<":status">>, StatusBin}
        | normalize_headers(Headers)
    ],
    %% Encode headers with QPACK
    {ok, EncodedHeaders} = wade_h3_qpack:encode(RespHeaders),
    %% Build HEADERS frame
    HeadersFrame = build_h3_frame(?H3_FRAME_HEADERS, EncodedHeaders),
    %% Build DATA frame
    DataFrame = build_h3_frame(?H3_FRAME_DATA, Body),
    %% Send both frames
    FrameData = <<HeadersFrame/binary, DataFrame/binary>>,
    wade_quic_conn:send_data(State#h3_state.conn_pid, StreamID, FrameData),
    ok.

%% @doc Send SETTINGS frame on control stream.
send_settings(StreamID, State) ->
    %% Build SETTINGS frame
    SettingsData = maps:fold(
        fun(Key, Value, Acc) ->
            KeyVarInt = wade_quic_packet:encode_variable_length(Key),
            ValueVarInt = wade_quic_packet:encode_variable_length(Value),
            <<Acc/binary, KeyVarInt/binary, ValueVarInt/binary>>
        end,
        <<>>,
        State#h3_state.settings
    ),
    %% Prepend stream type (0x00 for control stream)
    StreamType = wade_quic_packet:encode_variable_length(16#00),
    SettingsFrame = build_h3_frame(?H3_FRAME_SETTINGS, SettingsData),
    wade_quic_conn:send_data(State#h3_state.conn_pid, StreamID,
                             <<StreamType/binary, SettingsFrame/binary>>).

%% @doc Match request against routes.
match_route([{PathPattern, Handler} | Rest], Req) ->
    case wade_router:match(PathPattern, Req#req.path) of
        {ok, PathParams} ->
            {ok, Handler, PathParams};
        nomatch ->
            match_route(Rest, Req)
    end;
match_route([], _Req) ->
    not_found.

%%=============================================================================
%% HTTP/3 Frame Parsing
%%=============================================================================

%% @doc Parse HTTP/3 frame.
parse_h3_frame(Data) ->
    case wade_quic_packet:decode_variable_length(Data) of
        {Type, Rest1} ->
            case wade_quic_packet:decode_variable_length(Rest1) of
                {Length, Rest2} when byte_size(Rest2) >= Length ->
                    <<Payload:Length/binary, Rest3/binary>> = Rest2,
                    {ok, {Type, Payload}, Rest3};
                {_Length, _Rest2} ->
                    {incomplete};
                _ ->
                    {error, invalid_frame}
            end;
        _ ->
            {error, invalid_frame}
    end.

%% @doc Build HTTP/3 frame.
build_h3_frame(Type, Payload) ->
    TypeVarInt = wade_quic_packet:encode_variable_length(Type),
    LengthVarInt = wade_quic_packet:encode_variable_length(byte_size(Payload)),
    <<TypeVarInt/binary, LengthVarInt/binary, Payload/binary>>.

%%=============================================================================
%% Helper Functions
%%=============================================================================

%% @doc Convert HTTP method binary to atom.
method_to_atom(<<"GET">>)    -> get;
method_to_atom(<<"POST">>)   -> post;
method_to_atom(<<"PUT">>)    -> put;
method_to_atom(<<"DELETE">>) -> delete;
method_to_atom(<<"PATCH">>)  -> patch;
method_to_atom(<<"HEAD">>)   -> head;
method_to_atom(<<"OPTIONS">>)-> options;
method_to_atom(_)           -> get.

%% @doc Parse body for Wade request.
parse_body_for_wade(<<>>) -> [];
parse_body_for_wade(Body) ->
    %% Assume JSON for now
    try jsone:decode(Body) of
        Map when is_map(Map) ->
            maps:fold(
                fun(K, V, Acc) ->
                    Key = binary_to_atom(K, utf8),
                    [{Key, V} | Acc]
                end,
                [],
                Map
            )
    catch
        _:_ -> []
    end.

%% @doc Convert headers to proplist.
headers_to_proplist(Headers) ->
    [{binary_to_list(K), binary_to_list(V)} || {K, V} <- Headers,
     not binary:match(K, <<":">>) =/= nomatch].

%% @doc Normalize response headers.
normalize_headers(Headers) when is_list(Headers) ->
    [{list_to_binary(K), list_to_binary(V)} || {K, V} <- Headers];
normalize_headers(Headers) when is_map(Headers) ->
    maps:fold(
        fun(K, V, Acc) ->
            KB = if is_binary(K) -> K; is_list(K) -> list_to_binary(K); true -> atom_to_binary(K) end,
            VB = if is_binary(V) -> V; is_list(V) -> list_to_binary(V); true -> term_to_binary(V) end,
            [{KB, VB} | Acc]
        end,
        [],
        Headers
    ).

%% @doc Normalize response format.
normalize_response(#req{reply_status = Status, reply_headers = Headers, reply_body = Body})
  when Status =/= undefined ->
    {Status, maps:to_list(Headers), Body};
normalize_response({Status, Body}) ->
    {Status, [], Body};
normalize_response({Status, Headers, Body}) ->
    {Status, Headers, Body};
normalize_response(_) ->
    {500, [], <<"Internal Server Error">>}.

