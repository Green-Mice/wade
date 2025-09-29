%% wade.erl
%% Wade - HTTP server library using OTP supervision
-module(wade).
-behaviour(gen_server).

-include_lib("inets/include/httpd.hrl").
-include("wade.hrl").

%% API
-export([
    start_link/1, start_link/2, stop/0,
    route/4, route/5,
    param/2, query/2, query/3, body/2, body/3, method/1,
    request/4
]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3, send_response/2]).

-export([parse_query/1, parse_body/1, url_decode/2, parse_pattern/1, match_pattern/3]).

%% inets callback
-export([do/1]).

-export([upgrade_to_websocket/1, websocket_loop/2, send_ws/2, close_ws/1]).

%% =============================================================================
%% API
%% =============================================================================

start_link(Port) -> start_link(Port, []).
start_link(Port, Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Port, Options], []).

stop() ->
    gen_server:call(?MODULE, stop).

route(Method, Path, Handler, RequiredParams) ->
    route(Method, Path, Handler, RequiredParams, []).

route(Method, Path, Handler, RequiredParams, RequiredHeaders) ->
    gen_server:call(?MODULE, {add_route, Method, Path, Handler, RequiredParams, RequiredHeaders}).

%% Helper functions
query(#req{query = Query}, Key) -> proplists:get_value(Key, Query).
query(#req{query = Query}, Key, Default) -> proplists:get_value(Key, Query, Default).
body(#req{body = Body}, Key) -> proplists:get_value(Key, Body).
body(#req{body = Body}, Key, Default) -> proplists:get_value(Key, Body, Default).
method(#req{method = Method}) -> Method.

param(#req{params = Params, query = Query}, Key) ->
    KeyAtom = case Key of
        KeyA when is_atom(KeyA) -> KeyA;
        KeyS when is_list(KeyS) -> list_to_atom(KeyS)
    end,
    
    case proplists:get_value(KeyAtom, Params) of
        undefined -> proplists:get_value(KeyAtom, Query);
        Value -> Value
    end.

%% =============================================================================
%% gen_server callbacks
%% =============================================================================

init([Port, _Options]) ->
    process_flag(trap_exit, true),
    application:ensure_all_started(inets),
    
    Config = [
        {port, Port},
        {server_name, "wade"},
        {server_root, "."},
        {document_root, "."},
        {modules, [?MODULE]}
    ],
    
    case inets:start(httpd, Config) of
        {ok, HttpdPid} ->
            link(HttpdPid),
            io:format("Wade server started on port ~p (PID: ~p)~n", [Port, HttpdPid]),
            {ok, #state{port = Port, httpd_pid = HttpdPid}};
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call({add_route, Method, Path, Handler, RequiredParams, RequiredHeaders}, _From, State) ->
    Route = #route{
        method = Method,
        pattern = parse_pattern(Path),
        handler = {Handler, RequiredParams, RequiredHeaders}
    },
    NewRoutes = [Route | State#state.routes],
    {reply, ok, State#state{routes = NewRoutes}};

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};

handle_call({get_routes}, _From, State) ->
    {reply, State#state.routes, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'EXIT', Pid, Reason}, #state{httpd_pid = Pid} = State) ->
    io:format("HTTP server crashed (~p), restarting...~n", [Reason]),
    try
        case inets:start(httpd, [
                 {port, State#state.port},
                 {server_name, "wade"},
                 {server_root, "."},
                 {document_root, "."},
                 {modules, [?MODULE]}
             ]) of
            {ok, NewPid} ->
                link(NewPid),
                io:format("HTTP server restarted (PID: ~p)~n", [NewPid]),
                {noreply, State#state{httpd_pid = NewPid}};
            {error, Reason2} ->
                io:format("Failed to restart HTTP server: ~p~n", [Reason2]),
                {stop, Reason2, State}
        end
    catch
        Class:Error ->
            io:format("Exception during restart: ~p:~p~n", [Class, Error]),
            % Optionally stop or continue with same state
            {stop, Error, State}
    end;

handle_info({tcp, Socket, Data}, State) ->
    io:format("Warning: Unexpected TCP data received: ~p~n", [Data]),
    gen_tcp:close(Socket),
    {noreply, State};

handle_info(_Other, State) ->
    {noreply, State}.

terminate(_Reason, #state{httpd_pid = HttpdPid}) ->
    case HttpdPid of
        undefined -> ok;
        Pid -> inets:stop(httpd, Pid)
    end.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% =============================================================================
%% HTTP request handling (inets callback)
%% =============================================================================
do(ModData) ->
    MethodString = string:to_lower(ModData#mod.method),
    Method = case MethodString of
        "get" -> get;
        "post" -> post;
        "put" -> put;
        "delete" -> delete;
        "patch" -> patch;
        "head" -> head;
        "options" -> options;
        _ -> unknown
    end,

    {Path, QueryString} = split_uri(ModData#mod.request_uri),
    Body = parse_body(ModData),

    Req = #req{
        method = Method,
        path = Path,
        query = parse_query(QueryString),
        body = Body,
        headers = ModData#mod.parsed_header
    },

    Routes = gen_server:call(?MODULE, {get_routes}),

    case match_route(Routes, Req) of
        {ok, Handler, PathParams} ->
            ReqWithParams = Req#req{params = PathParams},
            Response = handle_request_safe(Handler, ReqWithParams, ModData),
            send_response(Response, ModData),  % <-- send full HTTP response here
            {stop, normal, ModData#mod.data};
        not_found ->
            send_response({404, "Not Found"}, ModData),  
            {stop, normal, ModData#mod.data}
    end.

%% Safe request handling with process isolation
handle_request_safe({Handler, RequiredParams, RequiredHeaders}, Req, ModData) ->
    Parent = self(),
    WorkerPid = spawn_link(fun() ->
        try
            case validate_params(RequiredParams, Req) of
                ok ->
                    case validate_headers(RequiredHeaders, Req) of
                        ok ->
                            Result = Handler(Req),
                            Parent ! {worker_result, Result};
                        {error, missing_header, Header} ->
                            Parent ! {worker_error, 400, "Missing header: " ++ Header}
                    end;
                {error, missing_param, Param} ->
                    Parent ! {worker_error, 400, "Missing parameter: " ++ Param}
            end
        catch
            Error:Reason:Stack ->
                ErrorMsg = io_lib:format("Handler error: ~p:~p", [Error, Reason]),
                io:format("~s~nStack: ~p~n", [ErrorMsg, Stack]),
                Parent ! {worker_error, 500, lists:flatten(ErrorMsg)}
        end
    end),
    
    receive
        {worker_result, Result} ->
            send_result(Result, ModData);
        {worker_error, Status, Message} ->
            send_response(Status, Message, [], ModData);
        {'EXIT', WorkerPid, Reason} ->
            ErrorMsg = io_lib:format("Worker process died: ~p", [Reason]),
            send_response(500, lists:flatten(ErrorMsg), [], ModData)
    after 30000 ->
        unlink(WorkerPid),
        exit(WorkerPid, timeout),
        send_response(504, "Request timeout", [], ModData)
    end.

%% =============================================================================
%% Route matching and utilities
%% =============================================================================

match_route([], _) -> not_found;
match_route([#route{method = RouteMethod, pattern = Pattern, handler = Handler} | Rest], Req) ->
    MethodMatch = (RouteMethod =:= any) orelse (RouteMethod =:= Req#req.method),
    case MethodMatch of
        true ->
            PathSegments = parse_path(Req#req.path),
            case match_pattern(Pattern, PathSegments, []) of
                {ok, PathParams} -> {ok, Handler, PathParams};
                no_match -> match_route(Rest, Req)
            end;
        false -> match_route(Rest, Req)
    end.

validate_params([], _) -> ok;
validate_params([Param | Rest], Req) ->
    case {param(Req, Param), query(Req, atom_to_list(Param)), body(Req, atom_to_list(Param))} of
        {undefined, undefined, undefined} -> {error, missing_param, atom_to_list(Param)};
        _ -> validate_params(Rest, Req)
    end.

validate_headers([], _) -> ok;
validate_headers([Header | Rest], Req) ->
    case proplists:get_value(Header, Req#req.headers) of
        undefined -> {error, missing_header, Header};
        _ -> validate_headers(Rest, Req)
    end.

send_result(Result, ModData) ->
    case Result of
        Body when is_list(Body) -> send_response(200, Body, [], ModData);
        Body when is_binary(Body) -> send_response(200, binary_to_list(Body), [], ModData);
        {Status, Body} -> send_response(Status, Body, [], ModData);
        {Status, Body, Headers} -> send_response(Status, Body, Headers, ModData);
        _ -> send_response(200, "OK", [], ModData)
    end.

send_response(Status, Body, Headers, ModData) ->
    BodyStr = lists:flatten(io_lib:format("~s", [Body])),
    DefaultHeaders = [{"Content-Type", "text/html; charset=UTF-8"},
                     {"Content-Length", integer_to_list(length(BodyStr))}],
    AllHeaders = merge_headers(DefaultHeaders, Headers),
    
    Response = [
        io_lib:format("HTTP/1.1 ~p ~s\r\n", [Status, status_text(Status)]),
        [io_lib:format("~s: ~s\r\n", [K, V]) || {K, V} <- AllHeaders],
        "\r\n", BodyStr
    ],
    
    gen_tcp:send(ModData#mod.socket, Response).

%% Parsing utilities
split_uri(URI) ->
    case string:split(URI, "?", leading) of
        [Path] -> {Path, ""};
        [Path, Query] -> {Path, Query}
    end.

parse_pattern(Path) ->
    CleanPath = string:trim(Path, leading, "/"),
    case CleanPath of
        "" -> [];
        _ -> [case string:prefix(Part, "[") of
                  nomatch -> {literal, Part};
                  Rest -> {param, list_to_atom(string:trim(Rest, trailing, "]"))}
              end || Part <- string:split(CleanPath, "/", all)]
    end.

parse_path(Path) ->
    CleanPath = string:trim(Path, leading, "/"),
    case CleanPath of "" -> []; _ -> string:split(CleanPath, "/", all) end.

match_pattern([], [], Acc) -> {ok, lists:reverse(Acc)};
match_pattern([{literal, Expected} | PR], [Expected | PathR], Acc) ->
    match_pattern(PR, PathR, Acc);
match_pattern([{param, Name} | PR], [Value | PathR], Acc) ->
    match_pattern(PR, PathR, [{Name, Value} | Acc]);
match_pattern(_, _, _) -> no_match.

parse_query("") -> [];
parse_query(Query) ->
    [case string:split(Pair, "=", leading) of
         [K] -> {list_to_atom(url_decode(K)), ""};
         [K, V] -> {list_to_atom(url_decode(K)), url_decode(V)}
     end || Pair <- string:split(Query, "&", all)].

%% Helper to check content type inline without calling a separate function
is_supported_content_type(ContentType) ->
    SupportedContentTypes = [
        "application/json",
        "application/x-www-form-urlencoded",
        "text/plain",
        "text/html"
    ],
    lists:any(fun(Type) -> string:find(ContentType, Type) =/= nomatch end, SupportedContentTypes).

binary_to_string(Binary) when is_binary(Binary) ->
    binary:bin_to_list(Binary);
binary_to_string(Other) ->
    Other.

parse_body(ModData) when is_tuple(ModData) ->
    case ModData of
        #mod{method=Method, parsed_header=Headers, entity_body=Body} ->
            io:format("Wade: Parsing body for method ~p~n", [Method]),
            MethodUpper = string:to_upper(Method),
            IsBodyMethod = MethodUpper == "POST" orelse MethodUpper == "PUT" orelse MethodUpper == "PATCH",
            if
                IsBodyMethod ->
                    ContentType = proplists:get_value("content-type", Headers, ""),
                    io:format("Wade: Content-Type is ~p~n", [ContentType]),
                    case is_supported_content_type(ContentType) of
                        true ->
                            case string:find(ContentType, "application/x-www-form-urlencoded") of
                                nomatch ->
                                    binary_to_string(Body);
                                _ ->
                                    parse_query(binary_to_string(Body))
                            end;
                        false ->
                            io:format("Wade: Unsupported content-type: ~p, returning empty body~n", [ContentType]),
                            []
                    end;
                true ->
                    io:format("Wade: No body for method ~p~n", [Method]),
                    []
            end;
        {mod, Method, _RequestURI, Headers, Body, _O1, _O2} ->
            io:format("Wade: Parsing body with raw tuple, method ~p~n", [Method]),
            MethodUpper = string:to_upper(Method),
            IsBodyMethod = MethodUpper == "POST" orelse MethodUpper == "PUT" orelse MethodUpper == "PATCH",
            if
                IsBodyMethod ->
                    ContentType = proplists:get_value("content-type", Headers, ""),
                    io:format("Wade: Content-Type is ~p~n", [ContentType]),
                    case is_supported_content_type(ContentType) of
                        true ->
                            case string:find(ContentType, "application/x-www-form-urlencoded") of
                                nomatch ->
                                    binary_to_string(Body);
                                _ ->
                                    parse_query(binary_to_string(Body))
                            end;
                        false ->
                            io:format("Wade: Unsupported content-type: ~p (test tuple), returning empty body~n", [ContentType]),
                            []
                    end;
                true ->
                    io:format("Wade: No body for method ~p (test tuple)~n", [Method]),
                    []
            end;
        _ ->
            io:format("Wade: parse_body called with unexpected argument: ~p~n", [ModData]),
            []
    end.

url_decode(Str) -> url_decode(Str, []).
url_decode([], Acc) -> lists:reverse(Acc);
url_decode([$%, H1, H2 | Rest], Acc) ->
    Char = list_to_integer([H1, H2], 16),
    url_decode(Rest, [Char | Acc]);
url_decode([$+ | Rest], Acc) -> url_decode(Rest, [32 | Acc]);
url_decode([C | Rest], Acc) -> url_decode(Rest, [C | Acc]).

%% Sends an HTTP response over the socket stored in ModData#mod.conn
send_response({StatusCode, Body}, ModData) ->
    % Build the HTTP status line: e.g. "HTTP/1.1 200 OK\r\n"
    StatusLine = io_lib:format("HTTP/1.1 ~p ~s\r\n",
                               [StatusCode, status_text(StatusCode)]),

    % Convert body to binary if it's a list (string)
    BodyBin = case is_list(Body) of
                  true -> list_to_binary(Body);
                  false -> Body
              end,

    ContentLength = byte_size(BodyBin),

    % Prepare HTTP response headers
    Headers = [
        {"content-length", integer_to_list(ContentLength)},
        {"content-type", "application/json"},  % Adjust content-type as appropriate
        {"connection", "close"}
    ],

    % Serialize headers to HTTP header lines
    HeaderLines = lists:map(fun({Key, Value}) ->
                                io_lib:format("~s: ~s\r\n", [Key, Value])
                            end, Headers),

    % Compose full HTTP response iolist: status line, headers, blank line, body
    ResponseIolist = [StatusLine, HeaderLines, "\r\n", BodyBin],

    % Send the serialized response over TCP socket
    gen_tcp:send(ModData#mod.connection, ResponseIolist).

%% Maps HTTP status codes to reason phrases
status_text(200) -> "OK";
status_text(201) -> "Created";
status_text(400) -> "Bad Request";
status_text(404) -> "Not Found";
status_text(405) -> "Method Not Allowed";
status_text(500) -> "Internal Server Error";
status_text(501) -> "Not Implemented";
status_text(504) -> "Gateway Timeout";
status_text(Code) -> integer_to_list(Code).

merge_headers(Defaults, Custom) ->
    lists:foldl(fun({K, V}, Acc) -> lists:keystore(K, 1, Acc, {K, V}) end, Defaults, Custom).

%% Client HTTP (GET, POST, PUT, PATCH, DELETE)
request(Method, URL, Headers, Body) ->
    application:ensure_all_started(inets),
    Verb =
        case Method of
            get -> get;
            post -> post;
            put -> put;
            patch -> patch;
            delete -> delete;
            _ -> get
        end,
    ContentType = case lists:keyfind("content-type", 1, Headers) of
        {_, CType} -> CType;
        false -> "application/json"
    end,
    Hdrs = [{list_to_binary(K), V} || {K, V} <- Headers],
    case Verb of
        get -> 
            httpc:request(get, {URL, Hdrs}, [], []);
        _ ->
            httpc:request(Verb, {URL, Hdrs, ContentType, Body}, [], [])
    end.

%% =============================================================================
%% WebSocket Support
%% =============================================================================

%% Perform the WebSocket handshake and switch protocol
upgrade_to_websocket(ModData) ->
    Headers = ModData#mod.parsed_header,
    case proplists:get_value("sec-websocket-key", Headers) of
        undefined ->
            gen_tcp:send(ModData#mod.socket,
                "HTTP/1.1 400 Bad Request\r\n\r\nMissing Sec-WebSocket-Key");
        Key ->
            Accept = base64:encode(crypto:hash(sha,
                Key ++ "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")),
            Response =
                "HTTP/1.1 101 Switching Protocols\r\n" ++
                "Upgrade: websocket\r\n" ++
                "Connection: Upgrade\r\n" ++
                "Sec-WebSocket-Accept: " ++ Accept ++ "\r\n\r\n",
            gen_tcp:send(ModData#mod.socket, Response),
            {ok, ModData#mod.socket}
    end.

%% Main loop – handles incoming websocket frames
websocket_loop(Socket, HandlerFun) ->
    inet:setopts(Socket, [{active, once}]),
    receive
        {tcp, Socket, Data} ->
            case parse_ws_frame(Data) of
                {text, Msg} ->
                    HandlerFun({text, Msg}),
                    websocket_loop(Socket, HandlerFun);
                {close, _} ->
                    close_ws(Socket);
                {ping, Msg} ->
                    send_ws(Socket, {pong, Msg}),
                    websocket_loop(Socket, HandlerFun);
                _ ->
                    websocket_loop(Socket, HandlerFun)
            end;
        {tcp_closed, Socket} ->
            ok
    end.

%% Send WebSocket frames
send_ws(Socket, {text, Msg}) ->
    Frame = build_ws_frame(1, list_to_binary(Msg)),
    gen_tcp:send(Socket, Frame);
send_ws(Socket, {pong, Msg}) ->
    Frame = build_ws_frame(10, Msg),
    gen_tcp:send(Socket, Frame).

close_ws(Socket) ->
    Frame = build_ws_frame(8, <<>>),
    gen_tcp:send(Socket, Frame),
    gen_tcp:close(Socket).

%% -----------------------------------------------------------------------------
%% Internal frame helpers
%% -----------------------------------------------------------------------------

%% Very basic WebSocket frame parser – supports single-frame text
parse_ws_frame(<<129, Len, Rest/binary>>) when Len =< 125 ->
    <<Msg:Len/binary, _/binary>> = Rest,
    {text, binary_to_list(Msg)};
parse_ws_frame(<<136, _, _/binary>>) ->
    {close, <<>>};
parse_ws_frame(<<137, Len, Msg:Len/binary>>) ->
    {ping, Msg};
parse_ws_frame(<<138, Len, Msg:Len/binary>>) ->
    {pong, Msg};
parse_ws_frame(_) ->
    {unknown, <<>>}.


%% Build a simple, unmasked WebSocket frame for text, close, and pong opcodes
build_ws_frame(1, Payload) when is_binary(Payload) ->
    Len = byte_size(Payload),
    <<129, Len, Payload/binary>>;
build_ws_frame(8, _) ->
    <<136, 0>>;
build_ws_frame(10, Payload) when is_binary(Payload) ->
    Len = byte_size(Payload),
    <<138, Len, Payload/binary>>.

