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
%% Internal Network Helpers (Wrappers for inets/gen_tcp)
%% =============================================================================

%% @doc Start the HTTP server using inets.
%%      Wraps inets:start(httpd, Config) to handle errors gracefully.
%% @param Config The inets HTTPD configuration.
%% @return {ok, Pid} | {error, Reason}
start_http_server(Config) ->
    try
        {ok, Pid} = inets:start(httpd, Config),
        {ok, Pid}
    catch
        error:Reason ->
            {error, Reason}
    end.

%% @doc Stop the HTTP server using inets.
%%      Wraps inets:stop(httpd, Pid) to handle errors gracefully.
%% @param Pid The PID of the HTTP server.
%% @return ok | {error, Reason}
stop_http_server(Pid) ->
    try
        inets:stop(httpd, Pid),
        ok
    catch
        error:Reason ->
            {error, Reason}
    end.

%% @doc Send data over a TCP socket.
%%      Wraps gen_tcp:send/2 to handle errors gracefully.
%% @param Socket The TCP socket.
%% @param Data The data to send (iolist or binary).
%% @return ok | {error, Reason}
send_tcp_data(Socket, Data) ->
    try
        gen_tcp:send(Socket, Data),
        ok
    catch
        error:Reason ->
            {error, Reason}
    end.

%% @doc Set options for a TCP socket.
%%      Wraps inet:setopts/2 to handle errors gracefully.
%% @param Socket The TCP socket.
%% @param Opts The list of options to set.
%% @return ok | {error, Reason}
set_tcp_opts(Socket, Opts) ->
    try
        inet:setopts(Socket, Opts),
        ok
    catch
        error:Reason ->
            {error, Reason}
    end.

%% @doc Perform an HTTP request (GET, POST, etc.).
%%      Wraps httpc:request/4 to handle errors gracefully.
%% @param Method The HTTP method (get, post, put, etc.).
%% @param URL The target URL.
%% @param Headers The request headers.
%% @param Body The request body.
%% @return ok | {error, Reason}
perform_http_request(Method, URL, Headers, Body) ->
    try
        ContentType = case lists:keyfind("content-type", 1, Headers) of
            {_, CType} -> CType;
            false -> "application/json"
        end,
        Hdrs = [{list_to_binary(K), V} || {K, V} <- Headers],
        Verb = case Method of
            get -> get;
            post -> post;
            put -> put;
            patch -> patch;
            delete -> delete;
            _ -> get
        end,
        httpc:request(Verb, {URL, Hdrs, ContentType, Body}, [], []),
        ok
    catch
        error:Reason ->
            {error, Reason}
    end.

%% =============================================================================
%% API
%% =============================================================================

%% @doc Start the Wade HTTP server on the specified port.
%% @param Port The port number to listen on.
%% @return {ok, Pid} | {error, Reason}
%% @equiv start_link(Port, [])
start_link(Port) -> start_link(Port, []).

%% @doc Start the Wade HTTP server with options.
%% @param Port The port number to listen on.
%% @param Options Additional server options (reserved for future use).
%% @return {ok, Pid} | {error, Reason}
start_link(Port, Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Port, Options], []).

%% @doc Stop the Wade HTTP server.
%% @return ok
stop() ->
    gen_server:call(?MODULE, stop).

%% @doc Register a route with required parameters.
%% @param Method HTTP method atom (get, post, put, delete, patch, any).
%% @param Path Route pattern with parameters in brackets, e.g., "/users/[id]".
%% @param Handler Function that takes a `#req{}' record and returns a response.
%% @param RequiredParams List of required parameter atoms.
%% @return ok
%% @equiv route(Method, Path, Handler, RequiredParams, [])
route(Method, Path, Handler, RequiredParams) ->
    route(Method, Path, Handler, RequiredParams, []).

%% @doc Register a route with required parameters and headers.
%% @param Method HTTP method atom (get, post, put, delete, patch, any).
%% @param Path Route pattern with parameters in brackets, e.g., "/users/[id]".
%% @param Handler Function that takes a `#req{}' record and returns a response.
%% @param RequiredParams List of required parameter atoms.
%% @param RequiredHeaders List of required header strings.
%% @return ok
route(Method, Path, Handler, RequiredParams, RequiredHeaders) ->
    gen_server:call(?MODULE, {add_route, Method, Path, Handler, RequiredParams, RequiredHeaders}).

%% @doc Get a query parameter value.
%% @param Req The request record.
%% @param Key The parameter key (atom or string).
%% @return Value | undefined
query(#req{query = Query}, Key) -> proplists:get_value(Key, Query).

%% @doc Get a query parameter value with default.
%% @param Req The request record.
%% @param Key The parameter key (atom or string).
%% @param Default The default value if key is not found.
%% @return Value | Default
query(#req{query = Query}, Key, Default) -> proplists:get_value(Key, Query, Default).

%% @doc Get a body parameter value.
%% @param Req The request record.
%% @param Key The parameter key (string).
%% @return Value | undefined
body(#req{body = Body}, Key) -> proplists:get_value(Key, Body).

%% @doc Get a body parameter value with default.
%% @param Req The request record.
%% @param Key The parameter key (string).
%% @param Default The default value if key is not found.
%% @return Value | Default
body(#req{body = Body}, Key, Default) -> proplists:get_value(Key, Body, Default).

%% @doc Get the HTTP method of the request.
%% @param Req The request record.
%% @return HTTP method atom (get, post, put, delete, patch, etc.)
method(#req{method = Method}) -> Method.

%% @doc Get a parameter from path params or query string.
%% Path parameters take precedence over query parameters.
%% @param Req The request record.
%% @param Key The parameter key (atom or string).
%% @return Value | undefined
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

%% @private
%% @doc Initialize the Wade server.
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
    case start_http_server(Config) of
        {ok, HttpdPid} ->
            link(HttpdPid),
            io:format("Wade server started on port ~p (PID: ~p)~n", [Port, HttpdPid]),
            {ok, #state{port = Port, httpd_pid = HttpdPid}};
        {error, Reason} ->
            {stop, Reason}
    end.

%% @private
%% @doc Handle synchronous calls.
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

%% @private
%% @doc Handle asynchronous casts.
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
%% @doc Handle info messages.
handle_info({'EXIT', Pid, Reason}, #state{httpd_pid = Pid} = State) ->
    io:format("HTTP server crashed (~p), restarting...~n", [Reason]),
    try
        case start_http_server([
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
            {stop, Error, State}
    end;

%% Silently handle unexpected TCP data (e.g., client sends data after connection close)
handle_info({tcp, Socket, _Data}, State) ->
    gen_tcp:close(Socket),
    {noreply, State};

handle_info(_Other, State) ->
    {noreply, State}.

%% @private
%% @doc Clean up before termination.
terminate(_Reason, #state{httpd_pid = HttpdPid}) ->
    case HttpdPid of
        undefined -> ok;
        Pid -> stop_http_server(Pid)
    end.

%% @private
%% @doc Handle code changes.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% =============================================================================
%% HTTP request handling (inets callback)
%% =============================================================================

%% @doc Main inets callback for handling HTTP requests.
%% @param ModData The inets mod record containing request information.
%% @return {stop, normal, Data}
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
            send_response(Response, ModData),
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

%% @doc Send an HTTP response over the socket.
%%      Uses send_tcp_data/2 to handle errors gracefully.
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
    send_tcp_data(ModData#mod.socket, Response).

%% @doc Send an HTTP response (simple form).
%% @param StatusCode HTTP status code integer.
%% @param Body Response body (string or binary).
%% @param ModData The inets mod record.
%% @return ok | {error, Reason}
send_response({StatusCode, Body}, ModData) ->
    BodyBin = case is_list(Body) of
                  true -> list_to_binary(Body);
                  false -> Body
              end,
    ContentLength = byte_size(BodyBin),
    Headers = [
        {"content-length", integer_to_list(ContentLength)},
        {"content-type", "application/json"},
        {"connection", "close"}
    ],
    HeaderLines = lists:map(fun({Key, Value}) ->
                                io_lib:format("~s: ~s\r\n", [Key, Value])
                            end, Headers),
    ResponseIolist = [
        io_lib:format("HTTP/1.1 ~p ~s\r\n", [StatusCode, status_text(StatusCode)]),
        HeaderLines, "\r\n", BodyBin
    ],
    send_tcp_data(ModData#mod.socket, ResponseIolist).

%% =============================================================================
%% WebSocket Support
%% =============================================================================

%% @doc Upgrade an HTTP connection to WebSocket.
%% Performs the WebSocket handshake according to RFC 6455.
%% @param ModData The inets mod record containing the upgrade request.
%% @return {ok, Socket} | error
upgrade_to_websocket(ModData) ->
    Headers = ModData#mod.parsed_header,
    case proplists:get_value("sec-websocket-key", Headers) of
        undefined ->
            send_tcp_data(ModData#mod.socket,
                "HTTP/1.1 400 Bad Request\r\n\r\nMissing Sec-WebSocket-Key");
        Key ->
            Accept = base64:encode(crypto:hash(sha,
                Key ++ "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")),
            Response =
                "HTTP/1.1 101 Switching Protocols\r\n" ++
                "Upgrade: websocket\r\n" ++
                "Connection: Upgrade\r\n" ++
                "Sec-WebSocket-Accept: " ++ Accept ++ "\r\n\r\n",
            send_tcp_data(ModData#mod.socket, Response),
            {ok, ModData#mod.socket}
    end.

%% @doc WebSocket event loop.
%% Receives and processes WebSocket frames, calling HandlerFun for each message.
%% @param Socket The TCP socket for the WebSocket connection.
%% @param HandlerFun Function called with {text, Message} for each frame.
%% @return ok
websocket_loop(Socket, HandlerFun) ->
    set_tcp_opts(Socket, [{active, once}]),
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

%% @doc Send a WebSocket frame.
%% @param Socket The TCP socket.
%% @param Message {text, String} or {pong, Binary}.
%% @return ok | {error, Reason}
send_ws(Socket, {text, Msg}) ->
    Frame = build_ws_frame(1, list_to_binary(Msg)),
    send_tcp_data(Socket, Frame);

send_ws(Socket, {pong, Msg}) ->
    Frame = build_ws_frame(10, Msg),
    send_tcp_data(Socket, Frame).

%% @doc Close a WebSocket connection gracefully.
%% @param Socket The TCP socket.
%% @return ok | {error, Reason}
close_ws(Socket) ->
    Frame = build_ws_frame(8, <<>>),
    send_tcp_data(Socket, Frame),
    gen_tcp:close(Socket).

%% =============================================================================
%% Client HTTP (GET, POST, PUT, PATCH, DELETE)

%% @doc Perform an HTTP client request.
%% @param Method HTTP method atom (get, post, put, patch, delete).
%% @param URL Target URL string.
%% @param Headers List of {Key, Value} header tuples.
%% @param Body Request body (binary or string).
%% @return ok | {error, Reason}
request(Method, URL, Headers, Body) ->
    application:ensure_all_started(inets),
    perform_http_request(Method, URL, Headers, Body).

%% =============================================================================
%% Parsing utilities and status text
%% =============================================================================
split_uri(URI) ->
    case string:split(URI, "?", leading) of
        [Path] -> {Path, ""};
        [Path, Query] -> {Path, Query}
    end.

%% @doc Parse a route pattern into a list of literals and parameters.
%% @param Path Route pattern string like "/users/[id]/posts/[post_id]".
%% @return List of {literal, String} | {param, Atom} tuples.
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

%% @doc Match a parsed pattern against path segments.
%% @param Pattern Parsed pattern from parse_pattern/1.
%% @param PathSegments List of path segment strings.
%% @param Acc Accumulator for matched parameters.
%% @return {ok, Params} | no_match
match_pattern([], [], Acc) -> {ok, lists:reverse(Acc)};
match_pattern([{literal, Expected} | PR], [Expected | PathR], Acc) ->
    match_pattern(PR, PathR, Acc);
match_pattern([{param, Name} | PR], [Value | PathR], Acc) ->
    match_pattern(PR, PathR, [{Name, Value} | Acc]);
match_pattern(_, _, _) -> no_match.

%% @doc Parse a URL query string into a proplist.
%% @param Query Query string like "key1=value1&key2=value2".
%% @return [{Key, Value}] where Key is an atom and Value is a string.
parse_query("") -> [];
parse_query(Query) ->
    [case string:split(Pair, "=", leading) of
         [K] -> {list_to_atom(url_decode(K)), ""};
         [K, V] -> {list_to_atom(url_decode(K)), url_decode(V)}
     end || Pair <- string:split(Query, "&", all)].

%% @doc URL-decode a string.
%% @param Str Encoded string.
%% @param Acc Accumulator for decoded characters.
%% @return Decoded string.
url_decode(Str) -> url_decode(Str, []).
url_decode([], Acc) -> lists:reverse(Acc);
url_decode([$%, H1, H2 | Rest], Acc) ->
    Char = list_to_integer([H1, H2], 16),
    url_decode(Rest, [Char | Acc]);
url_decode([$+ | Rest], Acc) -> url_decode(Rest, [32 | Acc]);
url_decode([C | Rest], Acc) -> url_decode(Rest, [C | Acc]).

merge_headers(Defaults, Custom) ->
    lists:foldl(fun({K, V}, Acc) -> lists:keystore(K, 1, Acc, {K, V}) end, Defaults, Custom).

binary_to_string(Binary) when is_binary(Binary) ->
    binary:bin_to_list(Binary);
binary_to_string(Other) ->
    Other.

%% @doc Parse the request body based on content type.
%% @param ModData The inets mod record or test tuple.
%% @return Parsed body (proplist for form data, string/binary for others).
parse_body(ModData) when is_tuple(ModData) ->
    case ModData of
        #mod{method=Method, parsed_header=Headers, entity_body=Body} ->
            MethodUpper = string:to_upper(Method),
            IsBodyMethod = MethodUpper == "POST" orelse MethodUpper == "PUT" orelse MethodUpper == "PATCH",
            if
                IsBodyMethod ->
                    ContentType = proplists:get_value("content-type", Headers, ""),
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
            MethodUpper = string:to_upper(Method),
            IsBodyMethod = MethodUpper == "POST" orelse MethodUpper == "PUT" orelse MethodUpper == "PATCH",
            if
                IsBodyMethod ->
                    ContentType = proplists:get_value("content-type", Headers, ""),
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

is_supported_content_type(ContentType) ->
    SupportedContentTypes = [
        "application/json",
        "application/x-www-form-urlencoded",
        "text/plain",
        "text/html"
    ],
    lists:any(fun(Type) -> string:find(ContentType, Type) =/= nomatch end, SupportedContentTypes).

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

%% @doc Convert HTTP status code to reason phrase.
%% @param Code HTTP status code integer.
%% @return Reason phrase string.

%% 1xx Informational
status_text(100) -> "Continue";
status_text(101) -> "Switching Protocols";
status_text(102) -> "Processing";
status_text(103) -> "Early Hints";

%% 2xx Success
status_text(200) -> "OK";
status_text(201) -> "Created";
status_text(202) -> "Accepted";
status_text(203) -> "Non-Authoritative Information";
status_text(204) -> "No Content";
status_text(205) -> "Reset Content";
status_text(206) -> "Partial Content";
status_text(207) -> "Multi-Status";
status_text(208) -> "Already Reported";
status_text(226) -> "IM Used";

%% 3xx Redirection
status_text(300) -> "Multiple Choices";
status_text(301) -> "Moved Permanently";
status_text(302) -> "Found";
status_text(303) -> "See Other";
status_text(304) -> "Not Modified";
status_text(305) -> "Use Proxy";
status_text(306) -> "Switch Proxy";
status_text(307) -> "Temporary Redirect";
status_text(308) -> "Permanent Redirect";

%% 4xx Client Errors
status_text(400) -> "Bad Request";
status_text(401) -> "Unauthorized";
status_text(402) -> "Payment Required";
status_text(403) -> "Forbidden";
status_text(404) -> "Not Found";
status_text(405) -> "Method Not Allowed";
status_text(406) -> "Not Acceptable";
status_text(407) -> "Proxy Authentication Required";
status_text(408) -> "Request Timeout";
status_text(409) -> "Conflict";
status_text(410) -> "Gone";
status_text(411) -> "Length Required";
status_text(412) -> "Precondition Failed";
status_text(413) -> "Payload Too Large";
status_text(414) -> "URI Too Long";
status_text(415) -> "Unsupported Media Type";
status_text(416) -> "Range Not Satisfiable";
status_text(417) -> "Expectation Failed";
status_text(418) -> "I'm a teapot";
status_text(421) -> "Misdirected Request";
status_text(422) -> "Unprocessable Entity";
status_text(423) -> "Locked";
status_text(424) -> "Failed Dependency";
status_text(425) -> "Too Early";
status_text(426) -> "Upgrade Required";
status_text(428) -> "Precondition Required";
status_text(429) -> "Too Many Requests";
status_text(431) -> "Request Header Fields Too Large";
status_text(451) -> "Unavailable For Legal Reasons";

%% 5xx Server Errors
status_text(500) -> "Internal Server Error";
status_text(501) -> "Not Implemented";
status_text(502) -> "Bad Gateway";
status_text(503) -> "Service Unavailable";
status_text(504) -> "Gateway Timeout";
status_text(505) -> "HTTP Version Not Supported";
status_text(506) -> "Variant Also Negotiates";
status_text(507) -> "Insufficient Storage";
status_text(508) -> "Loop Detected";
status_text(510) -> "Not Extended";
status_text(511) -> "Network Authentication Required";

%% Default for unknown codes
status_text(Code) -> integer_to_list(Code).

