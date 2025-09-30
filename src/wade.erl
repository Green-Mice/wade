-module(wade).
-behaviour(gen_server).
-include_lib("inets/include/httpd.hrl").
-include("wade.hrl").

%% API
-export([
    start_link/1, start_link/2, stop/0,
    route/4, route/5,
    param/2, query/2, query/3, body/2, body/3, method/1,
    reply/3, reply/4,
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

start_link(Port) -> start_link(Port, #{}).

start_link(Port, Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Port, Options], []).

stop() ->
    gen_server:call(?MODULE, stop).

route(Method, Path, Handler, RequiredParams) ->
    route(Method, Path, Handler, RequiredParams, []).

route(Method, Path, Handler, RequiredParams, RequiredHeaders) ->
    gen_server:call(?MODULE, {add_route, Method, Path, Handler, RequiredParams, RequiredHeaders}).

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

%% @doc Reply to a request with status code and body
reply(Req, StatusCode, Body) ->
    reply(Req, StatusCode, #{}, Body).

%% @doc Reply to a request with status code, headers, and body
reply(Req, StatusCode, Headers, Body) ->
    Req#req{
        reply_status = StatusCode,
        reply_headers = Headers,
        reply_body = Body
    }.

%% =============================================================================
%% gen_server callbacks
%% =============================================================================

init([Port, Options]) ->
    process_flag(trap_exit, true),
    application:ensure_all_started(inets),
    
    Dispatch = maps:get(dispatch, Options, []),
    
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
            {ok, #state{port = Port, httpd_pid = HttpdPid, routes = [], dispatch = Dispatch}};
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
    {reply, State#state.routes, State};

handle_call({get_dispatch}, _From, State) ->
    {reply, State#state.dispatch, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'EXIT', Pid, Reason}, #state{httpd_pid = Pid} = State) ->
    io:format("HTTP server crashed (~p), restarting...~n", [Reason]),
    Config = [
        {port, State#state.port},
        {server_name, "wade"},
        {server_root, "."},
        {document_root, "."},
        {modules, [?MODULE]}
    ],
    case inets:start(httpd, Config) of
        {ok, NewPid} ->
            link(NewPid),
            io:format("HTTP server restarted (PID: ~p)~n", [NewPid]),
            {noreply, State#state{httpd_pid = NewPid}};
        {error, Reason2} ->
            {stop, Reason2, State}
    end;

handle_info({tcp, Socket, _Data}, State) ->
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
    try
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
            headers = ModData#mod.parsed_header,
            reply_status = undefined,
            reply_headers = #{},
            reply_body = <<>>
        },

        Dispatch = gen_server:call(?MODULE, {get_dispatch}),
        Response = case match_dispatch(Dispatch, Path, Req) of
            {ok, Result} -> Result;
            not_found ->
                Routes = gen_server:call(?MODULE, {get_routes}),
                case match_route(Routes, Req) of
                    {ok, Handler, PathParams} ->
                        ReqWithParams = Req#req{params = PathParams},
                        handle_request_safe(Handler, ReqWithParams, ModData);
                    not_found -> {404, <<"Not Found">>}
                end
        end,
        send_final_response(Response, ModData)
    catch
        Class:Reason:Stacktrace ->
            io:format("Error in do/1: ~p:~p~nStacktrace: ~p~n", [Class, Reason, Stacktrace]),
            %% Return 500 error with JSON error body so the client sees a consistent message
            ErrorBody = jsx:encode(#{error => <<"Internal Server Error">>}),
            send_response_to_client(500, ErrorBody, [{"content-type","application/json"}], ModData),
            {proceed, ModData#mod.data}
    end.

%% Match dispatch-based routes
match_dispatch([], _Path, _Req) -> not_found;
match_dispatch([{Pattern, {Module, Args}} | Rest], Path, Req) ->
    case match_dispatch_pattern(Pattern, Path) of
        {ok, PathParams} ->
            % Call the handler module
            ReqWithParams = Req#req{params = PathParams},
            case Module:start_link(Args) of
                {ok, _Pid} ->
                    Result = gen_server:call({Module, Args}, {http_request, ReqWithParams}),
                    {ok, Result};
                {error, {already_started, _Pid}} ->
                    Result = gen_server:call({Module, Args}, {http_request, ReqWithParams}),
                    {ok, Result};
                _Error ->
                    not_found
            end;
        no_match ->
            match_dispatch(Rest, Path, Req)
    end.

match_dispatch_pattern(Pattern, Path) when is_list(Pattern) ->
    % Simple pattern matching for now
    case Pattern of
        "/" ++ _ ->
            if 
                Pattern == Path -> {ok, []};
                true -> no_match
            end;
        _ -> no_match
    end.

send_final_response(Response, ModData) ->
    case Response of
        {StatusCode, Body} when is_integer(StatusCode) ->
            send_response_to_client(StatusCode, Body, [], ModData);
        {StatusCode, Body, Headers} when is_integer(StatusCode) ->
            send_response_to_client(StatusCode, Body, Headers, ModData);
        #req{reply_status = Status, reply_headers = Headers, reply_body = Body} when Status =/= undefined ->
            HeadersList = maps:to_list(Headers),
            send_response_to_client(Status, Body, HeadersList, ModData);
        _ ->
            send_response_to_client(500, <<"Internal Server Error">>, [], ModData)
    end,
    {proceed, ModData#mod.data}.

send_response_to_client(StatusCode, Body, Headers, ModData) ->
    BodyBin = case Body of
        B when is_binary(B) -> B;
        B when is_list(B) -> list_to_binary(B);
        _ -> <<>>
    end,
    
    ContentLength = byte_size(BodyBin),
    
    DefaultHeaders = [
        {"content-length", integer_to_list(ContentLength)},
        {"content-type", "text/html; charset=UTF-8"},
        {"connection", "close"}
    ],
    
    AllHeaders = merge_headers(DefaultHeaders, Headers),
    
    HeaderLines = lists:map(fun({Key, Value}) ->
        K = if is_binary(Key) -> binary_to_list(Key); true -> Key end,
        V = if is_binary(Value) -> binary_to_list(Value); true -> Value end,
        io_lib:format("~s: ~s\r\n", [K, V])
    end, AllHeaders),
    
    Response = [
        io_lib:format("HTTP/1.1 ~p ~s\r\n", [StatusCode, status_text(StatusCode)]),
        HeaderLines,
        "\r\n",
        BodyBin
    ],
    
    gen_tcp:send(ModData#mod.socket, Response).

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

handle_request_safe({Handler, RequiredParams, RequiredHeaders}, Req, _ModData) ->
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
            Result;
        {worker_error, Status, Message} ->
            {Status, list_to_binary(Message)};
        {'EXIT', WorkerPid, Reason} ->
            ErrorMsg = io_lib:format("Worker process died: ~p", [Reason]),
            {500, list_to_binary(ErrorMsg)}
    after 30000 ->
        unlink(WorkerPid),
        exit(WorkerPid, timeout),
        {504, <<"Request timeout">>}
    end.


%% =============================================================================
%% HTTP Client
%% =============================================================================

request(Method, URL, Headers, Body) ->
    application:ensure_all_started(inets),
    ContentType = case lists:keyfind("content-type", 1, Headers) of
        {_, CType} -> CType;
        false -> "application/json"
    end,
    
    Request = case Method of
        get -> {URL, Headers};
        _ -> {URL, Headers, ContentType, Body}
    end,
    
    case httpc:request(Method, Request, [], []) of
        {ok, {{_Version, StatusCode, _ReasonPhrase}, RespHeaders, RespBody}} ->
            {ok, StatusCode, RespHeaders, RespBody};
        {error, Reason} ->
            {error, Reason}
    end.

%% =============================================================================
%% WebSocket Support
%% =============================================================================

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

%% =============================================================================
%% Parsing utilities
%% =============================================================================

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

url_decode(Str) -> url_decode(Str, []).
url_decode([], Acc) -> lists:reverse(Acc);
url_decode([$%, H1, H2 | Rest], Acc) ->
    Char = list_to_integer([H1, H2], 16),
    url_decode(Rest, [Char | Acc]);
url_decode([$+ | Rest], Acc) -> url_decode(Rest, [32 | Acc]);
url_decode([C | Rest], Acc) -> url_decode(Rest, [C | Acc]).

merge_headers(Defaults, Custom) ->
    lists:foldl(fun({K, V}, Acc) -> 
        Key = if is_binary(K) -> binary_to_list(K); true -> K end,
        lists:keystore(Key, 1, Acc, {Key, V}) 
    end, Defaults, Custom).

parse_body(ModData) when is_tuple(ModData) ->
    % Extract method, headers, and body from ModData record or tuple
    {Method, Headers, Body} = case ModData of
        #mod{method=Method0, parsed_header=Headers0, entity_body=Body0} ->
            {Method0, Headers0, Body0};
        {mod, Method0, _RequestURI, Headers0, Body0, _O1, _O2} ->
            {Method0, Headers0, Body0};
        _ ->
            {"", [], ""}
    end,

    MethodUpper = string:to_upper(Method),
    IsBodyMethod = lists:member(MethodUpper, ["POST", "PUT", "PATCH"]),

    if
        IsBodyMethod ->
            ContentType = proplists:get_value("content-type", Headers, ""),
            % Normalize content type to handle parameters e.g. application/json; charset=UTF-8
            MainContentType = case string:split(ContentType, ";", leading) of
                [Type | _] -> string:strip(Type);
                [] -> ""
            end,

            BodyStr = case Body of
                B when is_binary(B) -> binary_to_list(B);
                B when is_list(B) -> B;
                _ -> ""
            end,

            case MainContentType of
                "application/x-www-form-urlencoded" ->
                    parse_query(BodyStr);
                "application/json" ->
                    case catch jsx:decode(BodyStr, [return_maps]) of
                        {'EXIT', _} -> [];  % JSON decode failed
                        JsonMap -> JsonMap
                    end;
                _ ->
                    []  % Unsupported content type returns empty list
            end;
        true ->
            []
    end.

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

build_ws_frame(1, Payload) when is_binary(Payload) ->
    Len = byte_size(Payload),
    <<129, Len, Payload/binary>>;
build_ws_frame(8, _) ->
    <<136, 0>>;
build_ws_frame(10, Payload) when is_binary(Payload) ->
    Len = byte_size(Payload),
    <<138, Len, Payload/binary>>.

status_text(100) -> "Continue";
status_text(101) -> "Switching Protocols";
status_text(200) -> "OK";
status_text(201) -> "Created";
status_text(204) -> "No Content";
status_text(301) -> "Moved Permanently";
status_text(302) -> "Found";
status_text(304) -> "Not Modified";
status_text(400) -> "Bad Request";
status_text(401) -> "Unauthorized";
status_text(403) -> "Forbidden";
status_text(404) -> "Not Found";
status_text(405) -> "Method Not Allowed";
status_text(500) -> "Internal Server Error";
status_text(502) -> "Bad Gateway";
status_text(503) -> "Service Unavailable";
status_text(504) -> "Gateway Timeout";
status_text(Code) -> integer_to_list(Code).

send_response(_, _) -> ok.
