%% @doc Wade is a lightweight HTTP server and WebSocket framework for Erlang/OTP.
%% It provides routing, request/response handling, WebSocket support, and utilities for building web applications.
%% Features:
%%   - RESTful routing with parameter extraction
%%   - WebSocket upgrade and messaging
%%   - Request/response utilities (query, body, headers, etc.)
%%   - Built-in HTTP client
%%   - Error handling and timeouts
%%   - Compatible with inets and gen_server
%% @end

-module(wade).
-behaviour(gen_server).
-include_lib("inets/include/httpd.hrl").
-include("wade.hrl").

%% @doc Public API functions for starting/stopping the server and defining routes.
-export([
    start_link/1, start_link/2, stop/0,
    route/4, route/5,
    param/2, query/2, query/3, body/2, body/3, method/1,
    reply/3, reply/4,
    request/4
]).

%% @doc gen_server callback functions.
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3, send_response/2]).

%% @doc Internal utility functions for parsing and matching.
-export([parse_query/1, parse_body/1, url_decode/2, parse_pattern/1, match_pattern/3]).

%% @doc inets HTTP callback function.
-export([do/1]).

%% @doc WebSocket support functions.
-export([upgrade_to_websocket/1, websocket_loop/2, send_ws/2, close_ws/1]).

%% =============================================================================
%% @section Public API
%% =============================================================================

%% @doc Start the Wade server on the specified port.
%% @param Port The TCP port to listen on.
%% @return {ok, pid()} | {error, term()}
%% @example start_link(8080).
-spec start_link(integer()) -> {ok, pid()} | {error, term()}.
start_link(Port) -> start_link(Port, #{}).

%% @doc Start the Wade server with custom options.
%% @param Port The TCP port to listen on.
%% @param Options Proplist of server options. Supported keys:
%%   - dispatch: List of {PathPattern, {Module, Args}} for dispatch-based routing.
%% @return {ok, pid()} | {error, term()}
%% @example start_link(8080, #{dispatch => [{"api/", {my_api, []}}]}).
-spec start_link(integer(), map()) -> {ok, pid()} | {error, term()}.
start_link(Port, Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Port, Options], []).

%% @doc Stop the Wade server.
%% @return ok
-spec stop() -> ok.
stop() ->
    gen_server:call(?MODULE, stop).

%% @doc Register a route for HTTP requests.
%% @param Method Atom: get, post, put, delete, patch, head, options, or any.
%% @param Path String: URL path pattern (e.g., "/users/[id]").
%% @param Handler Function: Fun(#req{}) -> #req{} | {StatusCode, Body} | {StatusCode, Headers, Body}.
%% @param RequiredParams List of atoms: Required query/body parameters.
%% @return ok
%% @example route(get, "/hello", fun(Req) -> reply(Req, 200, "Hello!") end, []).
-spec route(atom(), string(), fun((#req{}) -> term()), list(atom())) -> ok.
route(Method, Path, Handler, RequiredParams) ->
    route(Method, Path, Handler, RequiredParams, []).

%% @doc Register a route with required headers.
%% @param Method Atom: HTTP method.
%% @param Path String: URL path pattern.
%% @param Handler Function: Request handler.
%% @param RequiredParams List of atoms: Required query/body parameters.
%% @param RequiredHeaders List of strings: Required HTTP headers.
%% @return ok
%% @example route(post, "/api", fun handle_api/1, [user_id], ["Authorization"]).
-spec route(atom(), string(), fun((#req{}) -> term()), list(atom()), list(string())) -> ok.
route(Method, Path, Handler, RequiredParams, RequiredHeaders) ->
    gen_server:call(?MODULE, {add_route, Method, Path, Handler, RequiredParams, RequiredHeaders}).

%% @doc Get the value of a query parameter from the request.
%% @param Req #req{} record.
%% @param Key Atom or string: Parameter name.
%% @return term() | undefined
%% @example query(Req, "id").
-spec query(#req{}, atom() | string()) -> term() | undefined.
query(#req{query = Query}, Key) -> proplists:get_value(Key, Query).

%% @doc Get the value of a query parameter, with a default if missing.
%% @param Req #req{} record.
%% @param Key Atom or string: Parameter name.
%% @param Default term(): Default value if parameter is missing.
%% @return term()
%% @example query(Req, "page", 1).
-spec query(#req{}, atom() | string(), term()) -> term().
query(#req{query = Query}, Key, Default) -> proplists:get_value(Key, Query, Default).

%% @doc Get the value of a body parameter from the request.
%% @param Req #req{} record.
%% @param Key Atom or string: Parameter name.
%% @return term() | undefined
%% @example body(Req, "username").
-spec body(#req{}, atom() | string()) -> term() | undefined.
body(#req{body = Body}, Key) -> proplists:get_value(Key, Body).

%% @doc Get the value of a body parameter, with a default if missing.
%% @param Req #req{} record.
%% @param Key Atom or string: Parameter name.
%% @param Default term(): Default value if parameter is missing.
%% @return term()
%% @example body(Req, "email", "default@example.com").
-spec body(#req{}, atom() | string(), term()) -> term().
body(#req{body = Body}, Key, Default) -> proplists:get_value(Key, Body, Default).

%% @doc Get the HTTP method of the request.
%% @param Req #req{} record.
%% @return atom(): get, post, put, delete, etc.
%% @example method(Req).
-spec method(#req{}) -> atom().
method(#req{method = Method}) -> Method.

%% @doc Get the value of a parameter (from path, query, or body).
%% @param Req #req{} record.
%% @param Key Atom or string: Parameter name.
%% @return term() | undefined
%% @example param(Req, "id").
-spec param(#req{}, atom() | string()) -> term() | undefined.
param(#req{params = Params, query = Query}, Key) ->
    KeyAtom = case Key of
        KeyA when is_atom(KeyA) -> KeyA;
        KeyS when is_list(KeyS) -> list_to_atom(KeyS)
    end,
    case proplists:get_value(KeyAtom, Params) of
        undefined -> proplists:get_value(KeyAtom, Query);
        Value -> Value
    end.

%% @doc Reply to a request with status code and body.
%% @param Req #req{} record.
%% @param StatusCode integer(): HTTP status code.
%% @param Body binary() | string(): Response body.
%% @return #req{} with reply fields set.
%% @example reply(Req, 200, "OK").
-spec reply(#req{}, integer(), binary() | string()) -> #req{}.
reply(Req, StatusCode, Body) ->
    reply(Req, StatusCode, #{}, Body).

%% @doc Reply to a request with status code, headers, and body.
%% @param Req #req{} record.
%% @param StatusCode integer(): HTTP status code.
%% @param Headers map(): Additional response headers.
%% @param Body binary() | string(): Response body.
%% @return #req{} with reply fields set.
%% @example reply(Req, 200, #{<<"content-type">> => <<"application/json">>}, "{\"status\":\"ok\"}").
-spec reply(#req{}, integer(), map(), binary() | string()) -> #req{}.
reply(Req, StatusCode, Headers, Body) ->
    Req#req{
        reply_status = StatusCode,
        reply_headers = Headers,
        reply_body = Body
    }.

%% @doc Make an HTTP request to an external service.
%% @param Method atom(): HTTP method (get, post, put, etc.).
%% @param URL string(): Target URL.
%% @param Headers list({binary(), binary()}): Request headers.
%% @param Body binary() | string(): Request body.
%% @return {ok, StatusCode, Headers, Body} | {error, term()}.
%% @example request(get, "http://example.com/api", [], "").
-spec request(atom(), string(), list({binary(), binary()}), binary() | string()) ->
    {ok, integer(), list({binary(), binary()}), binary()} | {error, term()}.
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
%% @section gen_server Callbacks
%% =============================================================================

%% @doc Initialize the server.
%% @param Args [Port, Options].
%% @return {ok, #state{}} | {stop, term()}.
-spec init([term()]) -> {ok, #state{}} | {stop, term()}.
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

%% @doc Handle synchronous calls (e.g., adding routes).
%% @param {add_route, Method, Path, Handler, RequiredParams, RequiredHeaders} | stop | {get_routes} | {get_dispatch}.
%% @return {reply, term(), #state{}}.
-spec handle_call(term(), pid(), #state{}) -> {reply, term(), #state{}}.
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

%% @doc Handle asynchronous messages.
%% @param Msg term().
%% @return {noreply, #state{}}.
-spec handle_cast(term(), #state{}) -> {noreply, #state{}}.
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @doc Handle non-OTP messages (e.g., TCP errors, HTTP server crashes).
%% @param Msg term().
%% @return {noreply, #state{}} | {stop, term(), #state{}}.
-spec handle_info(term(), #state{}) -> {noreply, #state{}} | {stop, term(), #state{}}.
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

%% @doc Clean up server resources.
%% @param Reason term().
%% @param State #state{}.
%% @return ok.
-spec terminate(term(), #state{}) -> ok.
terminate(_Reason, #state{httpd_pid = HttpdPid}) ->
    case HttpdPid of
        undefined -> ok;
        Pid -> inets:stop(httpd, Pid)
    end.

%% @doc Handle code upgrades.
%% @param _OldVsn term().
%% @param State #state{}.
%% @param _Extra term().
%% @return {ok, #state{}}.
-spec code_change(term(), #state{}, term()) -> {ok, #state{}}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% =============================================================================
%% @section HTTP Request Handling (inets callback)
%% =============================================================================

%% @doc Main HTTP request handler, called by inets for each incoming request.
%% @param ModData #mod{} record from inets.
%% @return {proceed, term()}.
-spec do(#mod{}) -> {proceed, term()}.
do(ModData) ->
    try
        %% Convert HTTP method to lowercase atom
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
        %% Split URI into path and query string
        {Path, QueryString} = split_uri(ModData#mod.request_uri),
        %% Read request body for POST/PUT/PATCH requests
        ModDataWithBody = case lists:member(Method, [post, put, patch]) of
            true ->
                ContentLength = case proplists:get_value("content-length", ModData#mod.parsed_header) of
                    undefined -> 0;
                    LenStr ->
                        case catch list_to_integer(LenStr) of
                            Len when is_integer(Len) -> Len;
                            _ -> 0
                        end
                end,
                BodyData = if
                    ContentLength > 0 andalso (ModData#mod.entity_body =:= <<>> orelse
                                              ModData#mod.entity_body =:= []) ->
                        io:format("Reading ~p bytes from socket...~n", [ContentLength]),
                        case gen_tcp:recv(ModData#mod.socket, ContentLength, 5000) of
                            {ok, Data} ->
                                io:format("Successfully read body: ~p~n", [Data]),
                                Data;
                            {error, Reason} ->
                                io:format("Failed to read body: ~p~n", [Reason]),
                                <<>>
                        end;
                    true ->
                        ModData#mod.entity_body
                end,
                ModData#mod{entity_body = BodyData};
            false ->
                ModData
        end,
        %% Parse the body according to content type
        Body = parse_body(ModDataWithBody),
        %% Build request record
        Req = #req{
            method = Method,
            path = Path,
            query = parse_query(QueryString),
            body = Body,
            headers = ModDataWithBody#mod.parsed_header,
            reply_status = undefined,
            reply_headers = #{},
            reply_body = <<>>
        },
        %% Try dispatch-based routing first, then fall back to regular routes
        Dispatch = gen_server:call(?MODULE, {get_dispatch}),
        Response = case match_dispatch(Dispatch, Path, Req) of
            {ok, Result} -> Result;
            not_found ->
                Routes = gen_server:call(?MODULE, {get_routes}),
                case match_route(Routes, Req) of
                    {ok, Handler, PathParams} ->
                        ReqWithParams = Req#req{params = PathParams},
                        handle_request_safe(Handler, ReqWithParams, ModDataWithBody);
                    not_found -> {404, <<"Not Found">>}
                end
        end,
        send_final_response(Response, ModDataWithBody)
    catch
        Class:Error:Stacktrace ->
            io:format("Error in do/1: ~p:~p~nStacktrace: ~p~n", [Class, Error, Stacktrace]),
            ErrorBody = jsx:encode(#{error => <<"Internal Server Error">>}),
            send_response_to_client(500, ErrorBody, [{"content-type","application/json"}], ModData),
            {proceed, ModData#mod.data}
    end.

%% @doc Match dispatch-based routes (e.g., "/api/*" -> my_api_module).
%% @param Dispatch List of {PathPattern, {Module, Args}}.
%% @param Path String: Request path.
%% @param Req #req{} record.
%% @return {ok, term()} | not_found.
-spec match_dispatch([{string(), {atom(), list()}}], string(), #req{}) -> {ok, term()} | not_found.
match_dispatch([], _Path, _Req) -> not_found;
match_dispatch([{Pattern, {Module, Args}} | Rest], Path, Req) ->
    case match_dispatch_pattern(Pattern, Path) of
        {ok, PathParams} ->
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

%% @doc Simple pattern matching for dispatch routes.
%% @param Pattern String: Path pattern (e.g., "/api/").
%% @param Path String: Request path.
%% @return {ok, list()} | no_match.
-spec match_dispatch_pattern(string(), string()) -> {ok, list()} | no_match.
match_dispatch_pattern(Pattern, Path) when is_list(Pattern) ->
    case Pattern of
        "/" ++ _ ->
            if
                Pattern == Path -> {ok, []};
                true -> no_match
            end;
        _ -> no_match
    end.

%% @doc Send the final HTTP response to the client.
%% @param Response term(): Handler response.
%% @param ModData #mod{} record.
%% @return {proceed, term()}.
-spec send_final_response(term(), #mod{}) -> {proceed, term()}.
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

%% @doc Send HTTP response to client via TCP socket.
%% @param StatusCode integer(): HTTP status code.
%% @param Body binary() | string(): Response body.
%% @param Headers list({string(), string()}): Response headers.
%% @param ModData #mod{} record.
%% @return ok.
-spec send_response_to_client(integer(), binary() | string(), list({string(), string()}), #mod{}) -> ok.
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
%% @section Route Matching and Utilities
%% =============================================================================

%% @doc Match request against registered routes.
%% @param Routes List of #route{} records.
%% @param Req #req{} record.
%% @return {ok, {fun(), list(), list()}, list()} | not_found.
-spec match_route([#route{}], #req{}) -> {ok, {fun(), list(), list()}, list()} | not_found.
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

%% @doc Validate that all required parameters are present in the request.
%% @param RequiredParams List of atoms: Parameter names.
%% @param Req #req{} record.
%% @return ok | {error, missing_param, string()}.
-spec validate_params(list(atom()), #req{}) -> ok | {error, missing_param, string()}.
validate_params([], _) -> ok;
validate_params([Param | Rest], Req) ->
    case {param(Req, Param), query(Req, atom_to_list(Param)), body(Req, atom_to_list(Param))} of
        {undefined, undefined, undefined} -> {error, missing_param, atom_to_list(Param)};
        _ -> validate_params(Rest, Req)
    end.

%% @doc Validate that all required headers are present in the request.
%% @param RequiredHeaders List of strings: Header names.
%% @param Req #req{} record.
%% @return ok | {error, missing_header, string()}.
-spec validate_headers(list(string()), #req{}) -> ok | {error, missing_header, string()}.
validate_headers([], _) -> ok;
validate_headers([Header | Rest], Req) ->
    case proplists:get_value(Header, Req#req.headers) of
        undefined -> {error, missing_header, Header};
        _ -> validate_headers(Rest, Req)
    end.

%% @doc Execute handler in a separate process with timeout and error handling.
%% @param Handler {fun(), list(), list()}: Handler function and its required params/headers.
%% @param Req #req{} record.
%% @param ModData #mod{} record.
%% @return term(): Handler result or error response.
-spec handle_request_safe({fun(), list(), list()}, #req{}, #mod{}) -> term().
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
%% @section WebSocket Support
%% =============================================================================

%% @doc Upgrade HTTP connection to WebSocket.
%% @param ModData #mod{} record.
%% @return {ok, socket()} | {error, term()}.
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

%% @doc WebSocket message loop.
%% @param Socket TCP socket.
%% @param HandlerFun fun({text, string()} | {close, binary()} | {ping, binary()} | {pong, binary()}).
%% @return ok.
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

%% @doc Send WebSocket message.
%% @param Socket TCP socket.
%% @param Msg {text, string()} | {pong, binary()}.
%% @return ok.
send_ws(Socket, {text, Msg}) ->
    Frame = build_ws_frame(1, list_to_binary(Msg)),
    gen_tcp:send(Socket, Frame);
send_ws(Socket, {pong, Msg}) ->
    Frame = build_ws_frame(10, Msg),
    gen_tcp:send(Socket, Frame).

%% @doc Close WebSocket connection.
%% @param Socket TCP socket.
%% @return ok.
close_ws(Socket) ->
    Frame = build_ws_frame(8, <<>>),
    gen_tcp:send(Socket, Frame),
    gen_tcp:close(Socket).

%% =============================================================================
%% @section Parsing Utilities
%% =============================================================================

%% @doc Split URI into path and query string.
%% @param URI string().
%% @return {Path, QueryString}.
-spec split_uri(string()) -> {string(), string()}.
split_uri(URI) ->
    case string:split(URI, "?", leading) of
        [Path] -> {Path, ""};
        [Path, Query] -> {Path, Query}
    end.

%% @doc Parse route pattern (e.g., "/users/[id]/posts" -> [{literal, "users"}, {param, id}, {literal, "posts"}]).
%% @param Path string().
%% @return list({literal, string()} | {param, atom()}).
-spec parse_pattern(string()) -> list({literal, string()} | {param, atom()}).
parse_pattern(Path) ->
    CleanPath = string:trim(Path, leading, "/"),
    case CleanPath of
        "" -> [];
        _ -> [case string:prefix(Part, "[") of
                  nomatch -> {literal, Part};
                  Rest -> {param, list_to_atom(string:trim(Rest, trailing, "]"))}
              end || Part <- string:split(CleanPath, "/", all)]
    end.

%% @doc Parse path into segments.
%% @param Path string().
%% @return list(string()).
-spec parse_path(string()) -> list(string()).
parse_path(Path) ->
    CleanPath = string:trim(Path, leading, "/"),
    case CleanPath of "" -> []; _ -> string:split(CleanPath, "/", all) end.

%% @doc Match path segments against route pattern.
%% @param Pattern list({literal, string()} | {param, atom()}).
%% @param PathSegments list(string()).
%% @param Acc list({atom(), string()}).
%% @return {ok, list({atom(), string()})} | no_match.
-spec match_pattern(list({literal, string()} | {param, atom()}), list(string()), list({atom(), string()})) ->
    {ok, list({atom(), string()})} | no_match.
match_pattern([], [], Acc) -> {ok, lists:reverse(Acc)};
match_pattern([{literal, Expected} | PR], [Expected | PathR], Acc) ->
    match_pattern(PR, PathR, Acc);
match_pattern([{param, Name} | PR], [Value | PathR], Acc) ->
    match_pattern(PR, PathR, [{Name, Value} | Acc]);
match_pattern(_, _, _) -> no_match.

%% @doc Parse query string into proplist.
%% @param Query string().
%% @return list({atom(), string()}).
-spec parse_query(string()) -> list({atom(), string()}).
parse_query("") -> [];
parse_query(Query) ->
    [case string:split(Pair, "=", leading) of
         [K] -> {list_to_atom(url_decode(K)), ""};
         [K, V] -> {list_to_atom(url_decode(K)), url_decode(V)}
     end || Pair <- string:split(Query, "&", all)].

%% @doc URL decode string.
%% @param Str string().
%% @return string().
-spec url_decode(string()) -> string().
url_decode(Str) -> url_decode(Str, []).
url_decode([], Acc) -> lists:reverse(Acc);
url_decode([$%, H1, H2 | Rest], Acc) ->
    Char = list_to_integer([H1, H2], 16),
    url_decode(Rest, [Char | Acc]);
url_decode([$+ | Rest], Acc) -> url_decode(Rest, [32 | Acc]);
url_decode([C | Rest], Acc) -> url_decode(Rest, [C | Acc]).

%% @doc Merge header lists, with custom headers overriding defaults.
%% @param Defaults list({string(), string()}).
%% @param Custom list({string(), string()}).
%% @return list({string(), string()}).
-spec merge_headers(list({string(), string()}), list({string(), string()})) -> list({string(), string()}).
merge_headers(Defaults, Custom) ->
    lists:foldl(fun({K, V}, Acc) ->
        Key = if is_binary(K) -> binary_to_list(K); true -> K end,
        lists:keystore(Key, 1, Acc, {Key, V})
    end, Defaults, Custom).

%% @doc Parse request body based on content type.
%% @param ModData #mod{} record.
%% @return list({atom(), string()}) | map() | [].
-spec parse_body(#mod{}) -> list({atom(), string()}) | map() | [].
parse_body(ModData) when is_tuple(ModData) ->
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
                    case catch jsx:decode(list_to_binary(BodyStr), [return_maps]) of
                        {'EXIT', _} -> [];
                        JsonMap -> JsonMap
                    end;
                _ ->
                    []
            end;
        true ->
            []
    end.

%% @doc Parse WebSocket frame.
%% @param Data binary().
%% @return {text, string()} | {close, binary()} | {ping, binary()} | {pong, binary()} | {unknown, binary()}.
-spec parse_ws_frame(binary()) ->
    {text, string()} | {close, binary()} | {ping, binary()} | {pong, binary()} | {unknown, binary()}.
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

%% @doc Build WebSocket frame.
%% @param Opcode 1 (text) | 8 (close) | 10 (pong).
%% @param Payload binary().
%% @return binary().
-spec build_ws_frame(1 | 8 | 10, binary()) -> binary().
build_ws_frame(1, Payload) when is_binary(Payload) ->
    Len = byte_size(Payload),
    <<129, Len, Payload/binary>>;
build_ws_frame(8, _) ->
    <<136, 0>>;
build_ws_frame(10, Payload) when is_binary(Payload) ->
    Len = byte_size(Payload),
    <<138, Len, Payload/binary>>.

%% @doc Get HTTP status text for status code.
%% @param Code integer().
%% @return string().
-spec status_text(integer()) -> string().
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

%% @doc Placeholder for compatibility.
-spec send_response(term(), term()) -> ok.
send_response(_, _) -> ok.

