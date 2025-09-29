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
    param/2, query/2, query/3, body/2, body/3, method/1
]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-export([parse_query/1, parse_body/1, url_decode/2, parse_pattern/1, match_pattern/3]).

%% inets callback
-export([do/1]).

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
    end;

handle_info(_Info, State) ->
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
    Method = case string:to_lower(ModData#mod.method) of
        "get" -> get; "post" -> post; "put" -> put; "delete" -> delete;
        "patch" -> patch; "head" -> head; "options" -> options;
        Other -> list_to_atom(Other)
    end,
    
    {Path, QueryString} = split_uri(ModData#mod.request_uri),
    
    Req = #req{
        method = Method,
        path = Path,
        query = parse_query(QueryString),
        body = parse_body(ModData),
        headers = ModData#mod.parsed_header
    },

    Routes = gen_server:call(?MODULE, {get_routes}),
    case match_route(Routes, Req) of
        {ok, Handler, PathParams} ->
            ReqWithParams = Req#req{params = PathParams},
            handle_request_safe(Handler, ReqWithParams, ModData);
        not_found ->
            send_response(404, "Not Found", [], ModData)
    end,
    
    {proceed, ModData#mod.data}.

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

parse_body(ModData) when is_tuple(ModData) ->
    % Extract fields safely - works with both real #mod and test tuples
    Method = case catch ModData#mod.method of
        {'EXIT', _} -> element(2, ModData);  % Test tuple fallback
        M -> M
    end,
    
    Headers = case catch ModData#mod.parsed_header of
        {'EXIT', _} -> element(4, ModData);  % Test tuple fallback
        H -> H
    end,
    
    EntityBody = case catch ModData#mod.entity_body of
        {'EXIT', _} -> element(5, ModData);  % Test tuple fallback
        E -> E
    end,
    
    MethodUpper = string:to_upper(Method),
    HasBody = lists:member(MethodUpper, ["POST", "PUT", "PATCH"]),

    case HasBody of
        true ->
            ContentType = proplists:get_value("content-type", Headers, ""),
            case string:find(ContentType, "application/x-www-form-urlencoded") of
                nomatch -> [];
                _ -> parse_query(EntityBody)
            end;
        false ->
            []
    end.

url_decode(Str) -> url_decode(Str, []).
url_decode([], Acc) -> lists:reverse(Acc);
url_decode([$%, H1, H2 | Rest], Acc) ->
    Char = list_to_integer([H1, H2], 16),
    url_decode(Rest, [Char | Acc]);
url_decode([$+ | Rest], Acc) -> url_decode(Rest, [32 | Acc]);
url_decode([C | Rest], Acc) -> url_decode(Rest, [C | Acc]).

status_text(200) -> "OK"; status_text(201) -> "Created";
status_text(400) -> "Bad Request"; status_text(404) -> "Not Found";
status_text(500) -> "Internal Server Error"; status_text(504) -> "Gateway Timeout";
status_text(Code) -> integer_to_list(Code).

merge_headers(Defaults, Custom) ->
    lists:foldl(fun({K, V}, Acc) -> lists:keystore(K, 1, Acc, {K, V}) end, Defaults, Custom).

