-module(wade_advanced_test).
-include_lib("eunit/include/eunit.hrl").
-include("wade.hrl").

%% =============================================================================
%% Route Record Tests
%% =============================================================================

route_record_structure_test() ->
    % Test route record creation and field access
    Handler = fun(_Req) -> {200, "OK"} end,
    Route = #route{
        method = get,
        pattern = [{literal, "users"}],
        handler = {Handler, [], []}
    },
    ?assertEqual(get, Route#route.method),
    ?assertEqual([{literal, "users"}], Route#route.pattern),
    {HandlerFun, Params, Headers} = Route#route.handler,
    ?assert(is_function(HandlerFun)),
    ?assertEqual([], Params),
    ?assertEqual([], Headers).

route_with_any_method_test() ->
    % Test route that accepts any HTTP method
    Handler = fun(_) -> "response" end,
    Route = #route{
        method = any,
        pattern = [{literal, "health"}],
        handler = {Handler, [], []}
    },
    ?assertEqual(any, Route#route.method),
    {HandlerFun, _, _} = Route#route.handler,
    ?assert(is_function(HandlerFun)).

route_with_required_params_test() ->
    % Test route with required parameters
    Handler = fun(_) -> "ok" end,
    RequiredParams = [user_id, token],
    RequiredHeaders = ["authorization"],
    Route = #route{
        method = post,
        pattern = [{literal, "api"}, {literal, "users"}],
        handler = {Handler, RequiredParams, RequiredHeaders}
    },
    {HandlerFun, Params, Headers} = Route#route.handler,
    ?assert(is_function(HandlerFun)),
    ?assertEqual([user_id, token], Params),
    ?assertEqual(["authorization"], Headers).

%% =============================================================================
%% State Record Tests
%% =============================================================================

state_record_initialization_test() ->
    % Test state record with default values
    State = #state{port = 8080, httpd_pid = undefined},
    ?assertEqual(8080, State#state.port),
    ?assertEqual(undefined, State#state.httpd_pid),
    ?assertEqual([], State#state.routes).

state_with_routes_test() ->
    % Test state with multiple routes
    Route1 = #route{method = get, pattern = [], handler = {fun(_) -> ok end, [], []}},
    Route2 = #route{method = post, pattern = [], handler = {fun(_) -> ok end, [], []}},
    State = #state{port = 3000, routes = [Route1, Route2]},
    ?assertEqual(2, length(State#state.routes)).

%% =============================================================================
%% Complex Pattern Matching Tests
%% =============================================================================

match_pattern_root_path_test() ->
    % Match root path
    Pattern = [],
    Path = [],
    Result = wade:match_pattern(Pattern, Path, []),
    ?assertEqual({ok, []}, Result).

match_pattern_deep_nesting_test() ->
    % Test deeply nested path with multiple parameters
    Pattern = [
        {literal, "api"},
        {literal, "v1"},
        {literal, "users"},
        {param, user_id},
        {literal, "posts"},
        {param, post_id},
        {literal, "comments"},
        {param, comment_id}
    ],
    Path = ["api", "v1", "users", "100", "posts", "200", "comments", "300"],
    Result = wade:match_pattern(Pattern, Path, []),
    ?assertMatch({ok, _}, Result),
    {ok, Params} = Result,
    ?assertEqual(3, length(Params)).

match_pattern_all_params_test() ->
    % Path with only parameters, no literals
    Pattern = [{param, a}, {param, b}, {param, c}],
    Path = ["val1", "val2", "val3"],
    {ok, Params} = wade:match_pattern(Pattern, Path, []),
    ?assertEqual(3, length(Params)),
    ?assertEqual("val3", proplists:get_value(c, Params)),
    ?assertEqual("val2", proplists:get_value(b, Params)),
    ?assertEqual("val1", proplists:get_value(a, Params)).

match_pattern_special_chars_in_path_test() ->
    % Path segments with special characters
    Pattern = [{literal, "files"}, {param, filename}],
    Path = ["files", "document-2024_v2.pdf"],
    {ok, Params} = wade:match_pattern(Pattern, Path, []),
    ?assertEqual("document-2024_v2.pdf", proplists:get_value(filename, Params)).

match_pattern_numeric_segments_test() ->
    % Numeric path segments should be captured as strings
    Pattern = [{literal, "year"}, {param, year}, {literal, "month"}, {param, month}],
    Path = ["year", "2024", "month", "09"],
    {ok, Params} = wade:match_pattern(Pattern, Path, []),
    ?assertEqual("2024", proplists:get_value(year, Params)),
    ?assertEqual("09", proplists:get_value(month, Params)).

%% =============================================================================
%% Request Helper Functions Advanced Tests
%% =============================================================================

param_precedence_complex_test() ->
    % Test param precedence with multiple sources
    Req = #req{
        params = [{id, "from-path"}, {name, "path-name"}],
        query = [{id, "from-query"}, {filter, "active"}],
        body = [{id, "from-body"}]
    },
    % Path params should take precedence
    ?assertEqual("from-path", wade:param(Req, id)),
    ?assertEqual("path-name", wade:param(Req, name)),
    ?assertEqual("active", wade:param(Req, filter)),
    ?assertEqual(undefined, wade:param(Req, nonexistent)).

query_with_atom_and_string_keys_test() ->
    % Test query with both atom and string keys
    Req = #req{query = [{page, "1"}, {limit, "10"}]},
    ?assertEqual("1", wade:query(Req, page)),
    ?assertEqual("10", wade:query(Req, limit)),
    ?assertEqual(undefined, wade:query(Req, offset)).

body_empty_list_test() ->
    % Empty body should return undefined for any key
    Req = #req{body = []},
    ?assertEqual(undefined, wade:body(Req, username)),
    ?assertEqual("default", wade:body(Req, username, "default")).

method_all_http_verbs_test() ->
    % Test all common HTTP methods
    Methods = [get, post, put, delete, patch, head, options],
    lists:foreach(fun(Method) ->
        Req = #req{method = Method},
        ?assertEqual(Method, wade:method(Req))
    end, Methods).

%% =============================================================================
%% Parse Pattern Edge Cases
%% =============================================================================

parse_pattern_trailing_slash_test() ->
    % Trailing slash is treated as empty segment, creating different pattern
    Pattern1 = wade:parse_pattern("/users/"),
    Pattern2 = wade:parse_pattern("/users"),
    % Pattern1 will have an empty literal segment at the end
    ?assertEqual([{literal, "users"}], Pattern2),
    ?assertEqual(2, length(Pattern1)),  % users + empty segment
    ?assertMatch([{literal, "users"}, {literal, ""}], Pattern1).

parse_pattern_multiple_slashes_test() ->
    % Multiple consecutive slashes (should be handled as empty segments)
    Pattern = wade:parse_pattern("/api//users"),
    % This should result in api, empty string, users
    ?assertEqual(3, length(Pattern)).

parse_pattern_param_variations_test() ->
    % Different parameter naming conventions
    Pattern = wade:parse_pattern("/users/[user_id]/posts/[post-id]/[id123]"),
    ?assertMatch([
        {literal, "users"},
        {param, user_id},
        {literal, "posts"},
        {param, 'post-id'},
        {param, id123}
    ], Pattern).

parse_pattern_mixed_case_test() ->
    % Mixed case in literals
    Pattern = wade:parse_pattern("/API/Users/[ID]"),
    ?assertMatch([
        {literal, "API"},
        {literal, "Users"},
        {param, 'ID'}
    ], Pattern).

%% =============================================================================
%% Query String Complex Scenarios
%% =============================================================================

parse_query_array_notation_test() ->
    % Array-like query parameters (common pattern)
    Result = wade:parse_query("ids=1&ids=2&ids=3"),
    % All values should be in the list
    IdsValues = [V || {ids, V} <- Result],
    ?assertEqual(3, length(IdsValues)).

parse_query_nested_brackets_test() ->
    % Query with bracket notation (not standard but sometimes used)
    Result = wade:parse_query("user[name]=john&user[age]=30"),
    % Should create atoms from the full key
    ?assertEqual(2, length(Result)).

parse_query_equals_in_value_test() ->
    % Equals sign in the value itself
    Result = wade:parse_query("equation=x%3D5"),
    ?assertEqual([{equation, "x=5"}], Result).

parse_query_ampersand_in_value_test() ->
    % Encoded ampersand in value
    Result = wade:parse_query("text=hello%26goodbye"),
    ?assertEqual([{text, "hello&goodbye"}], Result).

parse_query_semicolon_separator_test() ->
    % Semicolon as separator (not standard but some systems use it)
    % Wade uses & separator, so semicolon should be part of value
    Result = wade:parse_query("a=1;b=2"),
    ?assertEqual(1, length(Result)),
    ?assertMatch([{'a', _}], Result).

%% =============================================================================
%% URL Decode Complex Cases
%% =============================================================================

url_decode_slash_test() ->
    % Encoded forward slash
    Result = wade:url_decode("path%2Fto%2Ffile", []),
    ?assertEqual("path/to/file", Result).

url_decode_question_mark_test() ->
    % Encoded question mark
    Result = wade:url_decode("is%20this%3F", []),
    ?assertEqual("is this?", Result).

url_decode_hash_test() ->
    % Encoded hash/pound sign
    Result = wade:url_decode("tag%23awesome", []),
    ?assertEqual("tag#awesome", Result).

url_decode_brackets_test() ->
    % Encoded brackets
    Result = wade:url_decode("array%5B0%5D", []),
    ?assertEqual("array[0]", Result).

url_decode_quotes_test() ->
    % Encoded quotes
    Result = wade:url_decode("say%20%22hello%22", []),
    ?assertEqual("say \"hello\"", Result).

url_decode_newline_test() ->
    % Encoded newline
    Result = wade:url_decode("line1%0Aline2", []),
    ?assertEqual("line1\nline2", Result).

url_decode_tab_test() ->
    % Encoded tab
    Result = wade:url_decode("col1%09col2", []),
    ?assertEqual("col1\tcol2", Result).

%% =============================================================================
%% Integration Scenarios
%% =============================================================================

full_request_simulation_test() ->
    % Simulate a complete request with all components
    Req = #req{
        method = post,
        path = "/api/v1/users/123/posts",
        query = [{page, "1"}, {limit, "20"}, {sort, "desc"}],
        body = [{title, "My Post"}, {content, "Hello World"}, {published, "true"}],
        params = [{user_id, "123"}],
        headers = [
            {"content-type", "application/x-www-form-urlencoded"},
            {"authorization", "Bearer token123"},
            {"user-agent", "TestClient/1.0"}
        ]
    },
    
    % Verify all components
    ?assertEqual(post, wade:method(Req)),
    ?assertEqual("123", wade:param(Req, user_id)),
    ?assertEqual("1", wade:query(Req, page)),
    ?assertEqual("My Post", wade:body(Req, title)),
    ?assertEqual("20", wade:query(Req, limit, "10")),
    ?assertEqual(undefined, wade:param(Req, missing)).

rest_api_pattern_test() ->
    % Test typical REST API patterns
    Patterns = [
        {"/users", []},
        {"/users/[id]", [{param, id}]},
        {"/users/[id]/posts", [{param, id}]},
        {"/users/[user_id]/posts/[post_id]", [{param, user_id}, {param, post_id}]}
    ],
    
    lists:foreach(fun({Path, ExpectedParams}) ->
        Pattern = wade:parse_pattern(Path),
        ParamCount = length([Param || {param, _Name} = Param <- Pattern]),
        ?assertEqual(length(ExpectedParams), ParamCount)
    end, Patterns).

query_string_edge_cases_combined_test() ->
    % Multiple edge cases in one query string
    Query = "empty=&space=hello+world&encoded=test%40example.com&number=42",
    Result = wade:parse_query(Query),
    ?assertEqual("", proplists:get_value(empty, Result)),
    ?assertEqual("hello world", proplists:get_value(space, Result)),
    ?assertEqual("test@example.com", proplists:get_value(encoded, Result)),
    ?assertEqual("42", proplists:get_value(number, Result)).
