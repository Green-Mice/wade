-module(wade_test).
-include_lib("eunit/include/eunit.hrl").
-include("wade.hrl").

%% =============================================================================
%% Query String Parsing Tests
%% =============================================================================

parse_query_empty_test() ->
    % Empty query string should return empty list
    ?assertEqual([], wade:parse_query("")).

parse_query_single_param_test() ->
    % Single parameter with value
    ?assertEqual([{k, "100"}], wade:parse_query("k=100")).

parse_query_multiple_params_test() ->
    % Multiple parameters separated by ampersand
    ?assertEqual([{k, "100"}, {j, "200"}], wade:parse_query("k=100&j=200")).

parse_query_param_without_value_test() ->
    % Parameter without value should have empty string
    ?assertEqual([{flag, ""}], wade:parse_query("flag")).

parse_query_mixed_params_test() ->
    % Mix of parameters with and without values
    ?assertEqual([{name, "john"}, {active, ""}, {age, "30"}], 
                 wade:parse_query("name=john&active&age=30")).

parse_query_url_encoded_test() ->
    % URL-encoded spaces (plus signs)
    ?assertEqual([{name, "john doe"}], wade:parse_query("name=john+doe")).

parse_query_percent_encoded_test() ->
    % Percent-encoded special characters
    ?assertEqual([{email, "test@example.com"}], 
                 wade:parse_query("email=test%40example.com")).

parse_query_complex_encoding_test() ->
    % Complex URL encoding with spaces and special chars
    ?assertEqual([{msg, "hello world!"}], 
                 wade:parse_query("msg=hello+world%21")).

%% =============================================================================
%% Body Parsing Tests
%% =============================================================================

parse_body_empty_test() ->
    % Body parsing should return empty list for non-POST/PUT/PATCH methods
    ModData = create_mod_data("GET", "/", "", []),
    ?assertEqual([], wade:parse_body(ModData)).

parse_body_get_method_test() ->
    % GET requests should not parse body even if present
    ModData = create_mod_data("GET", "/", "key=value", 
                              [{"content-type", "application/x-www-form-urlencoded"}]),
    ?assertEqual([], wade:parse_body(ModData)).

parse_body_post_urlencoded_test() ->
    % POST with form-urlencoded content type should parse body
    ModData = create_mod_data("POST", "/", "name=alice&age=25", 
                              [{"content-type", "application/x-www-form-urlencoded"}]),
    ?assertEqual([{name, "alice"}, {age, "25"}], wade:parse_body(ModData)).

parse_body_put_urlencoded_test() ->
    % PUT with form-urlencoded should parse body
    ModData = create_mod_data("PUT", "/users/1", "status=active", 
                              [{"content-type", "application/x-www-form-urlencoded"}]),
    ?assertEqual([{status, "active"}], wade:parse_body(ModData)).

parse_body_patch_urlencoded_test() ->
    % PATCH with form-urlencoded should parse body
    ModData = create_mod_data("PATCH", "/users/1", "email=new@email.com", 
                              [{"content-type", "application/x-www-form-urlencoded"}]),
    ?assertEqual([{email, "new@email.com"}], wade:parse_body(ModData)).

parse_body_wrong_content_type_test() ->
    % POST with non-urlencoded content type should return empty list
    ModData = create_mod_data("POST", "/", "key=value", 
                              [{"content-type", "application/json"}]),
    ?assertEqual([], wade:parse_body(ModData)).

parse_body_no_content_type_test() ->
    % POST without content-type header should return empty list
    ModData = create_mod_data("POST", "/", "key=value", []),
    ?assertEqual([], wade:parse_body(ModData)).

%% =============================================================================
%% Request Record Helper Functions Tests
%% =============================================================================

query_helper_test() ->
    % Test query/2 - retrieve query parameter
    Req = #req{query = [{name, "bob"}, {age, "30"}]},
    ?assertEqual("bob", wade:query(Req, name)),
    ?assertEqual("30", wade:query(Req, age)),
    ?assertEqual(undefined, wade:query(Req, missing)).

query_with_default_test() ->
    % Test query/3 - retrieve query parameter with default
    Req = #req{query = [{name, "charlie"}]},
    ?assertEqual("charlie", wade:query(Req, name, "default")),
    ?assertEqual("default", wade:query(Req, missing, "default")).

body_helper_test() ->
    % Test body/2 - retrieve body parameter
    Req = #req{body = [{username, "dave"}, {password, "secret"}]},
    ?assertEqual("dave", wade:body(Req, username)),
    ?assertEqual("secret", wade:body(Req, password)),
    ?assertEqual(undefined, wade:body(Req, token)).

body_with_default_test() ->
    % Test body/3 - retrieve body parameter with default
    Req = #req{body = [{status, "active"}]},
    ?assertEqual("active", wade:body(Req, status, "inactive")),
    ?assertEqual("inactive", wade:body(Req, missing, "inactive")).

method_helper_test() ->
    % Test method/1 - retrieve HTTP method
    GetReq = #req{method = get},
    PostReq = #req{method = post},
    ?assertEqual(get, wade:method(GetReq)),
    ?assertEqual(post, wade:method(PostReq)).

param_from_path_test() ->
    % Test param/2 - retrieve path parameter (atom key)
    Req = #req{params = [{id, "123"}, {slug, "my-post"}], query = []},
    ?assertEqual("123", wade:param(Req, id)),
    ?assertEqual("my-post", wade:param(Req, slug)).

param_from_query_test() ->
    % Test param/2 - fallback to query parameter if not in path
    Req = #req{params = [{id, "123"}], query = [{filter, "active"}]},
    ?assertEqual("123", wade:param(Req, id)),
    ?assertEqual("active", wade:param(Req, filter)).

param_path_priority_test() ->
    % Test param/2 - path parameters take priority over query
    Req = #req{params = [{id, "path-id"}], query = [{id, "query-id"}]},
    ?assertEqual("path-id", wade:param(Req, id)).

param_string_key_test() ->
    % Test param/2 - string key should be converted to atom
    Req = #req{params = [{name, "test"}], query = []},
    ?assertEqual("test", wade:param(Req, "name")).

param_missing_test() ->
    % Test param/2 - missing parameter returns undefined
    Req = #req{params = [], query = []},
    ?assertEqual(undefined, wade:param(Req, nonexistent)).

%% =============================================================================
%% URL Decoding Tests
%% =============================================================================

url_decode_normal_test() ->
    % Normal string without encoding
    ?assertEqual("hello", wade:url_decode("hello", [])).

url_decode_space_plus_test() ->
    % Plus sign should decode to space
    ?assertEqual("hello world", wade:url_decode("hello+world", [])).

url_decode_percent_test() ->
    % Percent encoding - %20 is space
    ?assertEqual("hello world", wade:url_decode("hello%20world", [])).

url_decode_at_sign_test() ->
    % Percent encoding - %40 is @
    ?assertEqual("test@email.com", wade:url_decode("test%40email.com", [])).

url_decode_special_chars_test() ->
    % Multiple special characters
    ?assertEqual("a&b=c", wade:url_decode("a%26b%3Dc", [])).

url_decode_mixed_test() ->
    % Mix of plus and percent encoding
    ?assertEqual("hello world & test", 
                 wade:url_decode("hello+world+%26+test", [])).

%% =============================================================================
%% Path Parsing Tests
%% =============================================================================

parse_path_root_test() ->
    % Root path should return empty list
    Pattern = wade:parse_pattern("/"),
    ?assertEqual([], Pattern).

parse_path_simple_test() ->
    % Simple path without parameters
    Pattern = wade:parse_pattern("/users"),
    ?assertEqual([{literal, "users"}], Pattern).

parse_path_nested_test() ->
    % Nested path without parameters
    Pattern = wade:parse_pattern("/api/users"),
    ?assertEqual([{literal, "api"}, {literal, "users"}], Pattern).

parse_path_with_param_test() ->
    % Path with single parameter
    Pattern = wade:parse_pattern("/users/[id]"),
    ?assertEqual([{literal, "users"}, {param, id}], Pattern).

parse_path_multiple_params_test() ->
    % Path with multiple parameters
    Pattern = wade:parse_pattern("/users/[id]/posts/[post_id]"),
    ?assertEqual([{literal, "users"}, {param, id}, 
                  {literal, "posts"}, {param, post_id}], Pattern).

parse_path_no_leading_slash_test() ->
    % Path without leading slash should still parse
    Pattern = wade:parse_pattern("users/[id]"),
    ?assertEqual([{literal, "users"}, {param, id}], Pattern).

%% =============================================================================
%% Pattern Matching Tests
%% =============================================================================

match_pattern_exact_test() ->
    % Exact literal match
    Pattern = [{literal, "users"}],
    Path = ["users"],
    ?assertEqual({ok, []}, wade:match_pattern(Pattern, Path, [])).

match_pattern_with_param_test() ->
    % Match with single parameter
    Pattern = [{literal, "users"}, {param, id}],
    Path = ["users", "123"],
    ?assertEqual({ok, [{id, "123"}]}, wade:match_pattern(Pattern, Path, [])).

match_pattern_multiple_params_test() ->
    % Match with multiple parameters
    Pattern = [{literal, "users"}, {param, id}, {literal, "posts"}, {param, post_id}],
    Path = ["users", "42", "posts", "99"],
    ?assertEqual({ok, [{id, "42"}, {post_id, "99"}]}, 
                 wade:match_pattern(Pattern, Path, [])).

match_pattern_mismatch_test() ->
    % No match when literal doesn't match
    Pattern = [{literal, "users"}, {param, id}],
    Path = ["posts", "123"],
    ?assertEqual(no_match, wade:match_pattern(Pattern, Path, [])).

match_pattern_length_mismatch_test() ->
    % No match when path length differs
    Pattern = [{literal, "users"}],
    Path = ["users", "extra"],
    ?assertEqual(no_match, wade:match_pattern(Pattern, Path, [])).

match_pattern_empty_test() ->
    % Empty pattern and path should match
    ?assertEqual({ok, []}, wade:match_pattern([], [], [])).

%% =============================================================================
%% Integration Tests
%% =============================================================================

full_query_parse_integration_test() ->
    % End-to-end query parsing with complex data
    QueryString = "name=John+Doe&email=john%40example.com&age=30&active",
    Result = wade:parse_query(QueryString),
    ?assertEqual([{name, "John Doe"}, 
                  {email, "john@example.com"}, 
                  {age, "30"}, 
                  {active, ""}], Result).

full_request_helpers_integration_test() ->
    % Test all helper functions working together
    Req = #req{
        method = post,
        params = [{user_id, "100"}],
        query = [{sort, "asc"}, {limit, "10"}],
        body = [{username, "alice"}, {email, "alice@test.com"}]
    },
    ?assertEqual(post, wade:method(Req)),
    ?assertEqual("100", wade:param(Req, user_id)),
    ?assertEqual("asc", wade:query(Req, sort)),
    ?assertEqual("10", wade:query(Req, limit)),
    ?assertEqual("alice", wade:body(Req, username)),
    ?assertEqual("alice@test.com", wade:body(Req, email)),
    ?assertEqual("default", wade:query(Req, missing, "default")).

%% =============================================================================
%% Test Helpers
%% =============================================================================

-record(mod, {
    method,
    request_uri,
    parsed_header,
    entity_body,
    socket,
    data = []
}).

create_mod_data(Method, URI, Body, Headers) ->
    % Create a mock mod record for testing
    #mod{
        method = Method,
        request_uri = URI,
        parsed_header = Headers,
        entity_body = Body,
        socket = undefined,
        data = []
    }.
