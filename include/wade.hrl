%%%-------------------------------------------------------------------
%%% @doc Wade framework header file
%%%-------------------------------------------------------------------

-record(req, {
    method :: atom(),           % HTTP method (get, post, put, delete, etc.)
    path :: string(),           % Request path
    query = [] :: list(),       % Parsed query parameters
    body = [] :: term(),        % Parsed body (proplist or raw)
    headers = [] :: list(),     % HTTP headers
    params = [] :: list(),      % Path parameters from route matching
    reply_status :: integer() | undefined,  % Status code for reply
    reply_headers = #{} :: map(),           % Headers for reply
    reply_body = <<>> :: binary()           % Body for reply
}).

-record(route, {
    method :: atom(),           % HTTP method or 'any'
    pattern :: list(),          % Parsed route pattern
    handler :: term()           % Handler function or MFA
}).

-record(state, {
    port :: integer(),          % Server port
    httpd_pid :: pid(),         % Inets HTTPD process PID
    routes = [] :: list(),      % List of registered routes
    dispatch = [] :: list()     % Dispatch table for module-based routing
}).
