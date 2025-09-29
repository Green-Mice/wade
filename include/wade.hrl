%% wade.hrl
%% Header file for Wade HTTP server library
%% Contains shared record definitions

-ifndef(WADE_HRL).
-define(WADE_HRL, true).

%% HTTP Request record
%% Used to represent parsed HTTP requests with all components
-record(req, {
    method,              % HTTP method atom (get, post, put, delete, etc.)
    path,                % Request path string
    query = [],          % Query parameters as proplist [{Key, Value}]
    body = [],           % Body parameters as proplist [{Key, Value}]
    params = [],         % Path parameters as proplist [{Key, Value}]
    headers = []         % HTTP headers as proplist [{Key, Value}]
}).

%% Server State record
%% Maintains the Wade server's internal state
-record(state, {
    port,                % Port number the HTTP server is listening on
    httpd_pid,           % PID of the inets httpd process
    routes = []          % List of registered routes (route records)
}).

%% Route record
%% Represents a single route definition with its handler
-record(route, {
    method,              % HTTP method (get, post, any, etc.) or 'any' for all methods
    pattern,             % Parsed path pattern (list of {literal, "segment"} or {param, name})
    handler              % Tuple: {HandlerFun, RequiredParams, RequiredHeaders}
}).

-endif.
