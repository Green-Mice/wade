%% wade_ws_client.hrl
%% Header file for Wade WebSocket client module
%% Defines record types used internally in Wade WebSocket client

-ifndef(WADE_WS_CLIENT_HRL).
-define(WADE_WS_CLIENT_HRL, true).

-record(state, {
    host,                       %% string() or atom() - target host to connect to via WebSocket
    port,                       %% integer() - TCP port number for connection, usually 80 or 443 (TLS)
    path,                       %% string() - HTTP URI path with query part, e.g. "/?v=10&encoding=json"
    socket,                     %% ssl:sslsocket() or undefined - TLS/TCP connection socket
    parent,                     %% pid() - process pid to send WebSocket messages and events to
    recv_buffer = <<>>,         %% binary() - buffered incoming data not yet fully parsed
    ws_established = false      %% boolean() - whether WebSocket handshake completed successfully
}).

-endif.

