%% @doc QUIC protocol constants and record definitions

%% QUIC version
-define(QUIC_VERSION_1, 16#00000001).
-define(QUIC_VERSION_DRAFT_29, 16#ff00001d).

%% Packet types
-define(PACKET_TYPE_INITIAL, initial).
-define(PACKET_TYPE_0RTT, zero_rtt).
-define(PACKET_TYPE_HANDSHAKE, handshake).
-define(PACKET_TYPE_RETRY, retry).
-define(PACKET_TYPE_1RTT, one_rtt).

%% Frame types
-define(FRAME_PADDING, 16#00).
-define(FRAME_PING, 16#01).
-define(FRAME_ACK, 16#02).
-define(FRAME_ACK_ECN, 16#03).
-define(FRAME_RESET_STREAM, 16#04).
-define(FRAME_STOP_SENDING, 16#05).
-define(FRAME_CRYPTO, 16#06).
-define(FRAME_NEW_TOKEN, 16#07).
-define(FRAME_STREAM, 16#08).  % 0x08-0x0f
-define(FRAME_MAX_DATA, 16#10).
-define(FRAME_MAX_STREAM_DATA, 16#11).
-define(FRAME_MAX_STREAMS_BIDI, 16#12).
-define(FRAME_MAX_STREAMS_UNI, 16#13).
-define(FRAME_DATA_BLOCKED, 16#14).
-define(FRAME_STREAM_DATA_BLOCKED, 16#15).
-define(FRAME_STREAMS_BLOCKED_BIDI, 16#16).
-define(FRAME_STREAMS_BLOCKED_UNI, 16#17).
-define(FRAME_NEW_CONNECTION_ID, 16#18).
-define(FRAME_RETIRE_CONNECTION_ID, 16#19).
-define(FRAME_PATH_CHALLENGE, 16#1a).
-define(FRAME_PATH_RESPONSE, 16#1b).
-define(FRAME_CONNECTION_CLOSE_QUIC, 16#1c).
-define(FRAME_CONNECTION_CLOSE_APP, 16#1d).
-define(FRAME_HANDSHAKE_DONE, 16#1e).

%% Encryption levels
-define(ENCRYPTION_INITIAL, initial).
-define(ENCRYPTION_HANDSHAKE, handshake).
-define(ENCRYPTION_APPLICATION, application).

%% Transport parameters
-define(TP_ORIGINAL_DESTINATION_CONNECTION_ID, 16#00).
-define(TP_MAX_IDLE_TIMEOUT, 16#01).
-define(TP_STATELESS_RESET_TOKEN, 16#02).
-define(TP_MAX_UDP_PAYLOAD_SIZE, 16#03).
-define(TP_INITIAL_MAX_DATA, 16#04).
-define(TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 16#05).
-define(TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 16#06).
-define(TP_INITIAL_MAX_STREAM_DATA_UNI, 16#07).
-define(TP_INITIAL_MAX_STREAMS_BIDI, 16#08).
-define(TP_INITIAL_MAX_STREAMS_UNI, 16#09).
-define(TP_ACK_DELAY_EXPONENT, 16#0a).
-define(TP_MAX_ACK_DELAY, 16#0b).
-define(TP_DISABLE_ACTIVE_MIGRATION, 16#0c).
-define(TP_PREFERRED_ADDRESS, 16#0d).
-define(TP_ACTIVE_CONNECTION_ID_LIMIT, 16#0e).
-define(TP_INITIAL_SOURCE_CONNECTION_ID, 16#0f).
-define(TP_RETRY_SOURCE_CONNECTION_ID, 16#10).

%% Error codes
-define(ERROR_NO_ERROR, 16#00).
-define(ERROR_INTERNAL_ERROR, 16#01).
-define(ERROR_CONNECTION_REFUSED, 16#02).
-define(ERROR_FLOW_CONTROL_ERROR, 16#03).
-define(ERROR_STREAM_LIMIT_ERROR, 16#04).
-define(ERROR_STREAM_STATE_ERROR, 16#05).
-define(ERROR_FINAL_SIZE_ERROR, 16#06).
-define(ERROR_FRAME_ENCODING_ERROR, 16#07).
-define(ERROR_TRANSPORT_PARAMETER_ERROR, 16#08).
-define(ERROR_CONNECTION_ID_LIMIT_ERROR, 16#09).
-define(ERROR_PROTOCOL_VIOLATION, 16#0a).
-define(ERROR_INVALID_TOKEN, 16#0b).
-define(ERROR_APPLICATION_ERROR, 16#0c).
-define(ERROR_CRYPTO_BUFFER_EXCEEDED, 16#0d).
-define(ERROR_KEY_UPDATE_ERROR, 16#0e).
-define(ERROR_AEAD_LIMIT_REACHED, 16#0f).
-define(ERROR_NO_VIABLE_PATH, 16#10).
-define(ERROR_CRYPTO_ERROR, 16#0100).  % 0x0100-0x01ff

%% Records

%% QUIC packet header
-record(quic_header, {
    form :: long | short,
    version :: integer() | undefined,
    packet_type :: initial | zero_rtt | handshake | retry | one_rtt,
    dest_conn_id :: binary(),
    src_conn_id :: binary() | undefined,
    token :: binary() | undefined,
    packet_number :: integer() | undefined,
    packet_number_length :: 1..4 | undefined
}).

%% QUIC frame (generic)
-record(quic_frame, {
    type :: atom(),
    data :: term()
}).

%% STREAM frame
-record(stream_frame, {
    stream_id :: integer(),
    offset :: integer(),
    length :: integer() | undefined,
    fin :: boolean(),
    data :: binary()
}).

%% CRYPTO frame
-record(crypto_frame, {
    offset :: integer(),
    length :: integer(),
    data :: binary()
}).

%% ACK frame
-record(ack_frame, {
    largest_acked :: integer(),
    ack_delay :: integer(),
    ack_ranges :: [{integer(), integer()}],  % [{first, last}]
    ecn_counts :: {integer(), integer(), integer()} | undefined
}).

%% CONNECTION_CLOSE frame
-record(connection_close_frame, {
    error_code :: integer(),
    frame_type :: integer() | undefined,
    reason :: binary()
}).

%% NEW_CONNECTION_ID frame
-record(new_connection_id_frame, {
    sequence_number :: integer(),
    retire_prior_to :: integer(),
    connection_id :: binary(),
    stateless_reset_token :: binary()
}).

%% Connection state
-record(conn_state, {
    role :: client | server,
    state :: initial | handshake | established | closing | draining | closed,
    remote_ip :: inet:ip_address(),
    remote_port :: inet:port_number(),
    
    %% Connection IDs
    local_conn_ids :: [binary()],
    remote_conn_ids :: [binary()],
    dest_conn_id :: binary(),
    src_conn_id :: binary(),
    
    %% Packet numbers
    next_packet_number = 0 :: integer(),
    largest_received_packet = -1 :: integer(),
    
    %% Cryptography
    crypto_state :: map(),  % Encryption keys per level
    tls_state :: term(),
    
    %% Flow control
    max_data_local = 1048576 :: integer(),  % 1MB
    max_data_remote = 1048576 :: integer(),
    data_sent = 0 :: integer(),
    data_received = 0 :: integer(),
    
    %% Streams
    streams = #{} :: #{integer() => pid()},
    next_stream_id_bidi = 0 :: integer(),
    next_stream_id_uni = 2 :: integer(),
    max_streams_bidi = 100 :: integer(),
    max_streams_uni = 100 :: integer(),
    
    %% Timers
    idle_timeout = 30000 :: integer(),  % 30 seconds
    last_activity :: integer() | undefined,
    
    %% Loss detection
    ack_eliciting_sent = [] :: [integer()],
    acked_packets = [] :: [integer()],
    
    %% Routing
    routes = [] :: list(),
    
    %% Options
    certfile :: string(),
    keyfile :: string(),
    alpn = [<<"h3">>] :: [binary()]
}).

%% Stream state
-record(stream_state, {
    stream_id :: integer(),
    conn_pid :: pid(),
    type :: bidi | uni,
    direction :: local | remote,
    state :: idle | open | half_closed_local | half_closed_remote | closed,
    
    %% Flow control
    max_data_local :: integer(),
    max_data_remote :: integer(),
    data_sent = 0 :: integer(),
    data_received = 0 :: integer(),
    
    %% Buffers
    send_buffer = <<>> :: binary(),
    recv_buffer = <<>> :: binary(),
    recv_offset = 0 :: integer(),
    
    %% Fin flags
    fin_sent = false :: boolean(),
    fin_received = false :: boolean(),
    
    %% HTTP/3 specific
    h3_handler :: pid() | undefined
}).

%% Crypto state per encryption level
-record(crypto_keys, {
    level :: initial | handshake | application,
    header_key :: binary(),
    iv :: binary(),
    key :: binary()
}).

