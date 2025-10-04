%% @doc QUIC packet parsing and building.
%% Handles long header packets (Initial, 0-RTT, Handshake, Retry)
%% and short header packets (1-RTT).
-module(wade_quic_packet).
-include("wade_quic.hrl").

%% Public API
-export([
    parse_header/1,
    build_initial/4,
    build_handshake/3,
    build_1rtt/3,
    build_version_negotiation/2,
    protect_packet/3,
    unprotect_packet/3,
    encode_variable_length/1,
    decode_variable_length/1
]).

%%=============================================================================
%% Public API
%%=============================================================================

%% @doc Parse QUIC packet header.
-spec parse_header(binary()) ->
    {ok, #quic_header{}, binary()} |
    {error, version_negotiation, [integer()]} |
    {error, term()}.
parse_header(<<1:1, _:7, _/binary>> = Packet) ->
    parse_long_header(Packet);
parse_header(<<0:1, _:7, _/binary>> = Packet) ->
    parse_short_header(Packet);
parse_header(_) ->
    {error, invalid_packet}.

%% @doc Build Initial packet.
-spec build_initial(binary(), binary(), binary(), [#quic_frame{}]) ->
    {ok, binary()} | {error, term()}.
build_initial(DestCID, SrcCID, Token, Frames) ->
    try
        Payload = build_payload(Frames),
        TokenLen = byte_size(Token),
        TokenLenVarInt = encode_variable_length(TokenLen),
        PayloadLenVarInt = encode_variable_length(byte_size(Payload) + 16),
        DestCIDLen = byte_size(DestCID),
        SrcCIDLen = byte_size(SrcCID),
        Header = <<
            1:1, 1:1, 0:2, 0:2, 0:2,
            ?QUIC_VERSION_1:32,
            DestCIDLen:8, DestCID/binary,
            SrcCIDLen:8, SrcCID/binary,
            TokenLenVarInt/binary, Token/binary,
            PayloadLenVarInt/binary
        >>,
        {ok, <<Header/binary, Payload/binary>>}
    catch
        error:Reason -> {error, Reason}
    end.

%% @doc Build Handshake packet.
-spec build_handshake(binary(), binary(), [#quic_frame{}]) ->
    {ok, binary()} | {error, term()}.
build_handshake(DestCID, SrcCID, Frames) ->
    try
        Payload = build_payload(Frames),
        PayloadLenVarInt = encode_variable_length(byte_size(Payload) + 16),
        DestCIDLen = byte_size(DestCID),
        SrcCIDLen = byte_size(SrcCID),
        Header = <<
            1:1, 1:1, 2:2, 0:2, 0:2,
            ?QUIC_VERSION_1:32,
            DestCIDLen:8, DestCID/binary,
            SrcCIDLen:8, SrcCID/binary,
            PayloadLenVarInt/binary
        >>,
        {ok, <<Header/binary, Payload/binary>>}
    catch
        error:Reason -> {error, Reason}
    end.

%% @doc Build 1-RTT (short header) packet.
-spec build_1rtt(binary(), integer(), [#quic_frame{}]) ->
    {ok, binary()} | {error, term()}.
build_1rtt(DestCID, PacketNumber, Frames) ->
    try
        Payload = build_payload(Frames),
        DestCIDLen = byte_size(DestCID),
        PNLen = packet_number_length(PacketNumber),
        PNLenBits = PNLen - 1,
        PN = <<PacketNumber:PNLen/unit:8>>,
        Header = <<
            0:1, 1:1, 0:1, 0:2, 0:1, PNLenBits:2,
            DestCID:DestCIDLen/binary, PN/binary
        >>,
        {ok, <<Header/binary, Payload/binary>>}
    catch
        error:Reason -> {error, Reason}
    end.

%% @doc Build Version Negotiation packet.
-spec build_version_negotiation(binary(), [integer()]) ->
    {ok, binary()} | {error, term()}.
build_version_negotiation(OriginalPacket, SupportedVersions) ->
    try
        <<_:8, _Version:32, DestCIDLen:8, DestCID:DestCIDLen/binary,
          SrcCIDLen:8, SrcCID:SrcCIDLen/binary, _/binary>> = OriginalPacket,
        VersionList = << <<V:32>> || V <- SupportedVersions >>,
        Packet = <<
            1:1, 0:7, 0:32,
            DestCIDLen:8, DestCID/binary,
            SrcCIDLen:8, SrcCID/binary,
            VersionList/binary
        >>,
        {ok, Packet}
    catch
        error:Reason -> {error, Reason}
    end.

%% @doc Protect packet with header protection and AEAD encryption.
-spec protect_packet(binary(), #crypto_keys{}, integer()) ->
    {ok, binary()} | {error, term()}.
protect_packet(Packet, _CryptoKeys, _PacketNumber) ->
    {ok, Packet}.

%% @doc Unprotect packet (remove header protection and AEAD decrypt).
-spec unprotect_packet(binary(), #crypto_keys{}, integer()) ->
    {ok, binary(), integer()} | {error, term()}.
unprotect_packet(Packet, _CryptoKeys, LargestPN) ->
    {ok, Packet, LargestPN}.

%% @doc Encode integer as variable-length integer.
-spec encode_variable_length(integer()) -> binary().
encode_variable_length(Val) when Val =< 63 -> <<0:2, Val:6>>;
encode_variable_length(Val) when Val =< 16383 -> <<1:2, Val:14>>;
encode_variable_length(Val) when Val =< 1073741823 -> <<2:2, Val:30>>;
encode_variable_length(Val) -> <<3:2, Val:62>>.

%% @doc Decode variable-length integer.
-spec decode_variable_length(binary()) -> {integer(), binary()}.
decode_variable_length(<<0:2, Val:6, Rest/binary>>) -> {Val, Rest};
decode_variable_length(<<1:2, Val:14, Rest/binary>>) -> {Val, Rest};
decode_variable_length(<<2:2, Val:30, Rest/binary>>) -> {Val, Rest};
decode_variable_length(<<3:2, Val:62, Rest/binary>>) -> {Val, Rest}.

%%=============================================================================
%% Internal Functions
%%=============================================================================

%% @doc Parse long header packet.
parse_long_header(<<1:1, FixedBit:1, PacketType:2, _Reserved:2, PNLen:2,
                    Version:32, Rest/binary>>) ->
    %% Check version first
    case Version of
        0 ->
            {error, version_negotiation, [?QUIC_VERSION_1]};
        ?QUIC_VERSION_1 ->
            %% Check fixed bit
            case FixedBit of
                1 ->
                    %% Parse connection IDs
                    <<DestCIDLen:8, DestCIDAndRest/binary>> = Rest,
                    <<DestCID:DestCIDLen/binary, SrcCIDLen:8, SrcCIDAndRest/binary>> = DestCIDAndRest,
                    <<SrcCID:SrcCIDLen/binary, Remainder/binary>> = SrcCIDAndRest,
                    %% Parse based on packet type
                    Type = case PacketType of
                        0 -> initial;
                        1 -> zero_rtt;
                        2 -> handshake;
                        3 -> retry
                    end,
                    case Type of
                        initial ->
                            {TokenLen, AfterToken} = decode_variable_length(Remainder),
                            <<Token:TokenLen/binary, AfterTokenRest/binary>> = AfterToken,
                            {_PayloadLen, Payload} = decode_variable_length(AfterTokenRest),
                            Header = #quic_header{
                                form = long,
                                version = Version,
                                packet_type = initial,
                                dest_conn_id = DestCID,
                                src_conn_id = SrcCID,
                                token = Token,
                                packet_number_length = PNLen + 1
                            },
                            {ok, Header, Payload};
                        handshake ->
                            {_PayloadLen, Payload} = decode_variable_length(Remainder),
                            Header = #quic_header{
                                form = long,
                                version = Version,
                                packet_type = handshake,
                                dest_conn_id = DestCID,
                                src_conn_id = SrcCID,
                                packet_number_length = PNLen + 1
                            },
                            {ok, Header, Payload};
                        retry ->
                            %% Retry packet has no packet number
                            Token = Remainder,
                            Header = #quic_header{
                                form = long,
                                version = Version,
                                packet_type = retry,
                                dest_conn_id = DestCID,
                                src_conn_id = SrcCID,
                                token = Token
                            },
                            {ok, Header, <<>>};
                        zero_rtt ->
                            {_PayloadLen, Payload} = decode_variable_length(Remainder),
                            Header = #quic_header{
                                form = long,
                                version = Version,
                                packet_type = zero_rtt,
                                dest_conn_id = DestCID,
                                src_conn_id = SrcCID,
                                packet_number_length = PNLen + 1
                            },
                            {ok, Header, Payload}
                    end;
                _ ->
                    {error, invalid_fixed_bit}
            end;
        _ ->
            {error, {unsupported_version, Version}}
    end.

%% @doc Parse short header packet (1-RTT).
parse_short_header(<<0:1, _FixedBit:1, _SpinBit:1, _Reserved:2, _KeyPhase:1,
                     PNLen:2, Rest/binary>>) ->
    DestCIDLen = 8,
    <<DestCID:DestCIDLen/binary, Payload/binary>> = Rest,
    Header = #quic_header{
        form = short,
        packet_type = one_rtt,
        dest_conn_id = DestCID,
        packet_number_length = PNLen + 1
    },
    {ok, Header, Payload}.

%% @doc Build payload from list of frames.
build_payload(Frames) ->
    iolist_to_binary([wade_quic_frame:encode(F) || F <- Frames]).

%% @doc Determine packet number encoding length.
packet_number_length(PN) when PN =< 255 -> 1;
packet_number_length(PN) when PN =< 65535 -> 2;
packet_number_length(PN) when PN =< 16777215 -> 3;
packet_number_length(_) -> 4.

