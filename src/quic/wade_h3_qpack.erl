%% @doc QPACK (QPACK: Header Compression for HTTP/3) implementation
%% Static table only for initial implementation (RFC 9204)
-module(wade_h3_qpack).

-export([
    encode/1,
    decode/1,
    encode_field_line/1,
    decode_field_line/1
]).

%% QPACK static table (subset of most common headers)
-define(STATIC_TABLE, [
    {0, {<<":authority">>, <<>>}},
    {1, {<<":path">>, <<"/">>}},
    {2, {<<":method">>, <<"GET">>}},
    {3, {<<":method">>, <<"POST">>}},
    {4, {<<":scheme">>, <<"http">>}},
    {5, {<<":scheme">>, <<"https">>}},
    {6, {<<":status">>, <<"200">>}},
    {7, {<<":status">>, <<"204">>}},
    {8, {<<":status">>, <<"206">>}},
    {9, {<<":status">>, <<"304">>}},
    {10, {<<":status">>, <<"400">>}},
    {11, {<<":status">>, <<"404">>}},
    {12, {<<":status">>, <<"500">>}},
    {13, {<<"accept">>, <<"*/*">>}},
    {14, {<<"accept-encoding">>, <<"gzip, deflate, br">>}},
    {15, {<<"accept-ranges">>, <<"bytes">>}},
    {16, {<<"access-control-allow-origin">>, <<"*">>}},
    {17, {<<"age">>, <<"0">>}},
    {18, {<<"cache-control">>, <<"max-age=0">>}},
    {19, {<<"cache-control">>, <<"no-cache">>}},
    {20, {<<"cache-control">>, <<"no-store">>}},
    {21, {<<"content-encoding">>, <<"br">>}},
    {22, {<<"content-encoding">>, <<"gzip">>}},
    {23, {<<"content-length">>, <<"0">>}},
    {24, {<<"content-type">>, <<"application/dns-message">>}},
    {25, {<<"content-type">>, <<"application/javascript">>}},
    {26, {<<"content-type">>, <<"application/json">>}},
    {27, {<<"content-type">>, <<"text/html; charset=utf-8">>}},
    {28, {<<"content-type">>, <<"text/plain; charset=utf-8">>}},
    {29, {<<"date">>, <<>>}},
    {30, {<<"server">>, <<>>}},
    {31, {<<"vary">>, <<"accept-encoding">>}}
]).

%% =============================================================================
%% Public API
%% =============================================================================

%% @doc Encode list of headers to QPACK format
-spec encode([{binary(), binary()}]) -> {ok, binary()} | {error, term()}.
encode(Headers) ->
    try
        %% Encode each header field
        EncodedFields = [encode_field_line({Name, Value}) || {Name, Value} <- Headers],
        
        %% Build QPACK encoded field section
        %% Prefix: Required Insert Count (0) and Base (0) for static table only
        Prefix = <<0:8, 0:8>>,  % Simplified: no dynamic table
        
        FieldSection = iolist_to_binary(EncodedFields),
        {ok, <<Prefix/binary, FieldSection/binary>>}
    catch
        _:Err -> {error, Err}
    end.

%% @doc Decode QPACK format to list of headers
-spec decode(binary()) -> {ok, [{binary(), binary()}]} | {error, term()}.
decode(Data) ->
    try
        %% Skip prefix (Required Insert Count and Base)
        <<_Prefix:16, FieldSection/binary>> = Data,
        
        %% Decode field lines
        Headers = decode_field_section(FieldSection, []),
        {ok, Headers}
    catch
        _:Err -> {error, Err}
    end.

%% @doc Encode a single field line
-spec encode_field_line({binary(), binary()}) -> binary().
encode_field_line({Name, Value}) ->
    %% Try to find in static table
    case find_in_static_table(Name, Value) of
        {indexed, Index} ->
            %% Indexed Field Line (full match)
            encode_indexed_field_line(Index);
        
        {name_ref, Index} ->
            %% Literal Field Line With Name Reference
            encode_literal_with_name_ref(Index, Value);
        
        not_found ->
            %% Literal Field Line With Literal Name
            encode_literal_with_literal_name(Name, Value)
    end.

%% @doc Decode a single field line
-spec decode_field_line(binary()) -> {{binary(), binary()}, binary()}.
decode_field_line(<<1:1, Rest/bitstring>>) ->
    %% Indexed Field Line (1xxxxxxx)
    try
        {Index, Rest1} = decode_integer(7, Rest),
        {Name, Value} = get_from_static_table(Index),
        {{Name, Value}, Rest1}
    catch
        _:_ -> {{<<>>, <<>>}, <<>>}
    end;

decode_field_line(<<0:1, 1:1, Rest/bitstring>>) ->
    %% Literal Field Line With Name Reference (01xxxxxx)
    try
        {NameIndex, Rest1} = decode_integer(6, Rest),
        {Name, _} = get_from_static_table(NameIndex),
        {ValueLen, Rest2} = decode_integer(7, Rest1),
        case Rest2 of
            <<Value:ValueLen/binary, Rest3/binary>> ->
                {{Name, Value}, Rest3};
            _ ->
                {{<<>>, <<>>}, Rest2}
        end
    catch
        _:_ -> {{<<>>, <<>>}, <<>>}
    end;

decode_field_line(<<0:1, 0:1, 1:1, Rest/bitstring>>) ->
    %% Literal Field Line With Literal Name (001xxxxx)
    try
        {NameLen, Rest1} = decode_integer(5, Rest),
        case Rest1 of
            <<Name:NameLen/binary, Rest2/binary>> ->
                {ValueLen, Rest3} = decode_integer(7, Rest2),
                case Rest3 of
                    <<Value:ValueLen/binary, Rest4/binary>> ->
                        {{Name, Value}, Rest4};
                    _ ->
                        {{<<>>, <<>>}, Rest3}
                end;
            _ ->
                {{<<>>, <<>>}, Rest1}
        end
    catch
        _:_ -> {{<<>>, <<>>}, <<>>}
    end;

decode_field_line(Data) ->
    %% Unknown format or error
    {{<<>>, <<>>}, Data}.

%% =============================================================================
%% Internal Functions - Encoding
%% =============================================================================

%% @doc Encode indexed field line
encode_indexed_field_line(Index) ->
    %% Format: 1xxxxxxx (indexed)
    encode_integer(7, Index, <<1:1>>).

%% @doc Encode literal field line with name reference
encode_literal_with_name_ref(NameIndex, Value) ->
    %% Format: 01xxxxxx (literal with name ref)
    NameEncoded = encode_integer(6, NameIndex, <<0:1, 1:1>>),
    ValueLen = byte_size(Value),
    ValueLenEncoded = encode_integer(7, ValueLen, <<0:1>>),
    <<NameEncoded/bitstring, ValueLenEncoded/bitstring, Value/binary>>.

%% @doc Encode literal field line with literal name
encode_literal_with_literal_name(Name, Value) ->
    %% Format: 001xxxxx (literal with literal name)
    NameLen = byte_size(Name),
    NameLenEncoded = encode_integer(5, NameLen, <<0:1, 0:1, 1:1>>),
    ValueLen = byte_size(Value),
    ValueLenEncoded = encode_integer(7, ValueLen, <<0:1>>),
    <<NameLenEncoded/bitstring, Name/binary, 
      ValueLenEncoded/bitstring, Value/binary>>.

%% @doc Encode integer with N-bit prefix (HPACK/QPACK integer encoding)
encode_integer(N, Value, Prefix) when Value < (1 bsl N) - 1 ->
    PrefixSize = bit_size(Prefix),
    <<PrefixBits:PrefixSize>> = Prefix,
    Bits = 8 - N,
    <<PrefixBits:Bits, Value:N>>;
encode_integer(N, Value, Prefix) ->
    MaxPrefix = (1 bsl N) - 1,
    PrefixSize = bit_size(Prefix),
    <<PrefixBits:PrefixSize>> = Prefix,
    Bits = 8 - N,
    FirstByte = <<PrefixBits:Bits, MaxPrefix:N>>,
    Remainder = Value - MaxPrefix,
    RestBytes = encode_integer_continuation(Remainder),
    <<FirstByte/binary, RestBytes/binary>>.

encode_integer_continuation(Value) when Value < 128 ->
    <<Value:8>>;
encode_integer_continuation(Value) ->
    Byte = (Value rem 128) bor 128,
    Rest = encode_integer_continuation(Value div 128),
    <<Byte:8, Rest/binary>>.

%% =============================================================================
%% Internal Functions - Decoding
%% =============================================================================

%% @doc Decode field section into list of headers
decode_field_section(<<>>, Acc) ->
    lists:reverse(Acc);
decode_field_section(Data, Acc) ->
    {{Name, Value}, Rest} = decode_field_line(Data),
    case Name of
        <<>> -> lists:reverse(Acc);  % Invalid or end
        _ -> decode_field_section(Rest, [{Name, Value} | Acc])
    end.

%% @doc Decode integer with N-bit prefix
decode_integer(N, Data) ->
    MaxPrefix = (1 bsl N) - 1,
    Bits = 8 - N,
    case Data of
        <<_:Bits, Value:N, Rest/bitstring>> when Value < MaxPrefix ->
            {Value, Rest};
        <<_:Bits, MaxPrefix:N, Rest/bitstring>> ->
            %% Continuation bytes follow
            decode_integer_continuation(MaxPrefix, Rest);
        _ ->
            {0, Data}
    end.

decode_integer_continuation(Acc, Data) ->
    case Data of
        <<Byte:8, Rest/binary>> when Byte >= 128 ->
            NewAcc = Acc + (Byte band 16#7F),
            decode_integer_continuation(NewAcc, Rest);
        <<Byte:8, Rest/binary>> ->
            FinalValue = Acc + Byte,
            {FinalValue, Rest};
        _ ->
            {Acc, Data}
    end.

%% =============================================================================
%% Static Table Functions
%% =============================================================================

%% @doc Find header in static table
find_in_static_table(Name, Value) ->
    case lists:keyfind({Name, Value}, 2, ?STATIC_TABLE) of
        {Index, _} ->
            {indexed, Index};
        false ->
            %% Try to find name only
            case find_name_in_static_table(Name) of
                {ok, Index} -> {name_ref, Index};
                not_found -> not_found
            end
    end.

%% @doc Find name only in static table
find_name_in_static_table(Name) ->
    case lists:keyfind(Name, 1, [Entry || {_, Entry} <- ?STATIC_TABLE]) of
        {Name, _} ->
            %% Find the index
            case [Idx || {Idx, {N, _}} <- ?STATIC_TABLE, N =:= Name] of
                [Index | _] -> {ok, Index};
                [] -> not_found
            end;
        false ->
            not_found
    end.

%% @doc Get entry from static table by index
get_from_static_table(Index) ->
    case lists:keyfind(Index, 1, ?STATIC_TABLE) of
        {Index, Entry} -> Entry;
        false -> {<<>>, <<>>}
    end.
