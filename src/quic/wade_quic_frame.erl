%% @doc QUIC frame parsing and encoding
%% Handles all QUIC frame types (STREAM, CRYPTO, ACK, etc.)
-module(wade_quic_frame).

-include("wade_quic.hrl").

-export([
    parse/1,
    parse_all/1,
    encode/1,
    is_ack_eliciting/1
]).

%% =============================================================================
%% Public API
%% =============================================================================

%% @doc Parse a single frame from binary
-spec parse(binary()) -> {ok, #quic_frame{}, binary()} | {error, term()}.
parse(<<?FRAME_PADDING, Rest/binary>>) ->
    %% PADDING frames can be consecutive
    {PaddingLen, NonPadding} = count_padding(Rest, 1),
    Frame = #quic_frame{type = padding, data = PaddingLen},
    {ok, Frame, NonPadding};

parse(<<?FRAME_PING, Rest/binary>>) ->
    Frame = #quic_frame{type = ping, data = undefined},
    {ok, Frame, Rest};

parse(<<?FRAME_ACK, Rest/binary>>) ->
    parse_ack_frame(Rest, false);

parse(<<?FRAME_ACK_ECN, Rest/binary>>) ->
    parse_ack_frame(Rest, true);

parse(<<?FRAME_RESET_STREAM, Rest/binary>>) ->
    {StreamID, Rest1} = wade_quic_packet:decode_variable_length(Rest),
    {AppErrorCode, Rest2} = wade_quic_packet:decode_variable_length(Rest1),
    {FinalSize, Rest3} = wade_quic_packet:decode_variable_length(Rest2),
    Frame = #quic_frame{
        type = reset_stream,
        data = #{stream_id => StreamID, error_code => AppErrorCode, final_size => FinalSize}
    },
    {ok, Frame, Rest3};

parse(<<?FRAME_STOP_SENDING, Rest/binary>>) ->
    {StreamID, Rest1} = wade_quic_packet:decode_variable_length(Rest),
    {AppErrorCode, Rest2} = wade_quic_packet:decode_variable_length(Rest1),
    Frame = #quic_frame{
        type = stop_sending,
        data = #{stream_id => StreamID, error_code => AppErrorCode}
    },
    {ok, Frame, Rest2};

parse(<<?FRAME_CRYPTO, Rest/binary>>) ->
    {Offset, Rest1} = wade_quic_packet:decode_variable_length(Rest),
    {Length, Rest2} = wade_quic_packet:decode_variable_length(Rest1),
    <<Data:Length/binary, Rest3/binary>> = Rest2,
    Frame = #quic_frame{
        type = crypto,
        data = #crypto_frame{offset = Offset, length = Length, data = Data}
    },
    {ok, Frame, Rest3};

parse(<<?FRAME_NEW_TOKEN, Rest/binary>>) ->
    {TokenLen, Rest1} = wade_quic_packet:decode_variable_length(Rest),
    <<Token:TokenLen/binary, Rest2/binary>> = Rest1,
    Frame = #quic_frame{type = new_token, data = Token},
    {ok, Frame, Rest2};

parse(<<Type, Rest/binary>>) when Type >= ?FRAME_STREAM, Type =< 16#0f ->
    parse_stream_frame(Type, Rest);

parse(<<?FRAME_MAX_DATA, Rest/binary>>) ->
    {MaxData, Rest1} = wade_quic_packet:decode_variable_length(Rest),
    Frame = #quic_frame{type = max_data, data = MaxData},
    {ok, Frame, Rest1};

parse(<<?FRAME_MAX_STREAM_DATA, Rest/binary>>) ->
    {StreamID, Rest1} = wade_quic_packet:decode_variable_length(Rest),
    {MaxData, Rest2} = wade_quic_packet:decode_variable_length(Rest1),
    Frame = #quic_frame{
        type = max_stream_data,
        data = #{stream_id => StreamID, max_data => MaxData}
    },
    {ok, Frame, Rest2};

parse(<<?FRAME_MAX_STREAMS_BIDI, Rest/binary>>) ->
    {MaxStreams, Rest1} = wade_quic_packet:decode_variable_length(Rest),
    Frame = #quic_frame{type = max_streams_bidi, data = MaxStreams},
    {ok, Frame, Rest1};

parse(<<?FRAME_MAX_STREAMS_UNI, Rest/binary>>) ->
    {MaxStreams, Rest1} = wade_quic_packet:decode_variable_length(Rest),
    Frame = #quic_frame{type = max_streams_uni, data = MaxStreams},
    {ok, Frame, Rest1};

parse(<<?FRAME_CONNECTION_CLOSE_QUIC, Rest/binary>>) ->
    parse_connection_close(Rest, quic);

parse(<<?FRAME_CONNECTION_CLOSE_APP, Rest/binary>>) ->
    parse_connection_close(Rest, app);

parse(<<?FRAME_HANDSHAKE_DONE, Rest/binary>>) ->
    Frame = #quic_frame{type = handshake_done, data = undefined},
    {ok, Frame, Rest};

parse(<<Type, _/binary>>) ->
    {error, {unknown_frame_type, Type}};

parse(<<>>) ->
    {error, empty_buffer}.

%% @doc Parse all frames from a packet payload
-spec parse_all(binary()) -> {ok, [#quic_frame{}]} | {error, term()}.
parse_all(Payload) ->
    parse_all(Payload, []).

parse_all(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
parse_all(Payload, Acc) ->
    case parse(Payload) of
        {ok, Frame, Rest} ->
            parse_all(Rest, [Frame | Acc]);
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Encode frame to binary
-spec encode(#quic_frame{}) -> binary().
encode(#quic_frame{type = padding, data = Count}) ->
    <<0:(Count * 8)>>;

encode(#quic_frame{type = ping}) ->
    <<?FRAME_PING>>;

encode(#quic_frame{type = ack, data = #ack_frame{} = Ack}) ->
    encode_ack_frame(Ack);

encode(#quic_frame{type = crypto, data = #crypto_frame{} = Crypto}) ->
    OffsetVarInt = wade_quic_packet:encode_variable_length(Crypto#crypto_frame.offset),
    LengthVarInt = wade_quic_packet:encode_variable_length(Crypto#crypto_frame.length),
    <<?FRAME_CRYPTO, OffsetVarInt/binary, LengthVarInt/binary, 
      (Crypto#crypto_frame.data)/binary>>;

encode(#quic_frame{type = stream, data = #stream_frame{} = Stream}) ->
    encode_stream_frame(Stream);

encode(#quic_frame{type = max_data, data = MaxData}) ->
    MaxDataVarInt = wade_quic_packet:encode_variable_length(MaxData),
    <<?FRAME_MAX_DATA, MaxDataVarInt/binary>>;

encode(#quic_frame{type = max_stream_data, data = #{stream_id := SID, max_data := MaxData}}) ->
    SIDVarInt = wade_quic_packet:encode_variable_length(SID),
    MaxDataVarInt = wade_quic_packet:encode_variable_length(MaxData),
    <<?FRAME_MAX_STREAM_DATA, SIDVarInt/binary, MaxDataVarInt/binary>>;

encode(#quic_frame{type = connection_close, data = #connection_close_frame{} = Close}) ->
    encode_connection_close(Close);

encode(#quic_frame{type = handshake_done}) ->
    <<?FRAME_HANDSHAKE_DONE>>.

%% @doc Check if frame is ACK-eliciting
-spec is_ack_eliciting(#quic_frame{}) -> boolean().
is_ack_eliciting(#quic_frame{type = padding}) -> false;
is_ack_eliciting(#quic_frame{type = ack}) -> false;
is_ack_eliciting(#quic_frame{type = connection_close}) -> false;
is_ack_eliciting(_) -> true.

%% =============================================================================
%% Internal Functions
%% =============================================================================

%% @doc Count consecutive padding bytes
count_padding(<<0, Rest/binary>>, Count) ->
    count_padding(Rest, Count + 1);
count_padding(Rest, Count) ->
    {Count, Rest}.

%% @doc Parse ACK frame
parse_ack_frame(Data, HasECN) ->
    {LargestAcked, Rest1} = wade_quic_packet:decode_variable_length(Data),
    {AckDelay, Rest2} = wade_quic_packet:decode_variable_length(Rest1),
    {AckRangeCount, Rest3} = wade_quic_packet:decode_variable_length(Rest2),
    {FirstAckRange, Rest4} = wade_quic_packet:decode_variable_length(Rest3),
    
    %% Parse additional ACK ranges
    {AckRanges, Rest5} = parse_ack_ranges(AckRangeCount, Rest4, 
                                          LargestAcked, FirstAckRange, []),
    
    %% Parse ECN counts if present
    {ECNCounts, Rest6} = case HasECN of
        true ->
            {ECT0, R1} = wade_quic_packet:decode_variable_length(Rest5),
            {ECT1, R2} = wade_quic_packet:decode_variable_length(R1),
            {ECNCE, R3} = wade_quic_packet:decode_variable_length(R2),
            {{ECT0, ECT1, ECNCE}, R3};
        false ->
            {undefined, Rest5}
    end,
    
    Frame = #quic_frame{
        type = ack,
        data = #ack_frame{
            largest_acked = LargestAcked,
            ack_delay = AckDelay,
            ack_ranges = AckRanges,
            ecn_counts = ECNCounts
        }
    },
    {ok, Frame, Rest6}.

%% @doc Parse ACK ranges
parse_ack_ranges(0, Rest, _PrevSmallest, _FirstRange, Acc) ->
    {lists:reverse(Acc), Rest};
parse_ack_ranges(Count, Data, PrevSmallest, FirstRange, Acc) when Count > 0 ->
    First = PrevSmallest,
    Last = PrevSmallest - FirstRange,
    
    {Gap, Rest1} = wade_quic_packet:decode_variable_length(Data),
    {AckRange, Rest2} = wade_quic_packet:decode_variable_length(Rest1),
    
    NewSmallest = Last - Gap - 2,
    parse_ack_ranges(Count - 1, Rest2, NewSmallest, AckRange, 
                     [{First, Last} | Acc]).

%% @doc Encode ACK frame
encode_ack_frame(#ack_frame{largest_acked = LA, ack_delay = AD, 
                            ack_ranges = Ranges, ecn_counts = ECN}) ->
    LAVarInt = wade_quic_packet:encode_variable_length(LA),
    ADVarInt = wade_quic_packet:encode_variable_length(AD),
    
    %% Calculate first ACK range
    [{First, Last} | RestRanges] = Ranges,
    FirstRange = First - Last,
    RangeCount = length(RestRanges),
    
    RangeCountVarInt = wade_quic_packet:encode_variable_length(RangeCount),
    FirstRangeVarInt = wade_quic_packet:encode_variable_length(FirstRange),
    
    %% Encode additional ranges
    RangesEncoded = encode_ack_ranges(RestRanges, Last),
    
    ECNData = case ECN of
        {ECT0, ECT1, ECNCE} ->
            ECT0VarInt = wade_quic_packet:encode_variable_length(ECT0),
            ECT1VarInt = wade_quic_packet:encode_variable_length(ECT1),
            ECNCEVarInt = wade_quic_packet:encode_variable_length(ECNCE),
            <<ECT0VarInt/binary, ECT1VarInt/binary, ECNCEVarInt/binary>>;
        undefined ->
            <<>>
    end,
    
    FrameType = case ECN of
        undefined -> ?FRAME_ACK;
        _ -> ?FRAME_ACK_ECN
    end,
    
    <<FrameType, LAVarInt/binary, ADVarInt/binary, RangeCountVarInt/binary,
      FirstRangeVarInt/binary, RangesEncoded/binary, ECNData/binary>>.

encode_ack_ranges([], _PrevLast) ->
    <<>>;
encode_ack_ranges([{First, Last} | Rest], PrevLast) ->
    Gap = PrevLast - First - 2,
    AckRange = First - Last,
    GapVarInt = wade_quic_packet:encode_variable_length(Gap),
    RangeVarInt = wade_quic_packet:encode_variable_length(AckRange),
    RestEncoded = encode_ack_ranges(Rest, Last),
    <<GapVarInt/binary, RangeVarInt/binary, RestEncoded/binary>>.

%% @doc Parse STREAM frame
parse_stream_frame(Type, Data) ->
    %% Extract flags from type byte
    HasOffset = (Type band 16#04) =/= 0,
    HasLength = (Type band 16#02) =/= 0,
    HasFin = (Type band 16#01) =/= 0,
    
    {StreamID, Rest1} = wade_quic_packet:decode_variable_length(Data),
    
    {Offset, Rest2} = case HasOffset of
        true -> wade_quic_packet:decode_variable_length(Rest1);
        false -> {0, Rest1}
    end,
    
    {Length, StreamData, Rest3} = case HasLength of
        true ->
            {Len, R} = wade_quic_packet:decode_variable_length(Rest2),
            <<SD:Len/binary, R2/binary>> = R,
            {Len, SD, R2};
        false ->
            %% No length means data extends to end of packet
            {byte_size(Rest2), Rest2, <<>>}
    end,
    
    Frame = #quic_frame{
        type = stream,
        data = #stream_frame{
            stream_id = StreamID,
            offset = Offset,
            length = Length,
            fin = HasFin,
            data = StreamData
        }
    },
    {ok, Frame, Rest3}.

%% @doc Encode STREAM frame
encode_stream_frame(#stream_frame{stream_id = SID, offset = Offset, 
                                   length = Length, fin = Fin, data = Data}) ->
    %% Calculate type byte
    HasOffset = Offset =/= 0,
    HasLength = Length =/= undefined,
    
    OffsetBit = case HasOffset of true -> 1; false -> 0 end,
    LengthBit = case HasLength of true -> 1; false -> 0 end,
    FinBit = case Fin of true -> 1; false -> 0 end,
    
    Type = ?FRAME_STREAM bor (OffsetBit bsl 2) bor (LengthBit bsl 1) bor FinBit,
    
    SIDVarInt = wade_quic_packet:encode_variable_length(SID),
    
    OffsetData = case HasOffset of
        true -> wade_quic_packet:encode_variable_length(Offset);
        false -> <<>>
    end,
    
    LengthData = case HasLength of
        true -> wade_quic_packet:encode_variable_length(byte_size(Data));
        false -> <<>>
    end,
    
    <<Type, SIDVarInt/binary, OffsetData/binary, LengthData/binary, Data/binary>>.

%% @doc Parse CONNECTION_CLOSE frame
parse_connection_close(Data, Type) ->
    {ErrorCode, Rest1} = wade_quic_packet:decode_variable_length(Data),
    
    {FrameType, Rest2} = case Type of
        quic ->
            wade_quic_packet:decode_variable_length(Rest1);
        app ->
            {undefined, Rest1}
    end,
    
    {ReasonLen, Rest3} = wade_quic_packet:decode_variable_length(Rest2),
    <<Reason:ReasonLen/binary, Rest4/binary>> = Rest3,
    
    Frame = #quic_frame{
        type = connection_close,
        data = #connection_close_frame{
            error_code = ErrorCode,
            frame_type = FrameType,
            reason = Reason
        }
    },
    {ok, Frame, Rest4}.

%% @doc Encode CONNECTION_CLOSE frame
encode_connection_close(#connection_close_frame{error_code = EC, 
                                                 frame_type = FT, 
                                                 reason = Reason}) ->
    ECVarInt = wade_quic_packet:encode_variable_length(EC),
    
    FTData = case FT of
        undefined ->
            <<?FRAME_CONNECTION_CLOSE_APP, ECVarInt/binary>>;
        _ ->
            FTVarInt = wade_quic_packet:encode_variable_length(FT),
            <<?FRAME_CONNECTION_CLOSE_QUIC, ECVarInt/binary, FTVarInt/binary>>
    end,
    
    ReasonLen = byte_size(Reason),
    ReasonLenVarInt = wade_quic_packet:encode_variable_length(ReasonLen),
    
    <<FTData/binary, ReasonLenVarInt/binary, Reason/binary>>.

