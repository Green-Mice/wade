-module(wade_ws_tests).
-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% Test Suite: WebSocket frame building and parsing
%%--------------------------------------------------------------------

%% Test generator for build_ws_frame/2 function.
build_ws_frame_test_() ->
    MaxPayload = binary:copy(<<"a">>, 125), % 125 bytes max short payload
    ExpectedMaxFrame = <<129, 125, MaxPayload/binary>>,

    [
        {"build text frame with small payload",
         fun() ->
             ?_assertEqual(<<129,5,104,101,108,108,111>>, wade:build_ws_frame(1, <<"hello">>))
         end},

        {"build close frame with empty payload",
         fun() ->
             ?_assertEqual(<<136,0>>, wade:build_ws_frame(8, <<>>))
         end},

        {"build pong frame with payload",
         fun() ->
             ?_assertEqual(<<138,4,112,111,110,103>>, wade:build_ws_frame(10, <<"pong">>))
         end},

        {"build text frame with empty payload",
         fun() ->
             ?_assertEqual(<<129,0>>, wade:build_ws_frame(1, <<>>))
         end},

        {"build text frame with max short payload length",
         fun() ->
             ?_assertEqual(ExpectedMaxFrame, wade:build_ws_frame(1, MaxPayload))
         end},

        {"build frame with unsupported opcode returns error",
         fun() ->
             ?_assertMatch({error, unsupported_opcode, 99}, wade:build_ws_frame(99, <<"xyz">>))
         end}
    ].

%% Test generator for parse_ws_frame/1 function.
parse_ws_frame_test_() ->
    [
        {"parse valid text frame yields {text, String}",
         fun() ->
             ?_assertEqual({text, "hello"}, wade:parse_ws_frame(<<129,5,104,101,108,108,111>>))
         end},

        {"parse valid close frame yields {close, <<>>}",
         fun() ->
             ?_assertEqual({close, <<>>}, wade:parse_ws_frame(<<136,0>>))
         end},

        {"parse valid ping frame yields {ping, Payload}",
         fun() ->
             ?_assertEqual({ping, <<"ping">>}, wade:parse_ws_frame(<<137,4,112,105,110,103>>))
         end},

        {"parse valid pong frame yields {pong, Payload}",
         fun() ->
             ?_assertEqual({pong, <<"pong">>}, wade:parse_ws_frame(<<138,4,112,111,110,103>>))
         end},

        {"parse zero-length text payload",
         fun() ->
             ?_assertEqual({text, ""}, wade:parse_ws_frame(<<129,0>>))
         end},

        {"parse unknown opcode yields {unknown, <<>>}",
         fun() ->
             ?_assertEqual({unknown, <<>>}, wade:parse_ws_frame(<<255,0>>))
         end}
    ].

%% Optional: Test the url_decode/1 function if exposed.
url_decode_test_() ->
    [
        {"url decode plus as space",
         fun() ->
             ?_assertEqual("hello world", wade:url_decode("hello+world"))
         end},

        {"url decode percent encoded",
         fun() ->
             ?_assertEqual("50% done", wade:url_decode("50%25+done"))
         end}
    ].

