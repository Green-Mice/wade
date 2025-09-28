-module(wade_test).
-include_lib("eunit/include/eunit.hrl").

parse_query_test() ->
    ?assertEqual([], wade:parse_query("")),
    ?assertEqual([{k,"100"}], wade:parse_query("k=100")),
    ?assertEqual([{k,"100"},{j,"200"}], wade:parse_query("k=100&j=200")).
