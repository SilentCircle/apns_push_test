-module(aptest_util).
-export([
        msg/2,
        hexdump/1
    ]).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------
msg(Fmt, Args) ->
    {TsFmt, TsArgs} = add_ts(Fmt, Args),
    io:format(standard_error, TsFmt, TsArgs).

hexdump(<<B/binary>>) ->
    hexdump_line(B, 16, 0).

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------
hexdump_line(<<>>, _Len, _Offs) ->
    ok;
hexdump_line(<<B/binary>>, Len, Offs) when byte_size(B) =< Len ->
    io:put_chars([hex_offset(Offs, 8), $:, $\s,
                  << <<(xdigit(U)), (xdigit(L)), $\s>>
                  || <<U:4, L:4>> <= B >>,
                  pad(B, Len), $\s, $\s, char_rep(B), $\n]);
hexdump_line(<<B/binary>>, Len, Offs) ->
    <<B1:Len/binary, Rest/binary>> = B,
    hexdump_line(B1, Len, Offs),
    hexdump_line(Rest, Len, Offs + Len).

hex_offset(Int, Pad) ->
    io_lib:format("~*.16.0b", [Pad, Int]).

pad(<<B/binary>>, Len) when byte_size(B) >= Len ->
    <<>>;
pad(<<B/binary>>, Len) ->
    lists:duplicate((Len - byte_size(B)) * 3, $\s).

char_rep(<<B/binary>>) ->
    [char_rep(Ch) || <<Ch>> <= B];
char_rep(Ch) when Ch >= $\s, Ch =< 127 ->
    Ch;
char_rep(_) ->
    $.
    .

xdigit(N) when N >= 0, N =< 9 ->
    $0 + N;
xdigit(N) when N >= 16#a, N =< 16#f ->
    $a - 10 + N;
xdigit(N) ->
    throw({invalid_nybble, N}).

add_ts(Fmt, Args) ->
    {"[~s] " ++ Fmt, [iso8601_ts() | Args]}.

iso8601_ts() ->
    Now = os:timestamp(),
    Micros = element(3, Now),
    {{Yr, Mo, Dy}, {H, M, S}} = calendar:now_to_universal_time(Now),
    io_lib:format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B.~6..0BZ",
                  [Yr, Mo, Dy, H, M, S, Micros]).

