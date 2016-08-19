-module(aptest_util).

-export([
        copy_props/2,
        do_rpc/4,
        do_rpc/5,
        err_msg/2,
        err_msg/3,
        hexdump/1,
        map_prop/2,
        msg/2,
        msg/3,
        ping_until_timeout/3,
        prop/2,
        prop/3,
        req_prop/2,
        set_dist_ports/2,
        start_distributed/1,
        start_distributed/2,
        start_network/2,
        timestamp_ms/0,
        wait_for_node/1,
        wait_for_node/2,
        wait_for_node/3
        ]).

%% Internal exports
-export([
          default_callback/0
        ]).

-include_lib("public_key/include/public_key.hrl").

-define(RPC_TIMEOUT, 60000).
-define(is_digit(X), ($0 =< X andalso X =< $9)).
-define(ASN1_NULL_BIN, <<5, 0>>).

%%--------------------------------------------------------------------
set_dist_ports(Min, Max) when is_integer(Min),
                              is_integer(Max),
                              Min >= 1024,
                              Max >= Min ->
	application:set_env(kernel, inet_dist_listen_min, Min),
	application:set_env(kernel, inet_dist_listen_max, Max).

%%--------------------------------------------------------------------
start_network(Node, Cookie) ->
    start_distributed(Node),
    erlang:set_cookie(Node, Cookie).

%%--------------------------------------------------------------------
start_distributed(Node) ->
    start_distributed(Node, longnames).

%%--------------------------------------------------------------------
start_distributed(Node, NameType) when NameType == shortnames;
                                       NameType == longnames ->
    case net_kernel:start([Node, NameType]) of
        {ok, _Pid} ->
            ok;
        {error, {{already_started, _Pid}, _}} ->
            ok;
        {error, Reason} ->
            throw(Reason)
    end.

%%--------------------------------------------------------------------
default_callback() ->
    fun(Node_, Act_) ->
            msg("~s ~p~n", [Act_, Node_])
    end.

%%--------------------------------------------------------------------
wait_for_node(Node) ->
    wait_for_node(Node, 30000).

%%--------------------------------------------------------------------
wait_for_node(Node, TimeoutMs) ->
    wait_for_node(Node, TimeoutMs, default_callback()).

%%--------------------------------------------------------------------
wait_for_node(Node, TimeoutMs, Callback) when is_function(Callback, 2) ->
    Ref = erlang:send_after(TimeoutMs, self(), timeout),
    ping_until_timeout(Node, Ref, Callback).

%%--------------------------------------------------------------------
ping_until_timeout(Node, Ref, Callback) when is_function(Callback, 2) ->
    Callback(Node, "Pinging"),
    case net_adm:ping(Node) of
        pong ->
            _ = erlang:cancel_timer(Ref),
            receive after 0 -> ok end, % Flush queue
            Callback(Node, "Connected to");
        pang ->
            Callback(Node, "Ping failed to"),
            receive
                timeout ->
                    Callback(Node, timeout),
                    throw({ping_timeout, Node})
            after
                1000 ->
                    ping_until_timeout(Node, Ref, Callback)
            end
    end.

%%--------------------------------------------------------------------
hexdump(<<B/binary>>) ->
    hexdump_line(B, 16, 0).

%%--------------------------------------------------------------------
%%% Perform an RPC call and throw on error
%%%--------------------------------------------------------------------
do_rpc(Node, M, F, A) ->
    do_rpc(Node, M, F, A, ?RPC_TIMEOUT).

%%--------------------------------------------------------------------
do_rpc(Node, M, F, A, Timeout) ->
    try rpc:call(Node, M, F, A, Timeout) of
        {badrpc, Reason} ->
            throw({rpcerror, {Reason, {Node, M, F, A}}});
        Result ->
            Result
        catch _:Why ->
            throw(Why)
    end.

%%--------------------------------------------------------------------
err_msg(Fmt, Args) ->
    err_msg(Fmt, Args, with_ts).

err_msg(Fmt, Args, with_ts) ->
    {TsFmt, TsArgs} = add_ts(Fmt, Args),
    err_msg(TsFmt, TsArgs, no_ts);
err_msg(Fmt, Args, no_ts) ->
    io:format(standard_error, Fmt, Args).

%%--------------------------------------------------------------------
msg(Fmt, Args) ->
    msg(Fmt, Args, with_ts).

msg(Fmt, Args, with_ts) ->
    {TsFmt, TsArgs} = add_ts(Fmt, Args),
    msg(TsFmt, TsArgs, no_ts);
msg(Fmt, Args, no_ts) ->
    io:format(Fmt, Args).

%%--------------------------------------------------------------------
timestamp_ms() ->
    erlang:system_time(micro_seconds) div 1000.

%%--------------------------------------------------------------------
copy_props(Keys, FromPL) ->
    [req_prop(K, FromPL) || K <- Keys].

%%--------------------------------------------------------------------
map_prop(Fun, {K, V}) when is_function(Fun, 1) ->
    {K, Fun(V)}.

%%--------------------------------------------------------------------
req_prop(K, PL) ->
    case lists:keysearch(K, 1, PL) of
        {value, KV} ->
            KV;
        false ->
            throw({missing_required_key, K})
    end.

%%--------------------------------------------------------------------
prop(K, PL) ->
    prop(K, PL, undefined).

%%--------------------------------------------------------------------
prop(K, PL, Default) ->
    case lists:keysearch(K, 1, PL) of
        {value, KV} ->
            KV;
        false ->
            Default
    end.

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

%%--------------------------------------------------------------------
hex_offset(Int, Pad) ->
    io_lib:format("~*.16.0b", [Pad, Int]).

%%--------------------------------------------------------------------
pad(<<B/binary>>, Len) when byte_size(B) >= Len ->
    <<>>;
pad(<<B/binary>>, Len) ->
    lists:duplicate((Len - byte_size(B)) * 3, $\s).

%%--------------------------------------------------------------------
char_rep(<<B/binary>>) ->
    [char_rep(Ch) || <<Ch>> <= B];
char_rep(Ch) when Ch >= $\s, Ch =< 127 ->
    Ch;
char_rep(_) ->
    $.
    .

%%--------------------------------------------------------------------
xdigit(N) when N >= 0, N =< 9 ->
    $0 + N;
xdigit(N) when N >= 16#a, N =< 16#f ->
    $a - 10 + N;
xdigit(N) ->
    throw({invalid_nybble, N}).

%%--------------------------------------------------------------------
add_ts(Fmt, Args) ->
    {"[~s] " ++ Fmt, [iso8601_ts() | Args]}.

%%--------------------------------------------------------------------
iso8601_ts() ->
    Now = os:timestamp(),
    Micros = element(3, Now),
    {{Yr, Mo, Dy}, {H, M, S}} = calendar:now_to_universal_time(Now),
    io_lib:format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B.~6..0BZ",
                  [Yr, Mo, Dy, H, M, S, Micros]).


% ex: set ft=erlang fenc=utf-8 sts=4 ts=4 sw=4 et:
