-module(aptest_apnsv2).
-export([
         send/4,
         format_apns_error/1,
         make_ssl_opts/2
        ]).

-import(aptest_util, [msg/2]).

%%--------------------------------------------------------------------
-spec send(Token, JSON, Opts, Env) -> Result
    when Token :: string() | binary(), JSON :: string() | binary(),
         Opts :: list(), Env :: prod | dev, Result :: ok | {error, term()}.
send(Token, JSON, Opts, Env) when is_binary(Token) ->
    send(binary_to_list(Token), JSON, Opts, Env);
send(Token, JSON, Opts, Env) when Env =:= prod; Env =:= dev ->
    BToken = sc_util:hex_to_bitstring(Token),
    {Host, Port} = host_info(Env),
    SSLOpts = sc_util:req_val(ssl_opts, Opts),
    msg("Connecting over TLS to ~s:~B~n", [Host, Port]),
    {ok, Sock} = ssl:connect(Host, Port, SSLOpts),
    msg("Connected.~n", []),
    try
        Packet = apns_lib:encode_v2(1, 16#FFFFFFFF, BToken, JSON, 10),
        check_packet(Packet),
        msg("Sending APNS v2 packet:~n", []),
        aptest_util:hexdump(Packet),
        case ssl:send(Sock, Packet) of
            ok ->
                msg("Waiting for error response.~n", []),
                wait_for_resp(1000);
            Error ->
                msg("APNS didn't like that packet! SSL said: ~p~n", [Error]),
                Error
        end
    after
        ssl:close(Sock)
    end.

%%--------------------------------------------------------------------
format_apns_error(R) ->
    true = apns_recs:'#is_record-'(apns_error, R),
    Fields = [id,status,status_code,status_desc],
    [Id, S, SC, SD] = apns_recs:'#get-apns_error'(Fields, R),
    io_lib:format("id: ~B status: ~p status_code: ~B status_desc: ~s~n",
                  [Id, S, SC, SD]).

%%--------------------------------------------------------------------
make_ssl_opts(APNSCert, APNSKey) ->
    [
     {certfile, APNSCert},
     {keyfile, APNSKey},
     {versions, ['tlsv1']} % Fix for SSL issue http://erlang.org/pipermail/erlang-questions/2015-June/084935.html
    ].

%%--------------------------------------------------------------------
wait_for_resp(Timeout) ->
    wait_for_resp(Timeout, ok).

wait_for_resp(Timeout, Status) ->
    receive
        {ssl, _Socket, Data} ->
            NewStatus = handle_response(Data),
            wait_for_resp(Timeout, NewStatus);
        {ssl_closed, _Socket} ->
            msg("SSL socket closed~n", []),
            wait_for_resp(Timeout, Status);
        Other ->
            msg("Ignored message queue data: ~p~n", [Other]),
            wait_for_resp(Timeout, Status)
    after
        Timeout ->
            Status
    end.

%%--------------------------------------------------------------------
handle_response(Data) ->
    Res = apns_lib:decode_error_packet(Data),
    case apns_recs:'#is_record-'(apns_error, Res) of
        true ->
            {error, Res};
        false ->
            {error, {unrecognized, Data}}
    end.

%%--------------------------------------------------------------------
check_packet(Packet) ->
    Res = apns_lib:decode(Packet),
    case apns_recs:'#is_record-'(apns_notification, Res) of
        true ->
            Fields = [cmd, id, expire, token, payload, priority, rest],
            [Cmd, Id, Expire, Token, Payload,
             Priority, Rest] = apns_recs:'#get-apns_notification'(Fields, Res),
            msg("Packet decode check:~n~n"
                "Command version: ~p~n"
                "Notification ID: ~B~n"
                "Expiry         : ~B~n"
                "Token          : ~s~n"
                "Payload        : ~s~n"
                "Priority       : ~B~n"
                "Rest           : ~p~n~n",
                [Cmd, Id, Expire, sc_util:bitstring_to_hex(Token),
                 Payload, Priority, Rest]);
        Error ->
            msg("Error doing packet decode check: ~p~n", [Error])
    end.

%%--------------------------------------------------------------------
host_info(prod) -> {"gateway.push.apple.com", 2195};
host_info(dev) -> {"gateway.sandbox.push.apple.com", 2195}.


