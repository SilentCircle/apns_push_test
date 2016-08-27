-module(aptest_apnsv2).
-export([
         connect/2,
         send/4,
         format_apns_error/1,
         make_ssl_opts/1
        ]).

-import(aptest_util, [msg/2, msg/3, err_msg/2, err_msg/3]).

%%--------------------------------------------------------------------
-spec start_client(Host, Port, SSLOpts) -> Result when
      Host :: string(), Port :: non_neg_integer(),
      SSLOpts :: [term()], Result :: {ok, pid()} | {error, term()}.
start_client(Host, Port, SSLOpts) ->
    msg("Connecting over TLS to ~s:~B~n", [Host, Port]),
    msg("SSL Opts: ~p~n", [SSLOpts]),
    {T, Result} = timer:tc(ssl, connect, [Host, Port, SSLOpts]),
    case Result of
        {ok, _Sock} ->
            msg("Connected in ~B microseconds.~n", [T]),
            Result;
        {error, {tls_alert, TlsAlert}} ->
            {error, {connection_error, "TLS Alert: " ++ TlsAlert}};
        {error, _Error} ->
            Result
    end.

%%--------------------------------------------------------------------
stop_client(Sock) ->
    _ = ssl:close(Sock).

%%--------------------------------------------------------------------
-spec connect(Opts, Env) -> Result
    when Opts :: list(), Env :: prod | dev,
         Result :: ok | {error, term()}.
connect(Opts, Env) when Env =:= prod; Env =:= dev ->
    {Host, Port} = host_info(Env),
    SSLOpts = sc_util:req_val(ssl_opts, Opts),
    case start_client(Host, Port, SSLOpts) of
        {ok, Sock} ->
            msg("Connected OK, disconnecting.~n", []),
            stop_client(Sock);
        Error ->
            Error
    end.

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
    Id = sc_util:val(apns_int_id, Opts, 1),
    Exp = sc_util:val(apns_expiration, Opts, 16#FFFFFFFF),
    Prio = sc_util:val(apns_priority, Opts, 10),

    case start_client(Host, Port, SSLOpts) of
        {ok, Sock} ->
            send_impl(Sock, Id, Exp, BToken, JSON, Prio);
        {error, _Reason} = Error ->
            Error
    end.


%%--------------------------------------------------------------------
send_impl(Sock, Id, Exp, BToken, JSON, Prio) ->
    try
        Packet = apns_lib:encode_v2(Id, Exp, BToken, JSON, Prio),
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
        _ = stop_client(Sock)
    end.

%%--------------------------------------------------------------------
format_apns_error(R) ->
    true = apns_recs:'#is_record-'(apns_error, R),
    Fields = [id,status,status_code,status_desc],
    [Id, S, SC, SD] = apns_recs:'#get-apns_error'(Fields, R),
    io_lib:format("id: ~B status: ~p status_code: ~B status_desc: ~s~n",
                  [Id, S, SC, SD]).

%%--------------------------------------------------------------------
-spec make_ssl_opts([{atom(), string()}]) -> [{atom(), term()}].
make_ssl_opts(SSLCfg) ->
    APNSCert = sc_util:req_val(apns_cert, SSLCfg),
    APNSKey = sc_util:req_val(apns_key, SSLCfg),
    APNSCACert = case sc_util:req_val(apns_ca_cert, SSLCfg) of
                     [] ->
                         "/etc/ssl/certs/ca-certificates.crt";
                     CAFile ->
                        CAFile
                 end,
    [
     {certfile, APNSCert},
     {cacertfile, APNSCACert},
     {keyfile, APNSKey},
     {versions, ['tlsv1']} % Fix for SSL issue http://erlang.org/pipermail/erlang-questions/2015-June/084935.html
    ].

%%--------------------------------------------------------------------
wait_for_resp(Timeout) ->
    wait_for_resp(Timeout, ok).

%%--------------------------------------------------------------------
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
                 Payload, Priority, Rest], no_ts);
        Error ->
            err_msg("Error doing packet decode check: ~p~n", [Error])
    end.

%%--------------------------------------------------------------------
host_info(prod) -> {"gateway.push.apple.com", 2195};
host_info(dev) -> {"gateway.sandbox.push.apple.com", 2195}.

% ex: set ft=erlang fenc=utf-8 sts=4 ts=4 sw=4 et:

