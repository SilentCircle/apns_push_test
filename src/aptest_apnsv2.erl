-module(aptest_apnsv2).
-export([
         connect/2,
         send/4,
         format_apns_error/1,
         make_auth_opts/1
        ]).

-import(aptest_util, [msg/2, msg/3, err_msg/2, err_msg/3]).

%%--------------------------------------------------------------------
-spec start_client(Scheme, Host, Port, SSLOpts) -> Result when
      Scheme :: https | http, Host :: string(), Port :: non_neg_integer(),
      SSLOpts :: [term()],
      Result :: {ok, gen_tcp:socket() | ssl:sslsocket()} | {error, term()}.
start_client(Scheme, Host, Port, SSLOpts) when Scheme == https orelse
                                               Scheme == http ->
    msg("Connecting to ~p://~s:~B~n", [Scheme, Host, Port]),
    case Scheme of
        https ->
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
            end;
        http ->
            {T, Result} = timer:tc(gen_tcp, connect, [Host, Port, []]),
            case Result of
                {ok, _Sock} ->
                    msg("Connected in ~B microseconds.~n", [T]),
                    Result;
                {error, Reason} ->
                    {error, {connection_error, inet:format_error(Reason)}}
            end
    end.

%%--------------------------------------------------------------------
stop_client(Mod, Sock) ->
    _ = Mod:close(Sock).

%%--------------------------------------------------------------------
-spec connect(Opts, Env) -> Result
    when Opts :: list(), Env :: prod | dev,
         Result :: ok | {error, term()}.
connect(Opts, Env) when Env =:= prod; Env =:= dev ->
    {Mod, Scheme, Host, Port} = get_apns_conninfo(Env, Opts),
    SSLOpts = sc_util:req_val(auth_opts, Opts),
    case start_client(Scheme, Host, Port, SSLOpts) of
        {ok, Sock} ->
            msg("Connected OK, disconnecting.~n", []),
            stop_client(Mod, Sock);
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
    {Mod, Scheme, Host, Port} = get_apns_conninfo(Env, Opts),
    SSLOpts = sc_util:req_val(auth_opts, Opts),
    Id = opt_int_val(apns_int_id, Opts, 1),
    Exp = opt_int_val(apns_expiration, Opts, 16#FFFFFFFF),
    Prio = opt_int_val(apns_priority, Opts, 10),

    case start_client(Scheme, Host, Port, SSLOpts) of
        {ok, Sock} ->
            send_impl(Sock, Id, Exp, BToken, JSON, Prio);
        {error, _Reason} = Error ->
            Error
    end.


%%--------------------------------------------------------------------
send_impl(Mod, Sock, Id, Exp, BToken, JSON, Prio) when Mod == ssl orelse
                                                       Mod == gen_tcp ->
    try
        Packet = apns_lib:encode_v2(Id, Exp, BToken, JSON, Prio),
        check_packet(Packet),
        msg("Sending APNS v2 packet:~n", []),
        aptest_util:hexdump(Packet),
        case Mod:send(Sock, Packet) of
            ok ->
                msg("Waiting for error response.~n", []),
                wait_for_resp(mod_to_proto(Mod), 1000);
            Error ->
                msg("APNS didn't like that packet! ~p said: ~p~n",
                    [Mod, Error]),
                Error
        end
    catch
        What:Why ->
            msg("send_impl exception: {~p, ~p}~n", [What, Why]),
            {What, Why}
    after
        _ = stop_client(Mod, Sock)
    end.

%%--------------------------------------------------------------------
mod_to_proto(gen_tcp) -> tcp;
mod_to_proto(ssl) -> ssl.

%%--------------------------------------------------------------------
mod_scheme(Opts) ->
    case sc_util:val(no_ssl, Opts, false) of
        true  -> {gen_tcp, http};
        false -> {ssl, https}
    end.

%%--------------------------------------------------------------------
format_apns_error(R) ->
    true = apns_recs:'#is_record-'(apns_error, R),
    Fields = [id,status,status_code,status_desc],
    [Id, S, SC, SD] = apns_recs:'#get-apns_error'(Fields, R),
    io_lib:format("id: ~B status: ~p status_code: ~B status_desc: ~s~n",
                  [Id, S, SC, SD]).

%%--------------------------------------------------------------------
-spec make_auth_opts([{atom(), string()}]) -> [{atom(), term()}].
make_auth_opts(SSLCfg) ->
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
wait_for_resp(Proto, Timeout) ->
    Closed = list_to_atom(atom_to_list(Proto) ++ "_closed"),
    wait_for_resp(Proto, Closed, Timeout, ok).

%%--------------------------------------------------------------------
wait_for_resp(Proto, Closed, Timeout, Status) when Proto == tcp orelse
                                                   Proto == ssl ->
    receive
        {Proto, _Socket, Data} ->
            msg("Received ~p data: ~p~n", [Proto, Data]),
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

%%--------------------------------------------------------------------
-spec get_apns_conninfo(Env, Opts) -> Result when
      Env :: prod | dev, Opts :: [{atom(), term()}],
      Result :: {Mod, Scheme, Host, Port}, Mod :: ssl | gen_tcp,
      Scheme :: https | http, Host :: string(), Port :: non_neg_integer().
get_apns_conninfo(Env, Opts) ->
    {DefHost, DefPort} = host_info(Env),
    Host = case string:strip(proplists:get_value(apns_host, Opts, "")) of
               "" -> DefHost;
               H  -> H
           end,
    Port = case sc_util:val(apns_port, Opts, DefPort) of
               -1        -> DefPort;
               OtherPort -> OtherPort
           end,
    {Mod, Scheme} = mod_scheme(Opts),
    {Mod, Scheme, Host, Port}.

%%--------------------------------------------------------------------
opt_int_val(Key, Opts, Default) ->
    case sc_util:val(Key, Opts, Default) of
        -1 -> Default;
        X  -> X
    end.

% ex: set ft=erlang fenc=utf-8 sts=4 ts=4 sw=4 et:

