-module(aptest_apnsv2).
-export([
         send/4,
         format_apns_error/1,
         make_ssl_opts/2
        ]).

-import(aptest_util, [msg/2]).

-include("apns_recs.hrl").

%%--------------------------------------------------------------------
-spec send(Token, JSON, Opts, Env) -> Result
    when Token :: string(), JSON :: string() | binary(), Opts :: list(),
         Env :: prod | dev,
         Result :: ok | {error, term()}.
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
format_apns_error(#apns_error{id = Id,
                              status = S,
                              status_code = SC,
                              status_desc = SD}) ->
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
    case apns_lib:decode_error_packet(Data) of
        #apns_error{} = Err ->
            {error, Err};
        _Error ->
            {error, {unrecognized, Data}}
    end.

%%--------------------------------------------------------------------
check_packet(Packet) ->
    case apns_lib:decode(Packet) of
        #apns_notification{cmd      = Cmd,
                           id       = Id,
                           expire   = Expire,
                           token    = Token,
                           payload  = Payload,
                           priority = Priority,
                           rest     = Rest} ->
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


