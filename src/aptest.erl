-module(aptest).
-export([main/1]).
-import(aptest_util, [msg/2]).

-include("apns_recs.hrl").

%%--------------------------------------------------------------------
main([Token, Msg, APNSCert, APNSKey]) ->
    main([Token, Msg, APNSCert, APNSKey, "prod"]);
main([Token, Msg, APNSCert, APNSKey, PD]) when PD == "prod"; PD == "dev" ->
    RC = run([Token, Msg, APNSCert, APNSKey, PD]),
    halt(RC);
main(_) ->
    usage().

%%--------------------------------------------------------------------
run([Token, Msg, APNSCert, APNSKey, PD]) ->
    application:ensure_all_started(ssl),
    BToken = sc_util:hex_to_bitstring(Token),
    Notification = [{alert, list_to_binary(Msg)}, {sound, <<"wopr">>}],
    JSON = apns_json:make_notification(Notification),
    SSLOpts = [
               {certfile, APNSCert},
               {keyfile, APNSKey},
               {versions, ['tlsv1']} % Fix for SSL issue http://erlang.org/pipermail/erlang-questions/2015-June/084935.html
              ],
    case send(BToken, JSON, SSLOpts, list_to_atom(PD)) of
        ok ->
            msg("Pushed without receiving APNS error!~n", []),
            0;
        {error, #apns_error{} = AE} ->
            msg("APNS error: ~s~n", [format_apns_error(AE)]),
            1;
        Error ->
            msg("Error: ~p~n", [Error]),
            2
    end.

%%--------------------------------------------------------------------
send(BToken, JSON, SSLOpts, Prod) when Prod =:= prod; Prod =:= dev ->
    {Host, Port} = host_info(Prod),
    msg("Connecting over TLS to ~s:~B~n", [Host, Port]),
    {ok, Sock} = ssl:connect(Host, Port, SSLOpts),
    msg("Connected.~n", []),
    try
        Packet = apns_lib:encode_v2(1, 16#FFFFFFFF, BToken, JSON, 10),
        check_packet(Packet),
        msg("Sending packet:~n", []),
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
format_apns_error(#apns_error{id = Id,
                              status = S,
                              status_code = SC,
                              status_desc = SD}) ->
    io_lib:format("id: ~B status: ~p status_code: ~B status_desc: ~s~n",
                  [Id, S, SC, SD]).

%%--------------------------------------------------------------------
usage() ->
    msg("usage: ~s token message path/to/apns/cert.pem path/to/apns/key.pem [prod|dev]~n~n",
        [escript:script_name()]),
    halt(1).

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

