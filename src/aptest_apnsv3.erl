-module(aptest_apnsv3).
-export([
         send/4,
         format_apns_error/1,
         make_ssl_opts/2
        ]).

-import(aptest_util, [msg/2, to_b/1]).

-include_lib("public_key/include/public_key.hrl").

%% TODO: Move this to an include file in apns_erl_util.
-record(cert_info, {
        issuer_cn = <<>> :: binary(),
        is_production = false :: boolean(),
        bundle_id = <<>> :: binary(),
        bundle_seed_id = <<>> :: binary()
    }).

%%%-------------------------------------------------------------------
%%% API
%%%-------------------------------------------------------------------

%%--------------------------------------------------------------------
-spec send(Token, JSON, Opts, Env) -> Result
    when Token :: string(), JSON :: string() | binary(), Opts :: list(),
         Env :: prod | dev,
         Result :: ok | {error, term()}.
send(Token, JSON, Opts, Env) when Env =:= prod; Env =:= dev ->
    SSLOpts = sc_util:req_val(ssl_opts, Opts),
    CertFile = sc_util:req_val(certfile, SSLOpts),
    AppBundleID = hd(get_bundle_ids(CertFile)),
    HTTPPath = to_b("/3/device/" ++ Token),
    ReqUUID = to_b(uuid:uuid_to_string(uuid:get_v4())),
    ReqHdrs = [{<<":method">>, <<"POST">>},
               {<<":path">>, HTTPPath},
               {<<":scheme">>, <<"https">>},
               {<<"apns-id">>, ReqUUID},
               {<<"apns-topic">>, to_b(AppBundleID)}
              ],

    {APNSHost, APNSPort} = host_info(Env),
    msg("Connecting with HTTP/2 to ~s:~B~n", [APNSHost, APNSPort]),

    {ok, Pid} = h2_client:start_link(https, APNSHost, APNSPort, SSLOpts),

    msg("Connected.~n", []),
    ReqBody = to_b(JSON),
    msg("Sending synchronous request:~nHeaders: ~p~nBody: ~p~n",
        [ReqHdrs, ReqBody]),

    TStart = erlang:system_time(micro_seconds),
    {ok, {RespHdrs, RespBody}} = h2_client:sync_request(Pid, ReqHdrs, ReqBody),
    TEnd = erlang:system_time(micro_seconds),

    TElapsed = TEnd - TStart,
    msg("Response time: ~B microseconds~n"
        "Response headers: ~p~n"
        "Response body: ~p~n",
        [TElapsed, RespHdrs, RespBody]),

    RespUUID = sc_util:req_val(<<"apns-id">>, RespHdrs),

    _ = maybe_warn_uuid(ReqUUID, RespUUID),

    Response = case sc_util:req_val(<<":status">>, RespHdrs) of
                   <<"200">> ->
                       ok;
                   _Error ->
                       {error, {RespHdrs, RespBody}}
               end,
    ok = h2_client:stop(Pid),
    Response.

%%--------------------------------------------------------------------
format_apns_error({RespHdrs, RespBody}) ->
    Id = sc_util:req_val(<<"apns-id">>, RespHdrs),
    S = sc_util:req_val(<<":status">>, RespHdrs),
    SD = status_desc(S),
    {RD, TS} = parse_resp_body(RespBody),
    TD = timestamp_desc(TS),

    io_lib:format("id: ~s~n"
                  "~s"
                  "status: ~s~n"
                  "status_desc: ~s~n"
                  "reason_desc: ~s",
                  [Id, TD, S, SD, RD]).

%%%-------------------------------------------------------------------
%%% Internal Functions
%%%-------------------------------------------------------------------

%%--------------------------------------------------------------------
maybe_warn_uuid(UUID, UUID) ->
    ok;
maybe_warn_uuid(ReqUUID, RespUUID) ->
    msg("***** WARNING - UUID mismatch!~n"
        "Req: ~s~nRsp: ~s~n", [ReqUUID, RespUUID]).

%%--------------------------------------------------------------------
-spec parse_resp_body(RespBody) -> {RespDesc, Timestamp}
    when RespBody :: [binary()], RespDesc :: binary(),
         Timestamp :: undefined | binary().
parse_resp_body([]) ->
    {<<"<undefined>">>, <<"">>};
parse_resp_body([<<RespBody/bytes>>]) ->
    EJSON = jsx:decode(RespBody),
    Reason = sc_util:req_val(<<"reason">>, EJSON),
    Timestamp = sc_util:val(<<"timestamp">>, EJSON),
    {reason_desc(Reason), Timestamp}.


%%--------------------------------------------------------------------
-spec get_bundle_ids(CertFile) -> Result
    when CertFile :: string(), Result :: [binary()].
get_bundle_ids(CertFile) ->
    {ok, BCert} = file:read_file(CertFile),
    [get_bundle_id(OTPCert) || OTPCert <- apns_cert:pem_decode_certs(BCert)].

%%--------------------------------------------------------------------
get_bundle_id(#'OTPCertificate'{} = OTPCert) ->
    bundle_id(apns_cert:get_cert_info(OTPCert)).

bundle_id(#cert_info{bundle_id=BundleID}) ->
    BundleID.

%%--------------------------------------------------------------------
timestamp_desc(undefined) ->
    <<"">>;
timestamp_desc(<<TS/binary>>) ->
    list_to_binary([<<"timestamp: ">>, TS, $\n]).

%%--------------------------------------------------------------------
status_desc(<<"200">>) ->
    <<"Success">>;
status_desc(<<"400">>) ->
    <<"Bad request">>;
status_desc(<<"403">>) ->
    <<"There was an error with the certificate.">>;
status_desc(<<"405">>) ->
    <<
      "The request used a bad :method value. Only POST requests are "
      "supported."
    >>;
status_desc(<<"410">>) ->
    <<"The device token is no longer active for the topic.">>;
status_desc(<<"413">>) ->
    <<"The notification payload was too large.">>;
status_desc(<<"429">>) ->
    <<"The server received too many requests for the same device token.">>;
status_desc(<<"500">>) ->
    <<"Internal server error">>;
status_desc(<<"503">>) ->
    <<"The server is shutting down and unavailable.">>;
status_desc(<<B/bytes>>) ->
    list_to_binary([<<"Unknown status ">>, B]).

%%--------------------------------------------------------------------
reason_desc(<<"PayloadEmpty">>) ->
    <<"The message payload was empty.">>;
reason_desc(<<"PayloadTooLarge">>) ->
    <<"The message payload was too large. The maximum payload size is 4096 "
      "bytes.">>;
reason_desc(<<"BadTopic">>) ->
    <<"The apns-topic was invalid.">>;
reason_desc(<<"TopicDisallowed">>) ->
    <<"Pushing to this topic is not allowed.">>;
reason_desc(<<"BadMessageId">>) ->
    <<"The apns-id value is bad.">>;
reason_desc(<<"BadExpirationDate">>) ->
    <<"The apns-expiration value is bad.">>;
reason_desc(<<"BadPriority">>) ->
    <<"The apns-priority value is bad.">>;
reason_desc(<<"MissingDeviceToken">>) ->
    <<"The device token is not specified in the request :path. Verify that "
      "the :path header contains the device token.">>;
reason_desc(<<"BadDeviceToken">>) ->
    <<
      "The specified device token was bad. Verify that the request contains "
      "a valid token and that the token matches the environment."
    >>;
reason_desc(<<"DeviceTokenNotForTopic">>) ->
    <<"The device token does not match the specified topic.">>;
reason_desc(<<"Unregistered">>) ->
    <<"The device token is inactive for the specified topic.">>;
reason_desc(<<"DuplicateHeaders">>) ->
    <<"One or more headers were repeated.">>;
reason_desc(<<"BadCertificateEnvironment">>) ->
    <<"The client certificate was for the wrong environment.">>;
reason_desc(<<"BadCertificate">>) ->
    <<"The certificate was bad.">>;
reason_desc(<<"Forbidden">>) ->
    <<"The specified action is not allowed.">>;
reason_desc(<<"BadPath">>) ->
    <<"The request contained a bad :path value.">>;
reason_desc(<<"MethodNotAllowed">>) ->
    <<"The specified :method was not POST.">>;
reason_desc(<<"TooManyRequests">>) ->
    <<"Too many requests were made consecutively to the same device token.">>;
reason_desc(<<"IdleTimeout">>) ->
    <<"Idle time out.">>;
reason_desc(<<"Shutdown">>) ->
    <<"The server is shutting down.">>;
reason_desc(<<"InternalServerError">>) ->
    <<"An internal server error occurred.">>;
reason_desc(<<"ServiceUnavailable">>) ->
    <<"The service is unavailable.">>;
reason_desc(<<"MissingTopic">>) ->
    <<
      "The apns-topic header of the request was not specified and was "
      "required. The apns-topic header is mandatory when the client is "
      "connected using a certificate that supports multiple topics."
    >>;
reason_desc(<<Other/bytes>>) ->
    Other.

%%--------------------------------------------------------------------
make_ssl_opts(APNSCert, APNSKey) ->
    [{certfile, APNSCert},
     {keyfile, APNSKey},
     {honor_cipher_order, false},
     {versions, ['tlsv1.2']},
     {alpn_preferred_protocols, [<<"h2">>]}].

%%--------------------------------------------------------------------
host_info(prod) -> {"api.push.apple.com", 443};
host_info(dev) -> {"api.development.push.apple.com", 443}.
