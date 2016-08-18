-module(aptest_apnsv3).
-export([
         send/4,
         send_file/2,
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
%%% Types
%%%-------------------------------------------------------------------
-type json() :: binary().
-type token() :: binary().
-type apns_env() :: prod | dev.
-type tokens() :: [token()].
-type cert_filename() :: string().
-type key_filename() :: string().
-type http2_header() :: {binary(), binary()}.
-type http2_headers() :: [http2_header()].
-type http2_body() :: [binary()].
-type http2_resp() :: {http2_headers(), http2_body()}.
-type send_error() :: {error, http2_resp()}.
-type send_result() :: ok | send_error().
-type apns_cert_files() :: {cert_filename(), key_filename()}.
-type send_mult_result() :: {ok, token()}
                          | {error, {http2_resp(), token()}}.
-type send_mult_results() :: [send_mult_result()].
-type send_file_result() :: {apns_cert_files(), send_mult_results()}.

%%%-------------------------------------------------------------------
%%% API
%%%-------------------------------------------------------------------

%%--------------------------------------------------------------------
start_client(Host, Port, SSLOpts) ->
    h2_client:start_link(https, Host, Port, SSLOpts).

%%--------------------------------------------------------------------
stop_client(Pid) ->
    ok = h2_client:stop(Pid).

%%--------------------------------------------------------------------
-spec send(Token, JSON, Opts, Env) -> Result
    when Token :: token(), JSON :: json(), Opts :: list(),
         Env :: apns_env(), Result :: send_result().
send(Token, JSON, Opts, Env) when Env =:= prod; Env =:= dev ->
    SSLOpts = sc_util:req_val(ssl_opts, Opts),
    CertFileName = sc_util:req_val(certfile, SSLOpts),
    AppBundleID = hd(get_bundle_ids(CertFileName)),
    {APNSHost, APNSPort} = aptest_util:get_apns_conninfo(Env, Opts),
    msg("Connecting with HTTP/2 to ~s:~B~n", [APNSHost, APNSPort]),
    {ok, Pid} = start_client(APNSHost, APNSPort, SSLOpts),
    msg("Connected.~n", []),
    Response = send_impl(Pid, Token, AppBundleID, JSON),
    _ = stop_client(Pid),
    Response.

%%--------------------------------------------------------------------
-spec send_file(Filename, JSON) -> Results
    when Filename :: string(), JSON :: json(),
         Results :: [send_file_result()].
send_file(Filename, JSON) ->
    {ok, B} = file:read_file(Filename),
    Conns = parse_conninfo(B),
    [{{Cert, Key}, send_mult(Cert, Key, JSON, Tokens)}
     || {{Cert, Key}, Tokens} <- validate_conninfo(Conns)].

%%--------------------------------------------------------------------
-spec send_mult(APNSCert, APNSKey, JSON, Tokens) -> Results
    when APNSCert :: cert_filename(), APNSKey :: key_filename(),
         JSON :: json(), Tokens :: tokens(),
         Results :: send_mult_results().
send_mult(APNSCert, APNSKey, JSON, Tokens) ->
    %% TODO: Identify prod/dev from cert, using ext v3 info
    %% 1.2.840.113635.100.6.3.1  = Development
    %% 1.2.840.113635.100.6.3.2  = Production
    {APNSHost, APNSPort} = aptest_util:host_info(prod), % For now
    Topic = get_topic(APNSCert),
    SSLOpts = make_ssl_opts(APNSCert, APNSKey),
    Wrap = fun(ok, Tok) ->
                   {ok, Tok};
              ({error, Err}, Tok) ->
                   {error, {Err, Tok}}
           end,

    msg("Connecting with HTTP/2 to ~s:~B~n", [APNSHost, APNSPort]),
    {ok, Pid} = start_client(APNSHost, APNSPort, SSLOpts),
    msg("Connected.~n", []),
    Results = try
                  [Wrap(send_impl(Pid, Tok, Topic, JSON), Tok)
                   || Tok <- Tokens]
              after
                  _ = stop_client(Pid),
                  msg("Disconnected.~n", [])
              end,
    Results.

%%--------------------------------------------------------------------
-spec send_impl(Pid, Token, Topic, JSON) -> Result
    when Pid :: pid(), Token :: token(), Topic :: binary(),
         JSON :: json(), Result :: send_result().
send_impl(Pid, Token, Topic, JSON) ->
    HTTPPath = to_b("/3/device/" ++ Token),
    ReqUUID = to_b(uuid:uuid_to_string(uuid:get_v4())),
    ReqHdrs = [{<<":method">>, <<"POST">>},
               {<<":path">>, HTTPPath},
               {<<":scheme">>, <<"https">>},
               {<<"apns-id">>, ReqUUID},
               {<<"apns-topic">>, to_b(Topic)}
              ],

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

    case sc_util:req_val(<<":status">>, RespHdrs) of
        <<"200">> ->
            ok;
        _Error ->
            {error, {RespHdrs, RespBody}}
    end.

%%--------------------------------------------------------------------
format_apns_error({RespHdrs, RespBody}) ->
    Id = sc_util:req_val(<<"apns-id">>, RespHdrs),
    S = sc_util:req_val(<<":status">>, RespHdrs),
    SD = status_desc(S),
    {Fmt, Args} = parsed_resp_body_fmt(Id, S, SD, parse_resp_body(RespBody)),
    io_lib:format(Fmt, Args).

%%--------------------------------------------------------------------
parsed_resp_body_fmt(Id, S, SD, []) ->
    {"id:             ~s~n"
     "status:         ~s~n"
     "status_desc:    ~s~n",
     [Id, S, SD]};
parsed_resp_body_fmt(Id, S, SD, [{Rsn, EJSON}]) ->
    {"id:             ~s~n"
     "status:         ~s~n"
     "status_desc:    ~s~n"
     "reason:         ~s~n"
     "reason_desc:    ~s~n"
     "ejson:          ~p~n",
     [Id, S, SD, Rsn, reason_desc(Rsn), EJSON]};
parsed_resp_body_fmt(Id, S, SD, [{Rsn, TS, EJSON}]) ->
    {"id:             ~s~n"
     "status:         ~s~n"
     "status_desc:    ~s~n"
     "reason:         ~s~n"
     "reason_desc:    ~s~n"
     "timestamp:      ~B~n"
     "timestamp_desc: ~s~n"
     "ejson:          ~p~n",
     [Id, S, SD, Rsn, reason_desc(Rsn), TS, timestamp_desc(TS), EJSON]}.

%%%-------------------------------------------------------------------
%%% Internal Functions
%%%-------------------------------------------------------------------

%% @doc
%% ConnData must be newline-separated records.
%% Each record has two space-delimited fields (one space only).
%%
%% Field 1: APNS cert file (.pem) path
%% Field 2: APNS key file (unencrypted .pem) path
%% Field 3: Token
%%
%% Returns [{{CertFile, KeyFile}, [Token]}].
%% where CertFile :: binary(), KeyFile :: binary(),
%%       Token :: binary().
%% @end
-spec parse_conninfo(ConnData) -> ConnInfo
    when ConnData :: binary(),
         ConnInfo :: [{{cert_filename(), key_filename()}, tokens()}].
parse_conninfo(<<ConnData/binary>>) ->
    Fields = [binary:split(L, [<<" ">>, <<"\t">>], [global, trim_all])
              || L <- binary:split(ConnData, <<"\n">>, [global])],
    %% Collect all the tokens that have the same AppBundleID
    D = lists:foldl(fun([CF, KF, Token], Dict) ->
                            dict:append({sc_util:to_list(CF),
                                         sc_util:to_list(KF)}, Token, Dict);
                       (X, Dict) ->
                            io:format(standard_error,
                                      "Ignoring data: ~p\n", [X]),
                            Dict
                    end, dict:new(), Fields),
    dict:to_list(D).

%%--------------------------------------------------------------------
-spec validate_conninfo(CIs) -> ValidCIs
    when CIs :: [{{cert_filename(), key_filename()}, tokens()}],
         ValidCIs :: [{{cert_filename(), key_filename()}, tokens()}].
validate_conninfo(CIs) ->
    [ConnInfo || ConnInfo <- CIs, is_valid_conn(ConnInfo)].

%%--------------------------------------------------------------------
is_valid_conn({{CertFile, KeyFile}, _Tok}) ->
    lists:all(fun(Filename) -> check_file(Filename) end,
              [CertFile, KeyFile]).

%%--------------------------------------------------------------------
check_file(Filename) ->
    case file:open(Filename, [read]) of
        {ok, FH} ->
            ok = file:close(FH),
            true;
        {error, _} ->
            msg("Cannot open file ~s\n", [Filename]),
            false
    end.

%%--------------------------------------------------------------------
maybe_warn_uuid(UUID, UUID) ->
    ok;
maybe_warn_uuid(ReqUUID, RespUUID) ->
    msg("***** WARNING - UUID mismatch!~n"
        "Req: ~s~nRsp: ~s~n", [ReqUUID, RespUUID]).

%%--------------------------------------------------------------------
-spec parse_resp_body(RespBody) -> []
                                   | [{Reason, EJSON}]
                                   | [{Reason, Timestamp, EJSON}]
    when RespBody :: [binary()], Reason :: binary(),
         Timestamp :: undefined | non_neg_integer(),
         EJSON :: term().
parse_resp_body([]) ->
    [];
parse_resp_body([<<RespBody/bytes>>]) ->
    EJSON = jsx:decode(RespBody),
    Reason = sc_util:req_val(<<"reason">>, EJSON),
    case sc_util:val(<<"timestamp">>, EJSON) of
        undefined ->
            [{Reason, EJSON}];
        TS when is_integer(TS)  ->
            [{Reason, TS, EJSON}]
    end.


%%--------------------------------------------------------------------
-spec get_topic(CertFile) -> Topic
    when CertFile :: string(), Topic :: binary().
get_topic(CertFile) ->
    hd(get_bundle_ids(CertFile)).

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
    undefined;
timestamp_desc(TS) when is_integer(TS), TS >= 0 ->
    list_to_binary(posix_ms_to_iso8601(TS)).

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
-spec make_ssl_opts(string(), string()) -> [{atom(), term()}].
make_ssl_opts(APNSCert, APNSKey) ->
    [{certfile, APNSCert},
     {keyfile, APNSKey},
     {honor_cipher_order, false},
     {versions, ['tlsv1.2']},
     {alpn_preferred_protocols, [<<"h2">>]}].

%%--------------------------------------------------------------------
posix_ms_to_iso8601(TS) ->
    now_to_iso8601(posix_ms_to_timestamp(TS)).

-compile({inline, [{posix_ms_to_timestamp, 1}]}).
posix_ms_to_timestamp(TS) when is_integer(TS), TS >= 0 ->
    {TS div 1000000000, TS rem 1000000000 div 1000, TS rem 1000 * 1000}.

now_to_iso8601(Now) ->
    {{Y,Mo,D},{H,M,S}} = calendar:now_to_universal_time(Now),
    io_lib:format("~B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0BZ",
                  [Y, Mo, D, H, M, S]).
