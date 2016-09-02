-module(aptest_apnsv3).
-export([
         send/4,
         send_file/3,
         format_apns_error/1,
         make_ssl_opts/1
        ]).

-import(aptest_util, [msg/2, err_msg/2]).
-import(sc_util, [to_bin/1, to_list/1]).

-include_lib("public_key/include/public_key.hrl").

%%%-------------------------------------------------------------------
%%% Types
%%%-------------------------------------------------------------------
-type apns_env() :: prod | dev.
-type json() :: binary().
-type token() :: binary().
-type tokens() :: [token()].
-type cert_filename() :: string().
-type key_filename() :: string().
-type http2_header() :: {binary(), binary()}.
-type http2_headers() :: [http2_header()].
-type http2_body() :: [binary()].
-type http2_resp() :: {http2_headers(), http2_body()}.
-type connect_error() :: {error, http2_resp()}.
-type connect_result() :: ok | connect_error().
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
-spec start_client(Host, Port, SSLOpts) -> Result when
      Host :: string(), Port :: non_neg_integer(),
      SSLOpts :: [term()], Result :: {ok, pid()} | {error, term()}.
start_client(Host, Port, SSLOpts) ->
    msg("Connecting with HTTP/2 to ~s:~B~n", [Host, Port]),
    msg("SSL Opts: ~p~n", [SSLOpts]),
    OldTrap = process_flag(trap_exit, true),
    try timer:tc(h2_client, start_link, [https, Host, Port, SSLOpts]) of
        {T, {ok, _}=Result} ->
            msg("Connected in ~B microseconds.~n", [T]),
            Result;
        {_, {error, {{badmatch, Error}, _StackTrace}}} ->
            SslError = ssl:format_error(Error),
            {error, {connection_error, SslError}}
    catch
        Class:Reason ->
            err_msg("[~p:~p] Exception, class: ~p, reason: ~p~n",
                    [Class, Reason]),
            Reason
    after
        process_flag(trap_exit, OldTrap)
    end.

%%--------------------------------------------------------------------
-spec stop_client(Pid) -> ok when Pid :: pid().
stop_client(Pid) ->
    ok = h2_client:stop(Pid).

%%--------------------------------------------------------------------
-spec connect(Opts, Env) -> Result
    when Opts :: list(), Env :: apns_env(), Result :: connect_result().
connect(Opts, Env) when Env =:= prod; Env =:= dev ->
    SSLOpts = sc_util:req_val(ssl_opts, Opts),
    {Host, Port} = get_apns_conninfo(Env, Opts),
    case start_client(Host, Port, SSLOpts) of
        {ok, Pid} ->
            msg("Connected ok, disconnecting.~n", []),
            _ = stop_client(Pid);
        {error, _Reason} = Error ->
            Error
    end.

%%--------------------------------------------------------------------
-spec send(Token, JSON, Opts, Env) -> Result when
      Token :: token(), JSON :: json(), Opts :: list(),
      Env :: apns_env(), Result :: send_result().
send(Token, JSON, Opts, Env) when Env =:= prod; Env =:= dev ->
    {Host, Port} = get_apns_conninfo(Env, Opts),
    SSLOpts = sc_util:req_val(ssl_opts, Opts),
    case start_client(Host, Port, SSLOpts) of
        {ok, Pid} ->
            try
                send_impl(Pid, Token, JSON, Opts)
            catch
                _:Reason ->
                    Reason
            after
                _ = stop_client(Pid)
            end;
        {error, _Reason} = Error ->
            Error
    end.

%%--------------------------------------------------------------------
-spec send_file(Opts, Filename, JSON) -> Results
    when Filename :: string(), JSON :: json(), Opts :: [{_,_}],
         Results :: [send_file_result()].
send_file(Opts, Filename, JSON) ->
    {ok, B} = file:read_file(Filename),
    Conns = parse_conninfo(B),
    MkOpts = fun(ACert, AKey) ->
                     SslOpts = {ssl_opts, [
                                           {apns_cert, ACert},
                                           {apns_key, AKey}
                                          ]},
                     lists:keystore(ssl_opts, 1, Opts, SslOpts)
             end,
    [{{Cert, Key}, send_mult(MkOpts(Cert, Key), JSON, Tokens)}
     || {{Cert, Key}, Tokens} <- validate_conninfo(Conns)].

%%--------------------------------------------------------------------
-spec send_mult(Opts, JSON, Tokens) -> Results
    when Opts :: [{atom(), string()}],
         JSON :: json(), Tokens :: tokens(),
         Results :: send_mult_results().
send_mult(Opts, JSON, Tokens) ->
    SSLCfg = sc_util:req_val(ssl_opts, Opts),
    APNSCert = sc_util:req_val(certfile, SSLCfg),
    Env = get_cert_env(APNSCert),
    {Host, Port} = host_info(Env),
    Topic = get_topic(Opts),
    SSLOpts = make_ssl_opts(SSLCfg),
    Wrap = fun(ok, Tok) ->
                   {ok, Tok};
              ({error, Err}, Tok) ->
                   {error, {Err, Tok}}
           end,

    case start_client(Host, Port, SSLOpts) of
        {ok, Pid} ->
            try
                [Wrap(send_impl(Pid, Tok, Topic, JSON), Tok)
                 || Tok <- Tokens]
            after
                _ = stop_client(Pid),
                msg("Disconnected.~n", [])
            end;
        {error, _Reason} = Error ->
            Error
    end.

%%--------------------------------------------------------------------
-spec send_impl(Pid, Token, JSON, Opts) -> Result when
      Pid :: pid(), Token :: token(), JSON :: json(), Opts :: [{_,_}],
      Result :: send_result().
send_impl(Pid, Token, JSON, Opts) ->
    HTTPPath = to_bin([<<"/3/device/">>, Token]),
    ReqHdrs = [{<<":method">>, <<"POST">>},
               {<<":path">>, HTTPPath},
               {<<":scheme">>, <<"https">>}
              ] ++ maybe_prop(apns_id, Opts)
                ++ maybe_prop(apns_topic, Opts)
                ++ maybe_prop(apns_expiration, Opts)
                ++ maybe_prop(apns_priority, Opts),

    ReqBody = JSON,
    sync_req(Pid, ReqHdrs, ReqBody).

%%--------------------------------------------------------------------
maybe_prop(Name, PL) ->
    case proplists:get_value(Name, PL) of
        undefined ->
            [];
        [] ->
            [];
        <<>> ->
            [];
        -1 ->
            [];
        Value ->
            [{atom_to_dash_binary(Name), to_bin(Value)}]
    end.

%%--------------------------------------------------------------------
%% this_is_a_key -> <<"this-is-a-key">>
atom_to_dash_binary(X) when is_atom(X) ->
    S = atom_to_list(X),
    to_bin(string:join(string:tokens(S, "_"), "-")).

%%--------------------------------------------------------------------
sync_req(Pid, ReqHdrs, ReqBody) ->
    msg("Sending synchronous request:~nHeaders: ~p~nBody: ~p~n",
        [ReqHdrs, ReqBody]),

    {TElapsed, Result} = timer:tc(h2_client, sync_request,
                                  [Pid, ReqHdrs, ReqBody]),
    {ok, {RespHdrs, RespBody}} = Result,

    msg("~n"
        "Response time: ~B microseconds~n"
        "Response headers: ~p~n"
        "Response body: ~p~n",
        [TElapsed, RespHdrs, RespBody]),

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
-spec get_topic(Opts) -> Topic
    when Opts :: list(), Topic :: binary().
get_topic(Opts) ->
    case sc_util:req_val(topic, Opts) of
        [] ->
            SSLOpts = sc_util:req_val(ssl_opts, Opts),
            CertFile = sc_util:req_val(certfile, SSLOpts),
            {ok, BCert} = file:read_file(CertFile),
            DecodedCert = apns_cert:decode_cert(BCert),
            #{subject_uid := Topic} = apns_cert:get_cert_info_map(DecodedCert),
            Topic;
        UserTopic ->
            list_to_binary(UserTopic)
    end.

%%--------------------------------------------------------------------
timestamp_desc(undefined) ->
    undefined;
timestamp_desc(TS) when is_integer(TS), TS >= 0 ->
    to_bin(posix_ms_to_iso8601(TS)).

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
    to_bin([<<"Unknown status ">>, B]).

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
-spec make_ssl_opts([{atom(), string()}]) -> [{atom(), term()}].
make_ssl_opts(SSLCfg) ->
    APNSCert = sc_util:req_val(apns_cert, SSLCfg),
    APNSKey = sc_util:req_val(apns_key, SSLCfg),
    APNSCACert = case sc_util:val(apns_ca_cert, SSLCfg, []) of
                     [] ->
                         "/etc/ssl/certs/ca-certificates.crt";
                     CAFile ->
                        CAFile
                 end,
    [{certfile, APNSCert},
     {keyfile, APNSKey},
     {cacertfile, APNSCACert},
     {verify, verify_peer},
     {honor_cipher_order, false},
     {versions, ['tlsv1.2']},
     {alpn_advertised_protocols, [<<"h2">>]}].

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

%%--------------------------------------------------------------------
host_info(prod) -> {"api.push.apple.com", 443};
host_info(dev) ->  {"api.development.push.apple.com", 443}.

%%--------------------------------------------------------------------
-spec get_apns_conninfo(Env, Opts) -> Result when
      Env :: apns_env(), Opts :: [{atom(), term()}],
      Result :: {Host, Port}, Host :: string(), Port :: non_neg_integer().
get_apns_conninfo(Env, Opts) ->
    {DefHost, DefPort} = host_info(Env),
    Host = case string:strip(proplists:get_value(apns_host, Opts, "")) of
               "" -> DefHost;
               H  -> H
           end,
    {_, Port} = aptest_util:prop(apns_port, Opts, DefPort),
    {Host, Port}.

%%--------------------------------------------------------------------
-spec get_cert_env(CertFile) -> Result when
      CertFile :: cert_filename(), Result :: apns_env() | none().
get_cert_env(CertFile) ->
    {ok, B} = file:read_file(CertFile),
    DecodedCert = apns_cert:decode_cert(B),
    #{is_development := IsDev,
      is_production  := IsProd} = apns_cert:get_cert_info_map(DecodedCert),

    %% This is not foolproof because VoIP certs are
    %% usable in both prod and dev, so we let prod take
    %% precedence.
    case {IsProd, IsDev} of
        {true, _} ->
            prod;
        {_, true} ->
            dev;
        {true, true} ->
            msg("Warning: ~s is both prod and dev, choosing prod",
                [CertFile]),
            prod;
        {_, _} ->
            msg("Error! ~s is not a push certificate!", [CertFile]),
            throw({not_push_cert, CertFile})
    end.

% ex: set ft=erlang fenc=utf-8 sts=4 ts=4 sw=4 et:
