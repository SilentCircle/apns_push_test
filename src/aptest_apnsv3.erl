-module(aptest_apnsv3).
-export([
         send/4,
         format_apns_error/1,
         make_auth_opts/1
        ]).

-import(aptest_util, [msg/2, err_msg/2]).
-import(sc_util, [to_bin/1, to_list/1]).

-include_lib("public_key/include/public_key.hrl").

%%%-------------------------------------------------------------------
%%% Types
%%%-------------------------------------------------------------------
-type apns_env() :: prod | dev.
-type apns_auth() :: {apns_auth, string()}.
-type apns_issuer() :: {apns_issuer, string()}.
-type apns_auth_info() :: apns_auth() | apns_issuer().
-type json() :: binary().
-type topic() :: binary().
-type token() :: binary().
-type cert_filename() :: string().
-type http2_header() :: {binary(), binary()}.
-type http2_headers() :: [http2_header()].
-type http2_body() :: [binary()].
-type http2_resp() :: {http2_headers(), http2_body()}.
-type connect_error() :: {error, http2_resp()}.
-type connect_result() :: ok | connect_error().
-type send_error() :: {error, http2_resp()}.
-type send_result() :: ok | send_error().

-type auth_cfg_key() :: apns_cert
                      | apns_key
                      | apns_ca_cert
                      | apns_auth
                      | apns_issuer.
-type auth_cfg_item() :: {auth_cfg_key(), string()}.
-type auth_cfg() :: [auth_cfg_item()].

-type auth_opt() :: ssl:ssl_option() | apns_auth_info().
-type auth_opts() :: [auth_opt()].

-type cmdline_opts() :: aptest_cmdline:config().

%%%-------------------------------------------------------------------
%%% API
%%%-------------------------------------------------------------------

%%--------------------------------------------------------------------
-spec start_client(Scheme, Host, Port, AuthOpts) -> Result when
      Scheme :: http | https, Host :: string(), Port :: non_neg_integer(),
      AuthOpts :: [term()], Result :: {ok, pid()} | {error, term()}.
start_client(Scheme, Host, Port, AuthOpts) when Scheme == https orelse
                                                Scheme == http ->
    msg("Connecting with HTTP/2 to ~p://~s:~B~n", [Scheme, Host, Port]),
    msg("Auth Opts: ~p~n", [AuthOpts]),
    Mod = fmt_module(Scheme),
    OldTrap = process_flag(trap_exit, true),
    try timer:tc(h2_client, start_link, [Scheme, Host, Port, AuthOpts]) of
        {T, {ok, _}=Result} ->
            msg("Connected in ~B microseconds.~n", [T]),
            Result;
        {_, {error, {{badmatch, Error}, _StackTrace}}} ->
            FmtError = Mod:format_error(Error),
            {error, {connection_error, FmtError}};
        {_, {error, Error}} ->
            FmtError = Mod:format_error(Error),
            {error, {connection_error, FmtError}}
    catch
        Class:Reason ->
            err_msg("[~p:~p] Exception, class: ~p, reason: ~p~n",
                    [Class, Reason]),
            Reason
    after
        process_flag(trap_exit, OldTrap)
    end.

%%--------------------------------------------------------------------
fmt_module(http)  -> inet;
fmt_module(https) -> ssl.

%%--------------------------------------------------------------------
-spec stop_client(Pid) -> ok when Pid :: pid().
stop_client(Pid) ->
    ok = h2_client:stop(Pid).

%%--------------------------------------------------------------------
-spec connect(Opts, Env) -> Result
    when Opts :: list(), Env :: apns_env(), Result :: connect_result().
connect(Opts, Env) when Env =:= prod; Env =:= dev ->
    AuthOpts = sc_util:val(auth_opts, Opts, []),
    {Scheme, Host, Port} = get_apns_conninfo(Env, Opts),
    case start_client(Scheme, Host, Port, AuthOpts) of
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
    {Scheme, Host, Port} = get_apns_conninfo(Env, Opts),
    AuthOpts = sc_util:val(auth_opts, Opts, []),
    case start_client(Scheme, Host, Port, AuthOpts) of
        {ok, Pid} ->
            try
                send_impl(Scheme, Pid, Token, JSON, Opts)
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
-spec send_impl(Scheme, Pid, Token, JSON, Opts) -> Result when
      Scheme :: https | http, Pid :: pid(), Token :: token(), JSON :: json(),
      Opts :: cmdline_opts(), Result :: send_result().
send_impl(Scheme, Pid, Token, JSON, Opts) ->
    HTTPPath = to_bin([<<"/3/device/">>, Token]),
    ReqHdrs = [{<<":method">>, <<"POST">>},
               {<<":path">>, HTTPPath},
               {<<":scheme">>, sc_util:to_bin(Scheme)}
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
    SD = apns_lib_http2:status_desc(S),
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
     [Id, S, SD, Rsn, apns_lib_http2:reason_desc(Rsn), EJSON]};
parsed_resp_body_fmt(Id, S, SD, [{Rsn, TS, EJSON}]) ->
    {"id:             ~s~n"
     "status:         ~s~n"
     "status_desc:    ~s~n"
     "reason:         ~s~n"
     "reason_desc:    ~s~n"
     "timestamp:      ~B~n"
     "timestamp_desc: ~s~n"
     "ejson:          ~p~n",
     [Id, S, SD, Rsn, apns_lib_http2:reason_desc(Rsn), TS, timestamp_desc(TS),
      EJSON]}.

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
-spec get_topic(AptestCfg) -> Topic
    when AptestCfg :: cmdline_opts(), Topic :: topic().
get_topic(AptestCfg) ->
    %Auth = sc_util:req_val(apns_auth, AptestCfg),
    UserTopic = sc_util:req_val(topic, AptestCfg),
    case UserTopic of
        [] ->
            AuthCfg = sc_util:req_val(auth_opts, AptestCfg),
            CertFile = sc_util:req_val(apns_cert, AuthCfg),
            {ok, BCert} = file:read_file(CertFile),
            DecodedCert = apns_cert:decode_cert(BCert),
            #{subject_uid := Topic} = apns_cert:get_cert_info_map(DecodedCert),
            Topic;
        _ ->
            list_to_binary(UserTopic)
    end.

%%--------------------------------------------------------------------
timestamp_desc(undefined) ->
    undefined;
timestamp_desc(TS) when is_integer(TS), TS >= 0 ->
    to_bin(posix_ms_to_iso8601(TS)).

%%--------------------------------------------------------------------
-spec make_auth_opts(AuthCfg) -> AuthOpts when
      AuthCfg :: auth_cfg(), AuthOpts :: auth_opts().
make_auth_opts(AuthCfg) ->
    APNSCert = sc_util:req_val(apns_cert, AuthCfg),
    APNSKey = sc_util:req_val(apns_key, AuthCfg),
    APNSCACert = case sc_util:val(apns_ca_cert, AuthCfg, []) of
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
      Result :: {Scheme, Host, Port}, Scheme :: https | http,
      Host :: string(), Port :: non_neg_integer().
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
    Scheme = case sc_util:val(no_ssl, Opts, false) of
                 true  -> http;
                 false -> https
             end,
    {Scheme, Host, Port}.

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
