%%%-------------------------------------------------------------------
%%% @author Edwin Fine
%%% @copyright (C) 2016, Silent Circle LLC
%%% @doc Main aptest module.
%%% @end
%%%-------------------------------------------------------------------
-module(aptest_main).
-export([exec/2]).
-import(aptest_util, [msg/2, msg/3, err_msg/2, err_msg/3, to_s/1]).

-define(RC_SUCCESS, 0).
-define(RC_ERROR, 1).
-define(RC_FATAL, 2).

-type return_code() :: integer().
-type terminate_arg() :: atom() |
                         {error, string()} |
                         {exception, Class :: atom(), Reason :: term()} |
                         {return_code(), string()} |
                         return_code().

%%--------------------------------------------------------------------
-spec exec(PgmName, Args) -> Result when
      PgmName :: string(), Args :: [string()], Result :: integer().
exec(PgmName, Args) ->
    {ok, _Apps} = application:ensure_all_started(aptest),
    terminate(PgmName, do_main(Args)).

%%--------------------------------------------------------------------
-spec do_main(Args) -> Result when
      Args :: [string()], Result :: terminate_arg().
do_main([]) ->
    help;
do_main(Args) ->
    try aptest_cmdline:parse_args(Args) of
        {ok, {action_help, _Config}} ->
            help;
        {ok, {action_version, _Config}} ->
            version;
        {error, _Errmsg} = Err ->
            Err;
        {ok, {Action, Config}} ->
            run(Action, Config)
    catch
        Class:Reason ->
            err_msg("Class: ~p, Reason: ~p~n", [Class, Reason]),
            {exception, Class, Reason}
    end.

%%--------------------------------------------------------------------
-spec run(Action, Config) -> Result when
      Action :: aptest_cmdline:action(),
      Config :: aptest_cmdline:config(),
      Result :: terminate_arg().
run(action_connect, Config) ->
    connect(Config);
run(action_send, Config) ->
    send(Config);
run(action_showcert, Config) ->
    show_cert(Config);
run(Action, Config) ->
    msg("Action: ~p~nConfig:~n~p~n", [Action, Config]),
    {error, "Unhandled action: " ++ sc_util:to_list(Action)}.

%%--------------------------------------------------------------------
-spec terminate(ScriptName, Arg) -> integer() when
      ScriptName :: string(),
      Arg :: terminate_arg().
terminate(ScriptName, help) ->
    usage(ScriptName),
    terminate(ScriptName, ?RC_ERROR);
terminate(ScriptName, version) ->
    version(ScriptName),
    terminate(ScriptName, ?RC_ERROR);
terminate(ScriptName, {error, Errmsg}) ->
    usage(ScriptName),
    err_msg("***** ~s~n~n", [Errmsg], no_ts),
    terminate(ScriptName, ?RC_ERROR);
terminate(ScriptName, {exception, Class, Reason}) ->
    err_msg("***** ~p:~n~p~n", [Class, Reason], no_ts),
    err_msg("~p~n~n", [erlang:get_stacktrace()], no_ts),
    terminate(ScriptName, ?RC_FATAL);
terminate(ScriptName, {RC, Errmsg}) when is_integer(RC) ->
    err_msg("***** ~s~n~n", [Errmsg], no_ts),
    terminate(ScriptName, RC);
terminate(_ScriptName, RC) when is_integer(RC) ->
    RC.

%%--------------------------------------------------------------------
-spec usage(PgmName) -> ok when PgmName :: string().
usage(PgmName) ->
    aptest_cmdline:usage(PgmName),
    ok.

%%--------------------------------------------------------------------
-spec version(PgmName) -> ok when PgmName :: string().
version(PgmName) ->
    {ok, App} = application:get_application(?MODULE),
    case lists:keyfind(App, 1, application:which_applications()) of
        {App, Desc, Vsn} ->
            msg("~p ~s (~s)~n", [App, Vsn, Desc], no_ts);
        false ->
            msg("~s <unknown version>~n", [PgmName], no_ts)
    end.

%%--------------------------------------------------------------------
connect(Config0) ->
    {_, AptestCfg} = aptest_util:req_prop(aptest, Config0),
    Env = sc_util:req_val(apns_env, AptestCfg),
    Config = combine_configs(Config0),
    CallbackMod = sc_util:req_val(mod, Config),
    case CallbackMod:connect(Config, Env) of
        ok ->
            0;
        Error ->
            err_msg("Error:~n~p~n", [Error]),
            2
    end.

%%--------------------------------------------------------------------
send(Config) ->
    {_, AptestCfg} = aptest_util:req_prop(aptest, Config),

    JSON = case sc_util:req_val(no_json, AptestCfg) of
               true ->
                   <<>>;
               false ->
                   make_json(AptestCfg)
           end,

    Token = sc_util:to_bin(sc_util:req_val(apns_token, AptestCfg)),

    CombinedConfig = combine_configs(Config),
    Env = sc_util:req_val(apns_env, AptestCfg),
    CallbackMod = sc_util:req_val(mod, CombinedConfig),
    try CallbackMod:send(Token, JSON, CombinedConfig, Env) of
        ok ->
            msg("Pushed without receiving APNS error!~n", []),
            0;
        {error, {[{_,_}|_] = _Hdrs, [<<_Body/binary>>]}=AE} ->
            err_msg("APNS error:~n~s~n",
                    [CallbackMod:format_apns_error(AE)]),
            1;
        {error, {connection_error, ErrorText}} ->
            err_msg("Connection error: ~s~n", [ErrorText]),
            2;
        Error ->
            err_msg("Error:~n~p~n", [Error]),
            2
    catch
        _:{error, {tls_alert, TlsError}} ->
            err_msg("TLS error: ~s~n", [TlsError]),
            2
    end.

%%--------------------------------------------------------------------
show_cert(Config) ->
    {_, Aptest} = aptest_util:req_prop(aptest, Config),
    case sc_util:val(no_ssl, Aptest) of
        true ->
            _ = io:format("no_ssl was selected, cannot view cert");
        _ ->
            {ok, _Apps} = application:ensure_all_started(ssl),
            {_, AuthCfg} = aptest_util:req_prop(auth_opts, Config),
            case sc_util:val(apns_auth, AuthCfg) of
                [] ->
                    APNSCert = sc_util:req_val(apns_cert, AuthCfg),
                    {ok, Cert} = file:read_file(APNSCert),
                    DecodedCert = apns_cert:decode_cert(Cert),
                    CertMap = apns_cert:get_cert_info_map(DecodedCert),
                    {Pairs, MaxName} = format_cert_info(CertMap),
                    Fmt = "~-" ++ integer_to_list(MaxName + 2) ++ "s~s\n",
                    _ = [io:format(Fmt, [Name, Val]) ||
                         {Name, Val} <- lists:sort(Pairs)],
                    0;
                Auth ->
                    _ = io:format("apns_auth=~s takes precedence over "
                                  "certificates", [Auth]),
                    0
            end
    end.


%%--------------------------------------------------------------------
make_notification(Message, Badge, Sound) ->
    [{alert, list_to_binary(Message)}] ++
    maybe_badge(Badge) ++
    maybe_sound(Sound).

%%--------------------------------------------------------------------
make_json(AptestCfg) ->
    case sc_util:req_val(raw_json, AptestCfg) of
        [] ->
             Message = sc_util:req_val(message, AptestCfg),
             Badge = sc_util:req_val(badge, AptestCfg),
             Sound = sc_util:req_val(sound, AptestCfg),
             Notification = make_notification(Message, Badge, Sound),
             apns_json:make_notification(Notification);
        RawJSON ->
            sc_util:to_bin(RawJSON)
    end.

%%--------------------------------------------------------------------
maybe_badge(N) when is_integer(N), N < 0 ->
    [];
maybe_badge(N) when is_integer(N) ->
    [{badge, N}].

%%--------------------------------------------------------------------
maybe_sound("") ->
    [];
maybe_sound(Sound) ->
    [{sound, sc_util:to_bin(Sound)}].

%%--------------------------------------------------------------------
-spec format_cert_info(CertInfo) -> Result when
      CertInfo :: map(), Result :: {[{binary(), binary()}], integer()}.
format_cert_info(#{} = CertInfo) ->
    lists:foldl(
      fun({topics, [_|_] = Topics}, {L, Max}) ->
              BName = <<"topics">>,
              BVal = format_topics(Topics),
              {[{BName, BVal}|L], max(Max, byte_size(BName))};
        ({Name, Val}, {L, Max}) ->
              BName = sc_util:to_bin(Name),
              BVal = sc_util:to_bin(Val),
              {[{BName, BVal}|L], max(Max, byte_size(BName))}
      end, {[], 0}, maps:to_list(CertInfo)).

%%--------------------------------------------------------------------
format_topics(Topics) ->
    list_to_binary(lists:foldl(fun({K, V}, Acc) ->
                                       [[K, $:, $\s, V, $;, $\s]|Acc]
                               end, [], Topics)).

%%--------------------------------------------------------------------
-spec module_for_version(Vsn) -> Module when
      Vsn :: pos_integer(), Module :: atom().
module_for_version(Vsn) when is_integer(Vsn), Vsn > 0 ->
    list_to_atom("aptest_apnsv" ++ integer_to_list(Vsn)).

%%--------------------------------------------------------------------
-spec combine_configs(Config) -> Result when
      Config :: list(), Result :: list().
combine_configs(Config) ->
    aptest_util:maybe_show_opts(Config),
    {_, AptestCfg} = aptest_util:req_prop(aptest, Config),
    APNSVersion = sc_util:req_val(apns_version, AptestCfg),
    Mod = module_for_version(APNSVersion),
    StartSSL = not sc_util:val(no_ssl, AptestCfg, false),
    StartSSL andalso application:ensure_all_started(ssl),
    {_, AuthCfg} = aptest_util:req_prop(auth_opts, Config),

    AuthOpts = case sc_util:val(apns_auth, AuthCfg, []) of
                   [] ->
                       Mod:make_auth_opts(AuthCfg);
                   Auth ->
                       case APNSVersion > 2 of
                           true ->
                               Mod:make_auth_opts(AuthCfg);
                           false ->
                               throw({incompatible_opts,
                                      {apns_auth, Auth,
                                       apns_version, APNSVersion}})
                       end
               end,
    [{mod, Mod}, {auth_opts, AuthOpts} | AptestCfg].

% ex: set ft=erlang fenc=utf-8 sts=4 ts=4 sw=4 et:
