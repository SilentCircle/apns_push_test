-module(aptest).
-export([main/1]).
-import(aptest_util, [msg/2, err_msg/2, to_s/1]).

-define(RC_SUCCESS, 0).
-define(RC_ERROR, 1).
-define(RC_FATAL, 2).

-type return_code() :: integer().
-type terminate_arg() :: 'help' |
                         {error, string()} |
                         {exception, Class :: atom(), Reason :: term()} |
                         {return_code(), string()} |
                         return_code().

%%--------------------------------------------------------------------
%% main([Token, Msg, APNSCert, APNSKey]) ->
%%     main([Token, Msg, APNSCert, APNSKey, "prod"]);
%% main([Token, Msg, APNSCert, APNSKey, PD]) when PD == "prod"; PD == "dev" ->
%%     RC = run([Token, Msg, APNSCert, APNSKey, PD]),
%%     halt(RC);
%% main(_) ->
%%     usage().

-spec main(Args) -> no_return() when Args :: [string()].
main(Args) ->
    PgmName = filename:basename(escript:script_name()),
    halt(terminate(PgmName, do_main(Args))).

%%--------------------------------------------------------------------
-spec do_main(Args) -> Result when
      Args :: [string()], Result :: terminate_arg().
do_main(Args) ->
    try aptest_cmdline:parse_args(Args) of
        {ok, {action_help, _Config}} ->
            help;
        {error, _Errmsg} = Err ->
            Err;
        {ok, {Action, Config}} ->
            try_run(Action, Config)
    catch
        Class:Reason ->
            err_msg("Class: ~p, Reason: ~p~n", [Class, Reason]),
            {exception, Class, Reason}
    end.

%%--------------------------------------------------------------------
-spec try_run(Action, Config) -> Result when
      Action :: aptest_cmdline:action(),
      Config :: aptest_cmdline:config(),
      Result :: terminate_arg().
try_run(Action, Config) ->
    run(Action, Config).

%%--------------------------------------------------------------------
-spec run(Action, Config) -> Result when
      Action :: aptest_cmdline:action(),
      Config :: aptest_cmdline:config(),
      Result :: terminate_arg().
run(action_default, Config) ->
    run(action_send, Config);
run(action_send, Config) ->
    send(Config);
run(action_sendfile, Config) ->
    send_file(Config);
run(Action, Config) ->
    msg("Action: ~p~nConfig:~n~p~n", [Action, Config]),
    {error, "Unhandled action: " ++ to_s(Action)}.

%%--------------------------------------------------------------------
-spec terminate(ScriptName, Arg) -> integer() when
      ScriptName :: string(),
      Arg :: terminate_arg().
terminate(ScriptName, help) ->
    usage(ScriptName),
    terminate(ScriptName, ?RC_ERROR);
terminate(ScriptName, {error, Errmsg}) ->
    usage(ScriptName),
    err_msg("***** ~s~n~n", [Errmsg]),
    terminate(ScriptName, ?RC_ERROR);
terminate(ScriptName, {exception, Class, Reason}) ->
    err_msg("***** ~p:~n~p~n", [Class, Reason]),
    err_msg("~p~n~n", [erlang:get_stacktrace()]),
    terminate(ScriptName, ?RC_FATAL);
terminate(ScriptName, {RC, Errmsg}) when is_integer(RC) ->
    err_msg("***** ~s~n~n", [Errmsg]),
    terminate(ScriptName, RC);
terminate(_ScriptName, RC) when is_integer(RC) ->
    RC.

-spec usage(PgmName) -> ok when PgmName :: string().
usage(PgmName) ->
    aptest_cmdline:usage(PgmName),
    ok.

%%--------------------------------------------------------------------
send(Config) ->
    {_, AptestCfg} = aptest_util:req_prop(aptest, Config),
    {_, SSLCfg} = aptest_util:req_prop(ssl_opts, Config),

    {ok, _Apps} = application:ensure_all_started(ssl),

    APNSVersion = sc_util:req_val(apns_version, AptestCfg),
    Mod = list_to_atom("aptest_apnsv" ++ integer_to_list(APNSVersion)),

    JSON = case sc_util:req_val(raw_json, AptestCfg) of
               [] ->
                    Message = sc_util:req_val(message, AptestCfg),
                    Badge = sc_util:req_val(badge, AptestCfg),
                    Sound = sc_util:req_val(sound, AptestCfg),
                    Notification = make_notification(Message, Badge, Sound),
                    apns_json:make_notification(Notification);
               RawJSON ->
                   sc_util:to_bin(RawJSON)
           end,

    APNSCert = sc_util:req_val(apns_cert, SSLCfg),
    APNSKey = sc_util:req_val(apns_key, SSLCfg),
    SSLOpts = Mod:make_ssl_opts(APNSCert, APNSKey),
    Opts = [{ssl_opts, SSLOpts}],

    Token = sc_util:to_bin(sc_util:req_val(apns_token, AptestCfg)),
    APNSEnv = sc_util:req_val(apns_env, AptestCfg),

    case Mod:send(Token, JSON, Opts, APNSEnv) of
        ok ->
            msg("Pushed without receiving APNS error!~n", []),
            0;
        {error, AE} ->
            msg("APNS error:~n~s~n", [Mod:format_apns_error(AE)]),
            1;
        Error ->
            msg("Error:~n~p~n", [Error]),
            2
    end.

send_file(Config) ->
    {_, AptestCfg} = aptest_util:req_prop(aptest, Config),

    {ok, _Apps} = application:ensure_all_started(ssl),

    case sc_util:val(apns_version, AptestCfg) of
        X when X =:= undefined; X =:= 3 ->
            ok;
        V ->
            msg("--file only works with APNS v3, ignoring version ~B", [V])
    end,
    Mod = aptest_apnsv3,

    Filename = sc_util:req_val(file, AptestCfg),
    JSON = case sc_util:req_val(raw_json, AptestCfg) of
               [] ->
                   Message = sc_util:req_val(message, AptestCfg),
                   Badge = sc_util:req_val(badge, AptestCfg),
                   Sound = sc_util:req_val(sound, AptestCfg),
                   Notification = make_notification(Message, Badge, Sound),
                   apns_json:make_notification(Notification);
               RawJSON ->
                   sc_util:to_bin(RawJSON)
           end,
    %% Results :: list(CertKeyResult),
    %% CertKeyResult :: {{CertFilename,KeyFilename}, [Result]}
    _ = [handle_sendfile_result(Result, Mod)
         || Result <- Mod:send_file(Filename, JSON)],
    0
    .

handle_sendfile_result({{CertFile,KeyFile}, Results}, Mod) ->
    {Good, Bad} = lists:partition(fun({ok, _}) -> true;
                                     (_)       -> false
                                  end, Results),

    msg("Results for cert file ~s, key file ~s\n", [CertFile, KeyFile]),
    msg("Successes: ~B, Failures: ~B\n\n", [length(Good), length(Bad)]),
    case Bad of
        [] ->
            0;
        _ ->
            lists:foreach(
              fun({error, {AE, Token}}) ->
                    msg("Error for ~s:\n~s\n",
                        [Token, Mod:format_apns_error(AE)])
              end, Bad),
            1
    end.

make_notification(Message, Badge, Sound) ->
    [{alert, list_to_binary(Message)}] ++
    maybe_badge(Badge) ++
    maybe_sound(Sound).

maybe_badge(N) when is_integer(N), N < 0 ->
    [];
maybe_badge(N) when is_integer(N) ->
    [{badge, N}].

maybe_sound("") ->
    [];
maybe_sound(Sound) ->
    [{sound, sc_util:to_bin(Sound)}].
