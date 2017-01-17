-module(aptest_cmdline).

%%====================================================================
%% API Exports
%%====================================================================

-export([
         option_spec_list/0,
         parse_args/1,
         usage/1
        ]).

%%====================================================================
%% Internal exports
%%====================================================================
-export([
         assert_or_die_fun/2
        ]).

-export_type([action/0, config/0]).

%%====================================================================
%% Defines
%%====================================================================
-define(UUID_RE, "^[[:xdigit:]]{8}(?:-[[:xdigit:]]{4}){3}-[[:xdigit:]]{12}$").

%%====================================================================
%% Includes
%%====================================================================
-include_lib("kernel/include/inet.hrl").
-include("aptest.hrl").

%%====================================================================
%% Typespecs
%%====================================================================
-type opt_specs() :: [getopt:option_spec()].
-type options() :: [getopt:option()].
-type action() :: atom().
-type config() :: proplists:proplist().

%%====================================================================
%% API
%%====================================================================
-spec option_spec_list() -> opt_specs().
option_spec_list() ->
    [
     {action_send,     undefined, "send",            undefined,               "Send notification"                      },
     {action_connect,  undefined, "connect",         undefined,               "Test connection to APNS"                },
     {action_showcert, undefined, "showcert",        undefined,               "Show certificate information"           },
     {apns_auth,       $a,        "apns-auth",       {string, ""},            "APNS auth private key file"             },
     {apns_cert,       $c,        "apns-cert",       {string, ""},            "APNS certificate file"                  },
     {apns_ca_cert,    $A,        "apns-ca-cert",    {string, ""},            "APNS CA chain certificate file"         },
     {apns_env,        $e,        "apns-env",        {atom, prod},            "APNS environment (prod|dev)"            },
     {apns_expiration, $x,        "apns-expiration", {integer, -1},           "APNS expiration time (optional)"        },
     {apns_key,        $k,        "apns-key",        {string, ""},            "APNS private key file"                  },
     {apns_host,       $H,        "apns-host",       {string, ""},            "APNS host (optional)"                   },
     {apns_id,         $i,        "apns-id",         {string, ""},            "APNS uuid (optional)"                   },
     {apns_issuer,     $I,        "apns-issuer",     {string, ""},            "APNS issuer (required for apns-auth)"   },
     {apns_kid,        $K,        "apns-kid",        {string, ""},            "APNS JWT kid (required for apns-auth)"  },
     {apns_port,       $p,        "apns-port",       {integer, -1},           "APNS port (optional)"                   },
     {apns_priority,   $P,        "apns-priority",   {integer, -1},           "APNS priority (optional)"               },
     {apns_token,      $t,        "apns-token",      {string, ""},            "APNS hexadecimal token"                 },
     {apns_topic,      $T,        "apns-topic",      {string, ""},            "APNS topic (defaults to cert topic)"    },
     {apns_version,    $v,        "apns-version",    {integer,  3},           "APNS protocol version"                  },
     {badge,           $b,        "badge",           {integer, -1},           "APNS badge count [-1: unchanged]"       },
     {help,            $h,        "help",            undefined,               "Show help"                              },
     {message,         $m,        "message",         {string, ""},            "APNS alert text"                        },
     {no_check_json,   $n,        "no-check-json",   {boolean, false},        "Allow invalid raw JSON"                 },
     {no_json,         $N,        "no-json",         {boolean, false},        "Omit the APNS payload"                  },
     {no_ssl,          $S,        "no-ssl",          {boolean, false},        "Use HTTP without SSL for debugging"     },
     {raw_json,        $r,        "raw-json",        {string, ""},            "Raw APNS JSON notification"             },
     {relaxed,         $L,        "relaxed-mode",    {boolean, false},        "Allow some invalid notification data"   },
     {sound,           $s,        "sound",           {string, ""},            "APNS sound file name"                   },
     {verbose,         $V,        "verbose",         {boolean, false},        "Verbose output"                         },
     {version,         undefined, "version",         undefined,               "Show aptest version"                    }
    ].

%%--------------------------------------------------------------------
-spec parse_args(Args) -> Result when
      Args :: [string()], Result :: {ok, {Action, Config}} | {error, ErrorText},
      Action :: atom(), Config :: proplists:proplist(), ErrorText :: string().
parse_args(Args) ->
    OptSpecList = option_spec_list(),
    Result = case getopt:parse(OptSpecList, Args) of
                 {ok, {Opts, NonOpts}} ->
                     show_parse_results(Opts, NonOpts),
                     Cfg = make_action_cfg(OptSpecList, Opts, NonOpts),
                     validate_action_cfg(Cfg);
                 Error ->
                     Error
             end,
    wrap_result(OptSpecList, Result).

%%--------------------------------------------------------------------
usage(PgmName) ->
    getopt:usage(option_spec_list(), PgmName).

%%%====================================================================
%%% Internal functions
%%%====================================================================

%%--------------------------------------------------------------------
%% Getopt-related
%%--------------------------------------------------------------------
-spec make_action_cfg(OptSpecList, Opts, NonOpts) -> Result when
      OptSpecList :: opt_specs(), Opts :: options(), NonOpts :: [string()],
      Result :: {ok, {Action, Config}} | {error, Reason},
      Action :: action(), Config :: config(), Reason :: term().
make_action_cfg(OptSpecList, Opts, NonOpts) ->
    case info_action(Opts) of
        none ->
            make_checked_action_cfg(OptSpecList, Opts, NonOpts);
        Action ->
            Action
    end.

%%--------------------------------------------------------------------
-spec make_checked_action_cfg(OptSpecList, Opts, NonOpts) -> Result when
      OptSpecList :: opt_specs(), Opts :: options(), NonOpts :: [string()],
      Result :: {ok, {Action, Config}} | {error, Reason},
      Action :: action(), Config :: config(), Reason :: term().
make_checked_action_cfg(OptSpecList, Opts, NonOpts) ->
    case getopt:check(OptSpecList, Opts) of
        ok ->
            make_action_cfg(Opts, NonOpts);
        Error ->
            Error
    end.

%%--------------------------------------------------------------------
-spec make_action_cfg(Opts, NonOpts) -> Result when
      Opts :: options(), NonOpts :: [string()],
      Result :: {ok, {Action, Config}} | {error, Reason},
      Action :: action(), Config :: config(), Reason :: term().
make_action_cfg(Opts, []) ->
    try
        Action = get_action(Opts),
        AptestCfg = make_aptest_cfg(Action, Opts),
        AuthCfg = make_auth_cfg(Action, Opts),
        Cfg = [{aptest, AptestCfg}, {auth_opts, AuthCfg}],
        {ok, {Action, Cfg}}
    catch
        throw:Error ->
            {error, Error}
    end;
make_action_cfg(_Opts, NonOpts) ->
    {error, {invalid_arg, NonOpts}}.

%%--------------------------------------------------------------------
-spec info_action(Opts) -> Result when
      Opts :: options(), Result :: {ok, {atom(), []}} | none.
info_action(Opts) ->
    lists:foldl(fun(help, none)    -> atom_to_action(help);
                   (version, none) -> atom_to_action(version);
                   (_, Acc)        -> Acc
                end, none, Opts).

%%--------------------------------------------------------------------
-spec get_action(Opts) -> Result when
      Opts :: options(), Result :: action().
get_action(Opts) ->
    L = lists:foldl(fun(action_send,     Acc) -> [action_send | Acc];
                       (action_connect,  Acc) -> [action_connect | Acc];
                       (action_showcert, Acc) -> [action_showcert | Acc];
                       (_,               Acc) -> Acc
                    end, [], Opts),
    case L of
        [Action] ->
            Action;
        L when is_list(L) ->
            Actions = action_list(option_spec_list()),
            throw({'Provide one of the following actions',
                   "'" ++ Actions ++ "'"})
    end.

%%--------------------------------------------------------------------
%% Config creators
%%--------------------------------------------------------------------
%%--------------------------------------------------------------------
make_aptest_cfg(action_connect, Opts) ->
    ValFuns = [fun verbose/1,
               fun apns_env/1,
               fun apns_host/1,
               fun apns_port/1,
               fun apns_version/1,
               fun no_ssl/1],
    lists:foldl(fun(ValFun, Acc) -> [ValFun(Opts)|Acc] end, [], ValFuns);
make_aptest_cfg(action_send, Opts) ->
    ValFuns = [fun apns_env/1,
               fun apns_expiration/1,
               fun apns_host/1,
               fun apns_id/1,
               fun apns_kid/1,
               fun apns_port/1,
               fun apns_priority/1,
               fun apns_token/1,
               fun apns_topic/1,
               fun apns_version/1,
               fun badge/1,
               fun message/1,
               fun no_json/1,
               fun no_ssl/1,
               fun raw_json/1,
               fun relaxed/1,
               fun sound/1,
               fun verbose/1],
    lists:foldl(fun(ValFun, Acc) -> [ValFun(Opts)|Acc] end, [], ValFuns);
make_aptest_cfg(action_showcert, Opts) ->
    ValFuns = [fun verbose/1],
    lists:foldl(fun(ValFun, Acc) -> [ValFun(Opts)|Acc] end, [], ValFuns).

%%--------------------------------------------------------------------
make_auth_cfg(action_connect, Opts) ->
    case sc_util:val(no_ssl, Opts, false) of
        true ->
            [apns_auth(Opts),
             apns_issuer(Opts),
             apns_kid(Opts)];
        false ->
            [
             apns_auth(Opts),
             apns_issuer(Opts),
             apns_kid(Opts),
             apns_cert(Opts),
             apns_ca_cert(Opts),
             apns_key(Opts)
            ]
    end;
make_auth_cfg(action_send, Opts) ->
    case sc_util:val(no_ssl, Opts, false) of
        true ->
            [
             apns_auth(Opts),
             apns_issuer(Opts),
             apns_kid(Opts)
            ];
        false ->
            [
             apns_auth(Opts),
             apns_issuer(Opts),
             apns_kid(Opts),
             apns_cert(Opts),
             apns_ca_cert(Opts),
             apns_key(Opts)
            ]
    end;
make_auth_cfg(action_showcert, Opts) ->
    case sc_util:val(no_ssl, Opts, false) of
        true ->
            [
             apns_auth(Opts)
            ];
        false ->
            [
             apns_auth(Opts),
             apns_cert(Opts)
            ]
    end.

%%--------------------------------------------------------------------
%% Predicates
%%--------------------------------------------------------------------
apns_auth(Opts) ->
    Pred = fun([]) -> true;
               (V) -> is_list(V) andalso filelib:is_regular(V)
           end,
    assert_prop(Pred, apns_auth, Opts).

%%--------------------------------------------------------------------
apns_cert(Opts) ->
    Pred = fun([]) -> true;
              (V) -> is_list(V) andalso filelib:is_regular(V)
           end,
    assert_prop(Pred, apns_cert, Opts).

%%--------------------------------------------------------------------
apns_ca_cert(Opts) ->
    Pred = fun([]) -> true;
              (V) -> is_list(V) andalso filelib:is_regular(V)
           end,
    assert_prop(Pred, apns_ca_cert, Opts).

%%--------------------------------------------------------------------
apns_expiration(Opts) ->
    Pred = fun(V) ->
                   strict(Opts, is_integer_range(V, -1, 16#FFFFFFFF))
           end,
    assert_prop(Pred, apns_expiration, Opts).

%%--------------------------------------------------------------------
apns_env(Opts) ->
    Pred = fun(V) -> V =:= prod orelse V =:= dev end,
    assert_prop(Pred, apns_env, Opts).

%%--------------------------------------------------------------------
apns_host(Opts) ->
    Pred = fun(V) -> is_string(V) end,
    assert_prop(Pred, apns_host, Opts).

%%--------------------------------------------------------------------
apns_id(Opts) ->
    Pred = fun([]) -> true;
              (V)  -> strict(Opts, is_uuid(V))
           end,
    assert_prop(Pred, apns_id, Opts).

%%--------------------------------------------------------------------
apns_issuer(Opts) ->
    Pred = fun([]) -> true;
              (V) -> is_string(V)
           end,
    assert_prop(Pred, apns_issuer, Opts).

%%--------------------------------------------------------------------
apns_key(Opts) ->
    Pred = fun([]) -> true;
              (V) -> is_list(V) andalso filelib:is_regular(V)
           end,
    assert_prop(Pred, apns_key, Opts).

%%--------------------------------------------------------------------
apns_kid(Opts) ->
    Pred = fun([]) -> true;
              (V) -> is_string(V)
           end,
    assert_prop(Pred, apns_kid, Opts).

%%--------------------------------------------------------------------
apns_port(Opts) ->
    Pred = fun(V) -> is_integer_range(V, -1, 16#FFFF) end,
    assert_prop(Pred, apns_port, Opts).

%%--------------------------------------------------------------------
apns_priority(Opts) ->
    Pred = fun(V) when is_integer(V) ->
                   strict(Opts, V == -1 orelse V == 5 orelse V == 10)
           end,
    assert_prop(Pred, apns_priority, Opts).

%%--------------------------------------------------------------------
apns_token(Opts) ->
    Pred = fun(V) -> is_nonempty_string(V) end,
    assert_prop(Pred, apns_token, Opts).

%%--------------------------------------------------------------------
%% If no_ssl is true, apns_topic is mandatory
apns_topic(Opts) ->
    NoSsl = aptest_util:req_prop(no_ssl, Opts),
    Pred = case NoSsl of
               {_, false} ->
                   fun(V) -> is_string(V) end;
               {_, true} ->
                   fun(V) -> is_nonempty_string(V) end
           end,
    assert_prop(Pred, apns_topic, Opts).

%%--------------------------------------------------------------------
apns_version(Opts) ->
    Pred = fun(V) -> is_integer_range(V, ?MIN_APNS_VER, ?MAX_APNS_VER) end,
    assert_prop(Pred, apns_version, Opts).

%%--------------------------------------------------------------------
badge(Opts) ->
    Pred = fun(V) -> is_integer_range(V, -1, ?MAX_APNS_BADGE) end,
    assert_prop(Pred, badge, Opts).

%%--------------------------------------------------------------------
%% If either raw_json or no_check_json is provided, message must not be
%% provided
message(Opts) ->
    RawJson = aptest_util:req_prop(raw_json, Opts),
    NoJson = aptest_util:req_prop(no_json, Opts),
    MessageMustBeEmpty = case {RawJson, NoJson} of
                             {{_, [_|_]}, _} -> true;
                             {_, {_, true}} -> true;
                             _ -> false
                         end,
    Pred = case MessageMustBeEmpty of
               true ->
                   fun(V) -> V == [] end;
               false ->
                   fun(V) -> is_nonempty_string(V) end
           end,
    assert_prop(Pred, message, Opts).

%%--------------------------------------------------------------------
%% If raw_json is provided, message must not be provided
raw_json(Opts) ->
    Pred = case aptest_util:req_prop(message, Opts) of
               {_, [_|_]} ->
                   fun(V) -> V == [] end;
               _ ->
                   fun([]) ->
                           true;
                      (V) ->
                           case nocheck_json(Opts) of
                               false ->
                                   B = sc_util:to_bin(V),
                                   jsx:is_json(B);
                               true ->
                                   true
                           end
                   end
           end,
    assert_prop(Pred, raw_json, Opts).

%%--------------------------------------------------------------------
relaxed(Opts) ->
    sc_util:val(relaxed, Opts, false).

%%--------------------------------------------------------------------
sound(Opts) ->
    assert_prop(fun io_lib:printable_unicode_list/1, sound, Opts).

%%--------------------------------------------------------------------
nocheck_json(Opts) ->
    sc_util:val(no_check_json, Opts, false).

%%--------------------------------------------------------------------
no_json(Opts) ->
    assert_prop(fun(_) -> true end, no_json, Opts).

%%--------------------------------------------------------------------
no_ssl(Opts) ->
    assert_prop(fun(_) -> true end, no_ssl, Opts).

%%--------------------------------------------------------------------
verbose(Opts) ->
    lists:foldl(fun({verbose, _} = V, _Acc) -> V;
                   (_, Acc) -> Acc
                end, aptest_util:req_prop(verbose, Opts), Opts).

%%--------------------------------------------------------------------
%% Helper functions
%%--------------------------------------------------------------------
assert_prop(Pred, Key, Props) when is_function(Pred, 1), is_list(Props) ->
    Prop = aptest_util:req_prop(Key, Props),
    Exc = case Prop of
              {Key, []} -> {missing_required_option, Key};
              _         -> {invalid_option_arg, Prop}
          end,
    aptest_util:map_prop(assert_or_die_fun(Pred, Exc), Prop).

%%--------------------------------------------------------------------
assert_or_die_fun(Pred, Exc) ->
    fun(V) ->
            case Pred(V) of
                true  -> V;
                false -> throw(Exc)
            end
    end.

%%--------------------------------------------------------------------
strict(Opts, StrictTest) ->
    case is_relaxed(Opts) of
        true ->
            true;
        false ->
            StrictTest
    end.

%%--------------------------------------------------------------------
is_relaxed(Opts) ->
    sc_util:val(relaxed, Opts, false).

%%--------------------------------------------------------------------
-spec is_string(term()) -> boolean().
is_string(X) when is_binary(X) ->
    is_string(binary_to_list(X));
is_string(X) ->
    io_lib:printable_unicode_list(X).

%%--------------------------------------------------------------------
-spec is_nonempty_string(term()) -> boolean().
is_nonempty_string(X) when is_binary(X) ->
    is_nonempty_string(binary_to_list(X));
is_nonempty_string([_|_] = X) ->
    io_lib:printable_unicode_list(X);
is_nonempty_string(_) ->
    false.

%%--------------------------------------------------------------------
-spec is_integer_range(X, Min, Max) -> boolean()
    when X :: term(), Min :: integer(), Max :: integer().
is_integer_range(X, Min, Max) ->
    is_integer(X) andalso
    is_integer(Min) andalso
    is_integer(Max) andalso
    Max >= Min andalso
    X >= Min andalso
    X =< Max.

%%--------------------------------------------------------------------
-spec is_pos_integer_range(X, Max) -> boolean()
    when X :: term(), Max :: pos_integer().
is_pos_integer_range(X, Max) ->
    is_integer_range(X, 1, Max).

%%--------------------------------------------------------------------
-spec is_uuid(X) -> boolean() when
      X :: term().
is_uuid(X) ->
    is_nonempty_string(X) andalso % 8-4-4-4-12
    match == re:run(X, ?UUID_RE, [{capture, none}]).

%%--------------------------------------------------------------------
-spec wrap_result(OptSpecList, Result) -> WrappedResult when
      OptSpecList :: opt_specs(), Result :: OkResult | {error, term()},
      WrappedResult ::  OkResult | {error, nonempty_string()},
      OkResult :: {ok, term()}.
wrap_result(_OptSpecList, {ok, _} = Result) ->
    Result;
wrap_result(OptSpecList, Error) ->
    {error, lists:flatten(getopt:format_error(OptSpecList, Error))}.

%%--------------------------------------------------------------------
-spec action_list(OptSpecList) -> Result when
      OptSpecList :: opt_specs(), Result :: string().
action_list(OptSpecList) ->
    L = lists:foldl(fun({Name,_,_,_,_} = Opt, Acc) ->
                            case atom_to_list(Name) of
                                "action_" ++ _Rest ->
                                    [option_name(Opt) | Acc];
                                _ ->
                                    Acc
                            end
                    end, [], OptSpecList),
    string:join(lists:reverse(L), ", ").

%%--------------------------------------------------------------------
option_name({_,ShortName,undefined,_,_}) -> [$-, ShortName];
option_name({_,undefined,LongName,_,_}) -> "--" ++ LongName.

%%--------------------------------------------------------------------
show_parse_results(Opts, NonOpts) ->
    case sc_util:val(verbose, Opts) of
        true ->
            aptest_util:msg("Parse results:~nOpts: ~p~nNonOpts: ~p~n",
                            [Opts, NonOpts]);
        _ ->
            ok
    end.

%%--------------------------------------------------------------------
atom_to_action(Atom) when is_atom(Atom) ->
    Action = list_to_atom("action_" ++ atom_to_list(Atom)),
    {ok, {Action, []}}.

%%--------------------------------------------------------------------
-spec validate_action_cfg(CfgResult) -> Result when
      CfgResult :: {ok, {Action, Config}} | {error, Reason},
      Result :: {ok, {Action, Config}} | {error, Reason},
      Action :: action(), Config :: config(), Reason :: term().

%% TODO: Unstub this
validate_action_cfg(Any) -> Any.

%% if apns_auth is present:
%%  apns_version MUST be > 2
%%  apns_issuer MUST be present
%%  apns_ca_cert MUST be present
%%  action_showcert is invalid
%%  apns_cert and apns_key must be removed
%% else % apns_auth is absent
%%  apns_cert and apns_key MUST be present
%%  apns_ca_cert MUST be present
%%  apns_issuer must be removed
%%
%%validate_action_cfg({ok, {action_send, Config}} = Result) ->
%%    validate_send_config(Config),
%%    Result;
%%validate_action_cfg({ok, {action_connect, Config}} = Result) ->
%%    ok;
%%validate_action_cfg({ok, {action_showcert, Config}} = Result) ->
%%    ok;
%%validate_action_cfg({error, _} = Error) ->
%%    Error.
%%
%%-spec validate_send_config(Config) -> NewConfig when
%%      Config :: config(), NewConfig :: config().
%%validate_send_config(Config) ->
%%    {_, AptestCfg} = aptest_util:req_prop(aptest, Config),
%%    {_, AuthCfg} = aptest_util:req_prop(auth_opts, Config),
%%    case apns_auth(AuthCfg) of
%%        [] ->
%%            apns_cert(AuthCfg) /= [] andalso
%%            apns_key(AuthCfg) /= [] andalso
%%            apns_ca_cert(AuthCfg) /= [] andalso
%%            begin
%%                NewAptestCfg = remove_keys(AuthCfg, [apns_issuer]),
%%                lists:keystore(aptest, 1, Config, {aptest, NewAptestcfg})
%%            end;
%%        _AuthFile ->
%%            apns_version(AptestCfg) > 2 andalso
%%            apns_issuer(AuthCfg) /= [] andalso
%%            apns_ca_cert(AptestCfg) /= [] andalso
%%            begin
%%                NewAuthCfg = remove_keys(AuthCfg, [apns_cert, apns_keys]),
%%                lists:keystore(auth_opts, 1, Config, {auth_opts, NewAuthCfg})
%%            end
%%    end.
%%
%%valid_combinations(action_send) ->
%%    [
%%     {apns_auth, fun is_nonempty_string/1},
%%     {apns_version, fun(V) -> V > 2 end},
%%     {apns_issuer, fun is_nonempty_string/1},
%%     {apns_ca_cert, fun is_nonempty_string/1}
%%    ];
%%valid_combinations(action_connect) ->
%%    [
%%     {apns_auth, fun is_nonempty_string/1},
%%     {apns_version, fun(V) -> V > 2 end},
%%     {apns_issuer, fun is_nonempty_string/1},
%%     {apns_ca_cert, fun is_nonempty_string/1}
%%    ].

% ex: set ft=erlang fenc=utf-8 sts=4 ts=4 sw=4 et:
