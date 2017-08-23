-module(aptest_cmdline).
%% DEBUG
-compile(export_all).

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
     {action_help,     $h,        "help",            undefined,               "Show help"                              },
     {action_connect,  undefined, "connect",         undefined,               "Test connection to APNS"                },
     {action_send,     undefined, "send",            undefined,               "Send notification"                      },
     {action_showcert, undefined, "showcert",        undefined,               "Show certificate information"           },
     {action_version,  undefined, "version",         undefined,               "Show aptest version"                    },
     {apns_auth,       $a,        "apns-auth",       {string, ""},            "APNS token-based auth private key file" },
     {apns_cert,       $c,        "apns-cert",       {string, ""},            "APNS TLS certificate file"              },
     {apns_ca_cert,    $A,        "apns-ca-cert",    {string, ""},            "APNS CA chain certificate file"         },
     {apns_env,        $e,        "apns-env",        {atom, prod},            "APNS environment (prod|dev)"            },
     {apns_expiration, $x,        "apns-expiration", {integer, -1},           "APNS expiration time (optional)"        },
     {apns_key,        $k,        "apns-key",        {string, ""},            "APNS TLS certificate private key file"  },
     {apns_host,       $H,        "apns-host",       {string, ""},            "APNS host (optional)"                   },
     {apns_id,         $i,        "apns-id",         {string, ""},            "APNS uuid (optional)"                   },
     {apns_issuer,     $I,        "apns-issuer",     {string, ""},            "APNS JWT `iss` (for apns-auth)"         },
     {apns_kid,        $K,        "apns-kid",        {string, ""},            "APNS JWT `kid` (for apns-auth)"         },
     {apns_port,       $p,        "apns-port",       {integer, -1},           "APNS port (optional)"                   },
     {apns_priority,   $P,        "apns-priority",   {integer, -1},           "APNS priority (optional)"               },
     {apns_token,      $t,        "apns-token",      {string, ""},            "APNS hexadecimal token"                 },
     {apns_topic,      $T,        "apns-topic",      {string, ""},            "APNS topic (required for apns-auth)"    },
     {apns_version,    $v,        "apns-version",    {integer,  3},           "APNS protocol version"                  },
     {badge,           $b,        "badge",           {integer, -1},           "APNS badge count [-1: unchanged]"       },
     {message,         $m,        "message",         {string, ""},            "APNS alert text"                        },
     {no_check_json,   $n,        "no-check-json",   {boolean, false},        "Allow invalid raw JSON"                 },
     {no_json,         $N,        "no-json",         {boolean, false},        "Omit the APNS payload"                  },
     {no_ssl,          $S,        "no-ssl",          {boolean, false},        "Use HTTP without SSL for debugging"     },
     {raw_json,        $r,        "raw-json",        {string, ""},            "Raw APNS JSON notification"             },
     {relaxed,         $L,        "relaxed-mode",    {boolean, false},        "Allow some invalid notification data"   },
     {sound,           $s,        "sound",           {string, ""},            "APNS sound file name"                   },
     {trace,           undefined, "trace",           {boolean, false},        "Trace output (implies verbose)"         },
     {verbose,         $V,        "verbose",         {boolean, false},        "Verbose output"                         }
    ].

%%--------------------------------------------------------------------
-spec parse_args(Args) -> Result when
      Args :: [string()], Result :: {ok, {Action, Config}} | {error, ErrorText},
      Action :: atom(), Config :: proplists:proplist(), ErrorText :: string().
parse_args(Args) ->
    OptSpecList = option_spec_list(),
    Result = case getopt:parse(OptSpecList, Args) of
                 {ok, {Opts0, NonOpts}} ->
                     % Eliminate duplicate options such that the
                     % last duplicate option wins
                     {Ts, NonTs} = lists:partition(fun(X) -> is_tuple(X) end,
                                                   Opts0),
                     Opts = NonTs ++ dict:to_list(dict:from_list(Ts)),
                     show_parse_results(Opts, NonOpts),
                     Cfg = make_action_cfg(OptSpecList, Opts, NonOpts),
                     validate_action_cfg(Cfg);
                 Error ->
                     aptest_util:msg("Error pasring args: ~p", [Error]),
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
    try make_action_cfg_nocatch(Opts, []) of
        Result ->
            Result
    catch
        error:Reason ->
            {error, Reason}
    end;
make_action_cfg(_Opts, NonOpts) ->
    {error, {invalid_arg, NonOpts}}.

%%--------------------------------------------------------------------
make_action_cfg_nocatch(Opts, _NonOpts) ->
    Action = get_action(Opts),
    AptestCfg = make_aptest_cfg(Action, Opts),
    AuthCfg = make_auth_cfg(Action, Opts),
    Cfg = [{aptest, AptestCfg}, {auth_opts, AuthCfg}],
    {ok, {Action, Cfg}}.

%%--------------------------------------------------------------------
-spec validate_action_cfg(CfgResult) -> Result when
      CfgResult :: {ok, {Action, Config}} | {error, Reason},
      Result :: {ok, {Action, Config}} | {error, Reason},
      Action :: action(), Config :: config(), Reason :: term().

validate_action_cfg({ok, {Action, Config}}) ->
    try validate_rules(Action, Config) of
        Result ->
            Result
    catch
        Class:Reason ->
            ?trace("{~p, ~p}, stack trace follows:\n: ~p",
                   [Class, Reason, erlang:get_stacktrace()]),
            {error, Reason}
    end;
validate_action_cfg({error, _}=Error) ->
    Error.

%%--------------------------------------------------------------------
validate_rules(Action, Config) ->
    case lists:keyfind(Action, 1, rules()) of
        {_, []} ->
            {ok, {Action, Config}};
        {_, ActionRules} ->
            {_, AptestCfg} = aptest_util:req_prop(aptest, Config),
            {_, AuthCfg} = aptest_util:req_prop(auth_opts, Config),
            set_log_level(AptestCfg),
            walk_rules(ActionRules, AptestCfg ++ AuthCfg),
            {ok, {Action, Config}};
        false ->
            {error, {unknown_action, Action}}
    end.

%%--------------------------------------------------------------------
-spec info_action(Opts) -> Result when
      Opts :: options(), Result :: {ok, {atom(), []}} | none.
info_action(Opts) ->
    % Help takes precedence over version
    InfoActions = [action_help,
                   action_version],
    Actions = lists:foldr(fun(Action, Acc) ->
                                  case lists:member(Action, Opts) of
                                      true  -> [Action|Acc];
                                      false -> Acc
                                  end
                          end, [], InfoActions),

    case Actions of
        [Action|_] ->
            {ok, {Action, []}};
        [] ->
            none
    end.

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
    [
     v(apns_env,     is_valid_apns_env_fun(Opts),     Opts),
     v(apns_host,    is_nonempty_string_fun(Opts),    Opts),
     v(apns_port,    is_valid_port_fun(Opts),         Opts),
     v(apns_version, is_valid_apns_version_fun(Opts), Opts),
     v(no_ssl,       is_boolean_fun(Opts),            Opts),
     v(trace,        is_boolean_fun(Opts),            Opts),
     v(verbose,      is_boolean_fun(Opts),            Opts)
    ];
make_aptest_cfg(action_send, Opts) ->
    [
     v(apns_env,        is_valid_apns_env_fun(Opts),      Opts),
     v(apns_expiration, is_valid_expiration_fun(Opts),    Opts),
     v(apns_host,       is_nonempty_string_fun(Opts),     Opts),
     v(apns_id,         is_valid_apns_id_fun(Opts),       Opts),
     v(apns_kid,        is_nonempty_string_fun(Opts),     Opts),
     v(apns_port,       is_valid_port_fun(Opts),          Opts),
     v(apns_priority,   is_valid_apns_priority_fun(Opts), Opts),
     v(apns_token,      is_nonempty_string_fun(Opts),     Opts),
     v(apns_topic,      is_nonempty_string_fun(Opts),     Opts),
     v(apns_version,    is_valid_apns_version_fun(Opts),  Opts),
     v(badge,           is_valid_badge_fun(Opts),         Opts),
     v(message,         is_nonempty_string_fun(Opts),     Opts),
     v(no_check_json,   is_boolean_fun(Opts),             Opts),
     v(no_json,         is_boolean_fun(Opts),             Opts),
     v(no_ssl,          is_boolean_fun(Opts),             Opts),
     v(raw_json,        is_nonempty_string_fun(Opts),     Opts),
     v(relaxed,         is_boolean_fun(Opts),             Opts),
     v(sound,           is_valid_apns_sound_fun(Opts),    Opts),
     v(trace,           is_boolean_fun(Opts),             Opts),
     v(verbose,         is_boolean_fun(Opts),             Opts)
    ];
make_aptest_cfg(action_showcert, Opts) ->
    [
     v(trace,   is_boolean_fun(Opts), Opts),
     v(verbose, is_boolean_fun(Opts), Opts)
    ].

%%--------------------------------------------------------------------
make_auth_cfg(_, Opts) ->
    [
     v(apns_auth,       is_readable_file_fun(Opts),    Opts),
     v(apns_topic,      is_nonempty_string_fun(Opts),  Opts),
     v(apns_issuer,     is_nonempty_string_fun(Opts),  Opts),
     v(apns_kid,        is_nonempty_string_fun(Opts),  Opts),
     v(apns_cert,       is_readable_file_fun(Opts),    Opts),
     v(apns_ca_cert,    is_readable_file_fun(Opts),    Opts),
     v(apns_key,        is_readable_file_fun(Opts),    Opts)
    ].

%%--------------------------------------------------------------------
v(Opt, Pred, Opts) when is_function(Pred, 1) ->
    case sc_util:val(Opt, Opts, []) of
        []  -> {Opt, []};
        Val -> assert_kv(Pred, {Opt, Val})
    end.

%%--------------------------------------------------------------------
%% Predicate function creators
%%--------------------------------------------------------------------
%%--------------------------------------------------------------------
is_equal_fun({Value, _Opts}) ->
    fun(V) -> is_equal(V, Value) end.

%%--------------------------------------------------------------------
is_string_fun(_Opts) ->
    fun is_string/1.

%%--------------------------------------------------------------------
is_nonempty_string_fun(_Opts) ->
    fun is_nonempty_string/1.

%%--------------------------------------------------------------------
is_boolean_fun(_Opts) ->
    fun erlang:is_boolean/1.

%%--------------------------------------------------------------------
is_integer_range_fun({Min, Max, _Opts}) ->
    fun(X) -> is_integer_range(X, Min, Max) end.

%%--------------------------------------------------------------------
is_pos_integer_range_fun({Max, _Opts}) ->
    fun(X) -> is_pos_integer_range(X, Max) end.

%%--------------------------------------------------------------------
is_readable_file_fun(_Opts) ->
    fun(Filename) ->
        is_list(Filename) andalso filelib:is_regular(Filename)
    end.

%%--------------------------------------------------------------------
is_uuid_fun(_Opts) ->
    fun is_uuid/1.

%%--------------------------------------------------------------------
is_valid_expiration_fun(Opts) ->
    fun(V) ->
            strict(Opts, V, is_integer_range_fun({-1, 16#FFFFFFFF, Opts}))
    end.

%%--------------------------------------------------------------------
is_valid_apns_env_fun(_Opts) ->
    fun(V) -> V =:= prod orelse V =:= dev end.

%%--------------------------------------------------------------------
is_valid_apns_id_fun(Opts) ->
    fun(V) -> strict(Opts, V, is_uuid_fun(V)) end.

%%--------------------------------------------------------------------
is_valid_port_fun(_Opts) ->
    fun(V) -> is_integer_range(V, -1, 16#FFFF) end.

%%--------------------------------------------------------------------
is_valid_apns_priority_fun(Opts) ->
    fun(V) ->
            is_integer(V) andalso
            strict(Opts, V,
                   fun(P) -> P == -1 orelse P == 5 orelse P == 10 end)
    end.

%%--------------------------------------------------------------------
is_valid_apns_version_fun(_Opts) ->
    fun(V) -> is_integer_range(V, ?MIN_APNS_VER, ?MAX_APNS_VER) end.

%%--------------------------------------------------------------------
is_valid_badge_fun(_Opts) ->
    fun(V) -> is_integer_range(V, -1, ?MAX_APNS_BADGE) end.

%%--------------------------------------------------------------------
is_valid_apns_sound_fun(_Opts) ->
    fun io_lib:printable_unicode_list/1.

%%--------------------------------------------------------------------
%% Predicates
%%--------------------------------------------------------------------
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
strict(Opts, Val, StrictTestFun) when is_function(StrictTestFun, 1) ->
    is_relaxed(Opts) orelse StrictTestFun(Val).

%%--------------------------------------------------------------------
is_relaxed(Opts) ->
    sc_util:val(relaxed, Opts, false).

%%--------------------------------------------------------------------
-spec is_equal(term(), term()) -> boolean().
is_equal(X, X) -> true;
is_equal(_, _) -> false.

%%--------------------------------------------------------------------
%% Helper functions
%%--------------------------------------------------------------------
assert_prop(Pred, Key, Props) when is_function(Pred, 1), is_list(Props) ->
    Prop = aptest_util:req_prop(Key, Props),
    ?trace("Pred: ~p, Key: ~p, Prop: ~p", [Pred, Key, Prop]),
    Exc = case Prop of
              {Key, []} -> {missing_required_option, Key};
              _         -> {invalid_option_arg, Prop}
          end,
    aptest_util:map_prop(assert_or_die_fun(Pred, Exc), Prop).

%%--------------------------------------------------------------------
assert_kv(Pred, {Key, _Val}=Prop) when is_function(Pred, 1) ->
    ?trace("Pred: ~p, Key: ~p, Prop: ~p", [Pred, Key, _Val]),
    Exc = case Prop of
              {Key, []} -> {missing_required_option, Key};
              _         -> {invalid_option_arg, Prop}
          end,
    aptest_util:map_prop(assert_or_die_fun(Pred, Exc), Prop).

%%--------------------------------------------------------------------
check_prop(Pred, Key, Props) when is_function(Pred, 1), is_list(Props) ->
    {_, Val}=Prop = aptest_util:req_prop(Key, Props),
    ?trace("Pred: ~p, Key: ~p, Prop: ~p", [Pred, Key, Prop]),
    Pred(Val).

%%--------------------------------------------------------------------
assert_or_die_fun(Pred, Exc) when is_function(Pred, 1) ->
    fun(V) ->
            ?trace("Pred: ~p, Exc: ~p", [Pred, Exc]),
            case Pred(V) of
                true  -> V;
                false -> erlang:error(Exc)
            end
    end.

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
%% Rules engine
%%--------------------------------------------------------------------
-type cmdline_opt() :: atom().
-type rules() :: [rule()].
-type rule() :: {action(), rule_conditions()}.
-type rule_conditions() :: [rule_condition()].
-type rule_condition() :: cmdline_opt_assertion()
                        | {cmdline_opt(), rule_pred(), true_part()}
                        | {cmdline_opt(), rule_pred(), true_part(), false_part()}.
-type rule_pred() :: present
                   | absent
                   | {value, any()}
                   | {'FAIL', Msg :: string()}
                   | func_pred().
-type func_pred() :: fun((any()) -> boolean()).
-type true_part() :: cmdline_opt_assertions().
-type false_part() :: cmdline_opt_assertions().
-type cmdline_opt_assertions() :: [cmdline_opt_assertion()].
-type cmdline_opt_assertion() :: {cmdline_opt(), rule_assertion()}.
-type rule_assertion() :: required
                        | forbidden
                        | {value, any()}
                        | func_pred()
                        | {'FAIL', Msg :: string()}
                        | {rule_pred(), true_part()}
                        | {rule_pred(), true_part(), false_part()}.


%%--------------------------------------------------------------------
walk_rules(Rules, Config) when is_list(Rules) ->
    ?trace("Rules: ~p", [Rules]),
    lists:foreach(fun(Rule) ->
                          ?trace("Rule: ~p", [Rule]),
                          rule_condition(Rule, Config)
                  end, Rules).

%%--------------------------------------------------------------------
rule_condition({Opt, Assertion}, Config) ->
    cmdline_opt_assertion(Opt, Assertion, Config);
rule_condition({Opt, Pred, IfTrue}, Config) ->
    rule_condition(Opt, {Pred, IfTrue, []}, Config);
rule_condition({Opt, Pred, IfTrue, IfFalse}, Config) ->
    ?trace("{~p, ~p, ~p, ~p}", [Opt, Pred, IfTrue, IfFalse]),
    rule_condition(Opt, {Pred, IfTrue, IfFalse}, Config).

%%--------------------------------------------------------------------
-spec rule_condition(Opt, RuleCondition, Config) -> ok when
      Opt :: cmdline_opt(), RuleCondition :: {Pred, IfTrue, IfFalse},
      Pred :: rule_pred(), IfTrue :: true_part(), IfFalse :: false_part(),
      Config :: list().
rule_condition(Opt, {Pred, IfTrue, IfFalse}=T, Config) ->
    ?trace("~p, ~p", [Opt, T]),
    Assertions = case rule_pred(Pred, Opt, Config) of
                     true  ->
                         ?trace("~p rule_pred was ~p", [Opt, true]),
                         IfTrue;
                     false ->
                         ?trace("~p rule_pred was ~p", [Opt, false]),
                         IfFalse
                 end,
    cmdline_opt_assertions(Assertions, Config).

%%--------------------------------------------------------------------
rule_pred(present, Opt, Config) ->
    ?trace("present, ~p", [Opt]),
    check_prop(fun is_present/1, Opt, Config);
rule_pred(absent, Opt, Config) ->
    ?trace("absent, ~p", [Opt]),
    check_prop(fun is_absent/1, Opt, Config);
rule_pred({value, Value}, Opt, Config) ->
    ?trace("{value, ~p}, ~p", [Value, Opt]),
    check_prop(is_equal_fun({Value, []}), Opt, Config);
rule_pred({'FAIL', Msg}, Opt, _Config) ->
    ?trace("{'FAIL', ~p}, ~p", [Msg, Opt]),
    erlang:error({rule_failed, Msg, for_opt, Opt});
rule_pred(Pred, Opt, Config) when is_function(Pred, 1) ->
    ?trace("Pred ~p, ~p", [Pred, Opt]),
    Pred(sc_util:val(Opt, Config));
rule_pred(Pred, Opt, _Config) ->
    erlang:error({unknown_rule_predicate, Pred, for_opt, Opt}).

%%--------------------------------------------------------------------
cmdline_opt_assertions(Assertions, Config) ->
    lists:foldl(fun({Opt, RuleAssertion}=_Cond, _Acc) ->
                        ?trace("~p", [_Cond]),
                        cmdline_opt_assertion(Opt, RuleAssertion, Config);
                   ({Opt, _Pred, _IfTrue}=Cond, _Acc) ->
                        ?trace("~p", [Cond]),
                        cmdline_opt_assertion(Opt, Cond, Config);
                   ({Opt, _Pred, _IfTrue, _IfFalse}=Cond, _Acc) ->
                        ?trace("~p", [Cond]),
                        cmdline_opt_assertion(Opt, Cond, Config)
                end, true, Assertions).

%%--------------------------------------------------------------------
cmdline_opt_assertion(Opt, {Opt, Pred, IfTrue}, Config) ->
    cmdline_opt_assertion(Opt, {Opt, Pred, IfTrue, []}, Config);
cmdline_opt_assertion(Opt, {Opt, Pred, IfTrue, IfFalse}=_Rule, Config) ->
    ?trace("assertion for ~p is rule: ~p", [Opt, _Rule]),
    rule_condition({Opt, Pred, IfTrue, IfFalse}, Config);
cmdline_opt_assertion(Opt, required, Config) ->
    ?trace("required, ~p", [Opt]),
    assert_is_present(Opt, Config);
cmdline_opt_assertion(Opt, forbidden, Config) ->
    ?trace("forbidden, ~p", [Opt]),
    assert_is_absent(Opt, Config);
cmdline_opt_assertion(Opt, {value, Value}, Config) ->
    ?trace("~p, ~p", [{value, Value}, Opt]),
    assert_is_equal(Opt, Value, Config);
cmdline_opt_assertion(Opt, {'FAIL', Msg}, _Config) ->
    ?trace("~p, ~p", [{'FAIL', Msg}, Opt]),
    erlang:error({failed_rule, Msg, for_opt, Opt});
cmdline_opt_assertion(Opt, Pred, Config) when is_function(Pred, 1) ->
    ?trace("Pred ~p, ~p", [Pred, Opt]),
    assert_prop(Pred, Opt, Config);
cmdline_opt_assertion(Opt, {RulePred, IfTrue}, Config) ->
    ?trace("RulePred ~p, IfTrue ~p, ~p", [RulePred, IfTrue, Opt]),
    rule_condition(Opt, {RulePred, IfTrue, []}, Config);
cmdline_opt_assertion(Opt, {_RulePred, _IfTrue, _IfFalse}=Cond, Config) ->
    ?trace("RulePred ~p, IfTrue ~p, IfFalse ~p, ~p",
           [_RulePred, _IfTrue, _IfFalse, Opt]),
    rule_condition(Opt, Cond, Config);
cmdline_opt_assertion(Opt, Cond, _Config) ->
    erlang:error({unknown_opt_assertion, {Opt, Cond}}).

%%--------------------------------------------------------------------
is_present(V) ->
    IsPresent = (V =/= undefined andalso V =/= []),
    ?trace("~p ~s present", [V, either(IsPresent, "is", "is not")]),
    IsPresent.

%%--------------------------------------------------------------------
is_absent(V) ->
    not is_present(V).

%%--------------------------------------------------------------------
assert_is_present(Opt, Config) ->
    ?trace("Opt: ~p", [Opt]),
    assert_prop(fun is_present/1, Opt, Config).

%%--------------------------------------------------------------------
assert_is_absent(Opt, Config) ->
    ?trace("Opt: ~p", [Opt]),
    assert_prop(fun is_absent/1, Opt, Config).

%%--------------------------------------------------------------------
assert_is_equal(Opt, ExpectedValue, Config) ->
    ?trace("Opt: ~p, Expected: ~p", [Opt, ExpectedValue]),
    assert_prop(is_equal_fun({ExpectedValue, []}), Opt, Config).

%%--------------------------------------------------------------------
-spec rules() -> rules().
rules() ->
    [
     %% Connect rules
     {action_connect,

      [{no_ssl, {value, false},
        %% no_ssl is false (i.e. SSL required)
        [{apns_auth, absent,
            [{apns_cert, required},
             {apns_key, required}]}
        ]
       }
      ]
     },

     %% Send rules
     {action_send,

      [{message, present,
        %% message present
        [{no_check_json, {value, false}},
         {no_json, {value, false}},
         {raw_json, forbidden}],
        %% message absent
        [{raw_json, present,
          % raw_json present
          [{no_json, {value, false}}],
          % raw_json absent
          [{'FAIL', "message or raw-json required"}]
         }
        ]
       },


       {no_ssl, {value, true},
        %% SSL is not being used
        [{apns_auth, required},
         {apns_issuer, required},
         {apns_kid, required},
         {apns_token, required},
         {apns_topic, required}],
        %% SSL is being used
        [{apns_auth, present,
          %% apns_auth has been provided, but this
          %% is only supported for v3 upwards
          [{apns_version, fun(V) -> is_integer_range(V, 3, ?MAX_APNS_VER) end},
           {apns_issuer, required},
           {apns_kid, required},
           {apns_token, required},
           {apns_topic, required},
           {apns_cert, forbidden},
           {apns_key, forbidden}
          ],
          %% apns_auth has not been provided
          [{apns_cert, required},
           {apns_key, required},
           {apns_token, required},
           {apns_issuer, forbidden},
           {apns_kid, forbidden}
          ]
         }
        ]
       }
      ]
     },

     %% Showcert rules
     {action_showcert,
      [{apns_cert, required}]
     },

     %% Help rules
     {action_help, []},

     %% Version rules
     {action_version, []}
    ].

%%--------------------------------------------------------------------
either(true,  IfTrue, _IfFalse) -> IfTrue;
either(false, _IfTrue, IfFalse) -> IfFalse.

%%--------------------------------------------------------------------
set_debug(K, AptestCfg) when K =:= verbose; K =:= trace ->
    IsSet = (sc_util:val(K, AptestCfg, false) =:= true),
    put(K, IsSet),
    K =:= trace andalso IsSet andalso put(verbose, IsSet).

%%--------------------------------------------------------------------
set_log_level(AptestCfg) ->
    lists:foreach(fun(K) -> set_debug(K, AptestCfg) end, [verbose, trace]).


% ex: set ft=erlang fenc=utf-8 sts=4 ts=4 sw=4 et:
