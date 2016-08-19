%%%-------------------------------------------------------------------
%%% @author Edwin Fine
%%% @copyright (C) 2016, Silent Circle LLC
%%% @doc escript driver for aptest_main.
%%% @end
%%%-------------------------------------------------------------------
-module(aptest).

-spec main(Args) -> no_return() when Args :: [string()].
main(Args) ->
    PgmName = filename:basename(escript:script_name()),
    aptest_main:exec(PgmName, Args).

% ex: set ft=erlang fenc=utf-8 sts=4 ts=4 sw=4 et:
