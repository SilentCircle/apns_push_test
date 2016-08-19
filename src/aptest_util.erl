-module(aptest_util).

-export([
        copy_props/2,
        do_rpc/4,
        do_rpc/5,
        err_msg/2,
        err_msg/3,
        get_cert_info/1,
        hexdump/1,
        map_prop/2,
        msg/2,
        msg/3,
        ping_until_timeout/3,
        prop/2,
        prop/3,
        req_prop/2,
        set_dist_ports/2,
        start_distributed/1,
        start_distributed/2,
        start_network/2,
        timestamp_ms/0,
        wait_for_node/1,
        wait_for_node/2,
        wait_for_node/3
        ]).

%% Internal exports
-export([
          default_callback/0
        , decode_ext/1
        ]).

-include_lib("public_key/include/public_key.hrl").

-define(RPC_TIMEOUT, 60000).
-define(is_digit(X), ($0 =< X andalso X =< $9)).
-define(ASN1_NULL_BIN, <<5, 0>>).

%%--------------------------------------------------------------------
set_dist_ports(Min, Max) when is_integer(Min),
                              is_integer(Max),
                              Min >= 1024,
                              Max >= Min ->
	application:set_env(kernel, inet_dist_listen_min, Min),
	application:set_env(kernel, inet_dist_listen_max, Max).

%%--------------------------------------------------------------------
start_network(Node, Cookie) ->
    start_distributed(Node),
    erlang:set_cookie(Node, Cookie).

%%--------------------------------------------------------------------
start_distributed(Node) ->
    start_distributed(Node, longnames).

%%--------------------------------------------------------------------
start_distributed(Node, NameType) when NameType == shortnames;
                                       NameType == longnames ->
    case net_kernel:start([Node, NameType]) of
        {ok, _Pid} ->
            ok;
        {error, {{already_started, _Pid}, _}} ->
            ok;
        {error, Reason} ->
            throw(Reason)
    end.

%%--------------------------------------------------------------------
default_callback() ->
    fun(Node_, Act_) ->
            msg("~s ~p~n", [Act_, Node_])
    end.

%%--------------------------------------------------------------------
wait_for_node(Node) ->
    wait_for_node(Node, 30000).

%%--------------------------------------------------------------------
wait_for_node(Node, TimeoutMs) ->
    wait_for_node(Node, TimeoutMs, default_callback()).

%%--------------------------------------------------------------------
wait_for_node(Node, TimeoutMs, Callback) when is_function(Callback, 2) ->
    Ref = erlang:send_after(TimeoutMs, self(), timeout),
    ping_until_timeout(Node, Ref, Callback).

%%--------------------------------------------------------------------
ping_until_timeout(Node, Ref, Callback) when is_function(Callback, 2) ->
    Callback(Node, "Pinging"),
    case net_adm:ping(Node) of
        pong ->
            _ = erlang:cancel_timer(Ref),
            receive after 0 -> ok end, % Flush queue
            Callback(Node, "Connected to");
        pang ->
            Callback(Node, "Ping failed to"),
            receive
                timeout ->
                    Callback(Node, timeout),
                    throw({ping_timeout, Node})
            after
                1000 ->
                    ping_until_timeout(Node, Ref, Callback)
            end
    end.

%%--------------------------------------------------------------------
hexdump(<<B/binary>>) ->
    hexdump_line(B, 16, 0).

%%--------------------------------------------------------------------
%%% Perform an RPC call and throw on error
%%%--------------------------------------------------------------------
do_rpc(Node, M, F, A) ->
    do_rpc(Node, M, F, A, ?RPC_TIMEOUT).

%%--------------------------------------------------------------------
do_rpc(Node, M, F, A, Timeout) ->
    try rpc:call(Node, M, F, A, Timeout) of
        {badrpc, Reason} ->
            throw({rpcerror, {Reason, {Node, M, F, A}}});
        Result ->
            Result
        catch _:Why ->
            throw(Why)
    end.

%%--------------------------------------------------------------------
err_msg(Fmt, Args) ->
    err_msg(Fmt, Args, with_ts).

err_msg(Fmt, Args, with_ts) ->
    {TsFmt, TsArgs} = add_ts(Fmt, Args),
    err_msg(TsFmt, TsArgs, no_ts);
err_msg(Fmt, Args, no_ts) ->
    io:format(standard_error, Fmt, Args).

%%--------------------------------------------------------------------
msg(Fmt, Args) ->
    msg(Fmt, Args, with_ts).

msg(Fmt, Args, with_ts) ->
    {TsFmt, TsArgs} = add_ts(Fmt, Args),
    msg(TsFmt, TsArgs, no_ts);
msg(Fmt, Args, no_ts) ->
    io:format(Fmt, Args).

%%--------------------------------------------------------------------
timestamp_ms() ->
    erlang:system_time(micro_seconds) div 1000.

%%--------------------------------------------------------------------
copy_props(Keys, FromPL) ->
    [req_prop(K, FromPL) || K <- Keys].

%%--------------------------------------------------------------------
map_prop(Fun, {K, V}) when is_function(Fun, 1) ->
    {K, Fun(V)}.

%%--------------------------------------------------------------------
req_prop(K, PL) ->
    case lists:keysearch(K, 1, PL) of
        {value, KV} ->
            KV;
        false ->
            throw({missing_required_key, K})
    end.

%%--------------------------------------------------------------------
prop(K, PL) ->
    prop(K, PL, undefined).

%%--------------------------------------------------------------------
prop(K, PL, Default) ->
    case lists:keysearch(K, 1, PL) of
        {value, KV} ->
            KV;
        false ->
            Default
    end.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------
hexdump_line(<<>>, _Len, _Offs) ->
    ok;
hexdump_line(<<B/binary>>, Len, Offs) when byte_size(B) =< Len ->
    io:put_chars([hex_offset(Offs, 8), $:, $\s,
                  << <<(xdigit(U)), (xdigit(L)), $\s>>
                  || <<U:4, L:4>> <= B >>,
                  pad(B, Len), $\s, $\s, char_rep(B), $\n]);
hexdump_line(<<B/binary>>, Len, Offs) ->
    <<B1:Len/binary, Rest/binary>> = B,
    hexdump_line(B1, Len, Offs),
    hexdump_line(Rest, Len, Offs + Len).

%%--------------------------------------------------------------------
hex_offset(Int, Pad) ->
    io_lib:format("~*.16.0b", [Pad, Int]).

%%--------------------------------------------------------------------
pad(<<B/binary>>, Len) when byte_size(B) >= Len ->
    <<>>;
pad(<<B/binary>>, Len) ->
    lists:duplicate((Len - byte_size(B)) * 3, $\s).

%%--------------------------------------------------------------------
char_rep(<<B/binary>>) ->
    [char_rep(Ch) || <<Ch>> <= B];
char_rep(Ch) when Ch >= $\s, Ch =< 127 ->
    Ch;
char_rep(_) ->
    $.
    .

%%--------------------------------------------------------------------
xdigit(N) when N >= 0, N =< 9 ->
    $0 + N;
xdigit(N) when N >= 16#a, N =< 16#f ->
    $a - 10 + N;
xdigit(N) ->
    throw({invalid_nybble, N}).

%%--------------------------------------------------------------------
add_ts(Fmt, Args) ->
    {"[~s] " ++ Fmt, [iso8601_ts() | Args]}.

%%--------------------------------------------------------------------
iso8601_ts() ->
    Now = os:timestamp(),
    Micros = element(3, Now),
    {{Yr, Mo, Dy}, {H, M, S}} = calendar:now_to_universal_time(Now),
    io_lib:format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B.~6..0BZ",
                  [Yr, Mo, Dy, H, M, S, Micros]).


%%--------------------------------------------------------------------
%% @doc Extract interesting APNS-related info from cert.
%% @end
%%--------------------------------------------------------------------
-ifndef('id-userid').
-define('id-userid', {0,9,2342,19200300,100,1,1}).
-endif.

-define('id-apns-development', {1,2,840,113635,100,6,3,1}).
-define('id-apns-production',  {1,2,840,113635,100,6,3,2}).
-define('id-apns-bundle-id',   {1,2,840,113635,100,6,3,3}).
-define('id-apns-bundle-info', {1,2,840,113635,100,6,3,4}).


now_to_gregorian_seconds(Now) ->
    calendar:datetime_to_gregorian_seconds(calendar:now_to_datetime(Now)).

cert_is_expired(DateTime) ->
    GSNow = now_to_gregorian_seconds(os:timestamp()),
    GSCert = calendar:datetime_to_gregorian_seconds(DateTime),
    GSNow >= GSCert.

%%--------------------------------------------------------------------
-spec get_cert_info(CertData) -> CertInfo when
      CertData :: binary(), CertInfo :: map().
get_cert_info(<<CertData/binary>>) ->
    #'OTPCertificate'{tbsCertificate = R} = decode_cert(CertData),

    %% Serial
    SerialNumber = R#'OTPTBSCertificate'.serialNumber,

    %% Subject
    SubjAttrs = [
                 {?'id-at-commonName',              subject_cn},
                 {?'id-userid',                     subject_uid},
                 {?'id-at-organizationName',        subject_o},
                 {?'id-at-organizationalUnitName',  subject_ou},
                 {?'id-at-localityName',            subject_l},
                 {?'id-at-stateOrProvinceName',     subject_st},
                 {?'id-at-countryName',             subject_c}
                ],
    {rdnSequence, SubjectRdnSeq} = R#'OTPTBSCertificate'.subject,

    %% Issuer
    IssuerAttrs = [
                   {?'id-at-commonName',              issuer_cn},
                   {?'id-at-organizationName',        issuer_o},
                   {?'id-at-organizationalUnitName',  issuer_ou},
                   {?'id-at-stateOrProvinceName',     issuer_st},
                   {?'id-at-localityName',            issuer_l},
                   {?'id-at-countryName',             issuer_c}
                  ],
    {rdnSequence, IssuerRdnSeq} = R#'OTPTBSCertificate'.issuer,

    %% Extensions
    ExtAttrs = [
                {?'id-apns-development', is_development},
                {?'id-apns-production',  is_production},
                {?'id-apns-bundle-id',   bundle_id},
                {?'id-apns-bundle-info', bundle_info}
               ],
    Extensions = R#'OTPTBSCertificate'.extensions,

    Validity = R#'OTPTBSCertificate'.validity,
    NotBefore = format_time(Validity#'Validity'.notBefore),
    NotAfter = format_time(Validity#'Validity'.notAfter),

    Expired = cert_is_expired(parse_time(Validity#'Validity'.notAfter)),
    ExpMsg = case Expired of
                 true ->
                     "*** THIS CERTIFICATE IS EXPIRED! ***";
                 false ->
                     "Unexpired"
             end,

    maps:from_list(
      [
       {expiry_status, ExpMsg},
       {serial_number, SerialNumber},
       {not_before, NotBefore},
       {not_after, NotAfter}
      ] ++
      extract_attrs(SubjAttrs, SubjectRdnSeq) ++
      extract_attrs(IssuerAttrs, IssuerRdnSeq) ++
      extract_exts(ExtAttrs, Extensions)
     ).


%%--------------------------------------------------------------------
-spec extract_attrs(Attrs, AttrVals) -> Result when
      Attrs :: [{Id, Name}], AttrVals :: [[#'AttributeTypeAndValue'{}]],
      Id :: tuple(), Name :: atom(),
      Result :: [{atom(), binary() | undefined}].
extract_attrs(Attrs, AttrVals) ->
    Decode = fun(Val) ->
                     Res = maybe_decode_val('DirectoryString', Val),
                     decode_special_string(Res)
             end,
    [{Name, select_attr(Id, AttrVals, Decode)} || {Id, Name} <- Attrs].

%%--------------------------------------------------------------------
-spec extract_exts(Exts, ExtVals) -> Result when
      Exts :: [{Id, Name}], Id :: tuple(), Name :: atom(),
      ExtVals :: asn1_NOVALUE | [[#'AttributeTypeAndValue'{}]],
      Result :: [{atom(), binary() | undefined}].
extract_exts(_Exts, asn1_NOVALUE) ->
    [];
extract_exts(Exts, ExtVals) ->
    [{Name, select_ext(Id, ExtVals, fun decode_ext/1)} || {Id, Name} <- Exts].

%%--------------------------------------------------------------------
-spec select_attr(AttrType, AttrVals, Decode) -> Result when
      AttrType :: tuple(), AttrVals :: [[#'AttributeTypeAndValue'{}]],
      Decode :: fun((special_string() | binary()) -> binary()),
      Result :: binary() | undefined.
select_attr(AttrType, AttrVals, Decode) when is_function(Decode, 1) ->
    L = [Decode(AttrVal) ||
         [#'AttributeTypeAndValue'{type = T, value = AttrVal}] <- AttrVals,
         T =:= AttrType],
    case L of
        [Val|_] -> Val;
        _       -> undefined
    end.

%%--------------------------------------------------------------------
-spec select_ext(ExtID, ExtVals, Decode) -> Result when
      ExtID :: tuple(), ExtVals :: asn1_NOVALUE | [#'Extension'{}],
      Decode :: fun((special_string() | binary()) -> binary()),
      Result :: term() | undefined.
select_ext(_ExtID, asn1_NOVALUE, _Decode) ->
    undefined;
select_ext(ExtID, ExtVals, Decode) when is_function(Decode, 1) ->
    L = [Decode(E#'Extension'.extnValue) || #'Extension'{} = E <- ExtVals,
                                            E#'Extension'.extnID =:= ExtID],
    case L of
        [Val|_] -> Val;
        _       -> undefined
    end.

%%--------------------------------------------------------------------
-type bin_or_string() :: binary() | string().
-type special_string() ::
    {teletexString, bin_or_string()} | {printableString, bin_or_string()} |
    {universalString, bin_or_string()} | {utf8String, bin_or_string()} |
    {bmpString, bin_or_string()}.

%%--------------------------------------------------------------------
decode_ext(?ASN1_NULL_BIN) ->
    true; % ASN.1 NULL value, but this is present, so true is good enough.
decode_ext(Val) ->
    Res = maybe_decode_val('DirectoryString', Val),
    decode_special_string(Res).

%%--------------------------------------------------------------------
decode_special_string({T, S}) when T =:= utf8String orelse
                                   T =:= printableString orelse
                                   T =:= teletexString orelse
                                   T =:= universalString orelse
                                   T =:= bmpString ->
    S;
decode_special_string(X) ->
    X.

%%--------------------------------------------------------------------
-spec maybe_decode_val(Type, Val) -> Result when
      Type :: atom(), Val :: term(), Result :: special_string() | undefined.
maybe_decode_val(Type, <<_Tag, _Length, _Value/binary>> = Tlv) ->
    {ok, SpecialString} = 'OTP-PUB-KEY':decode(Type, Tlv),
    maybe_decode_val(undefined, SpecialString);
maybe_decode_val(_Type, {SpecialStringType, V}) ->
    {SpecialStringType, iolist_to_binary(V)}; % Already decoded
maybe_decode_val(_Type, S) when is_list(S) ->
    S;
maybe_decode_val(_Type, _Unknown) ->
    undefined.

%%--------------------------------------------------------------------
decode_cert(CertData) ->
    {PemOk, OTPCertRec} = try
        [R] = apns_cert:pem_decode_certs(CertData),
        {true, #'OTPCertificate'{} = R}
    catch _:_ ->
        {false, undefined}
    end,

    case PemOk of
        true ->
            OTPCertRec;
        false ->
            apns_cert:der_decode_cert(CertData)
    end.

%%--------------------------------------------------------------------
month(1)  -> "Jan";
month(2)  -> "Feb";
month(3)  -> "Mar";
month(4)  -> "Apr";
month(5)  -> "May";
month(6)  -> "Jun";
month(7)  -> "Jul";
month(8)  -> "Aug";
month(9)  -> "Sep";
month(10) -> "Oct";
month(11) -> "Nov";
month(12) -> "Dec".


%%--------------------------------------------------------------------
%% 4.1.2.5.1.  UTCTime
%%
%%    ...
%%
%%    For the purposes of this profile, UTCTime values MUST be expressed in
%%    Greenwich Mean Time (Zulu) and MUST include seconds (i.e., times are
%%    YYMMDDHHMMSSZ), even where the number of seconds is zero.  Conforming
%%    systems MUST interpret the year field (YY) as follows:
%%
%%       Where YY is greater than or equal to 50, the year SHALL be
%%       interpreted as 19YY; and
%%
%%       Where YY is less than 50, the year SHALL be interpreted as 20YY.
%%--------------------------------------------------------------------

-type asn1_time_type() :: utcTime | generalTime.

-spec format_time({asn1_time_type(), string()}) -> string().
format_time({utcTime, [Y1, Y2|_] = UTCTime}) when length(UTCTime) == 13 ->
    format_time({generalTime, utctime_century(Y1, Y2) ++ UTCTime});
format_time({generalTime, [Y1, Y2, Y3, Y4, M1, M2, D1, D2,
                           H1, H2, Mn1, Mn2, S1, S2, $Z]}) ->
    Month = month(dd_to_int(M1, M2)),
    Month ++ [$\s, D1, D2, $\s, H1, H2, $:, Mn1, Mn2, $:, S1, S2,
              $\s, Y1, Y2, Y3, Y4] ++ " GMT".

-type digit() :: 16#30 .. 16#39.
-spec utctime_century(digit(), digit()) -> string().
utctime_century(Y1, Y2) ->
    case dd_to_int(Y1, Y2) >= 50 of
        true  -> "19";
        false -> "20"
    end.

-spec parse_time({asn1_time_type(), string()}) -> calendar:datetime().
parse_time({utcTime, [Y1, Y2|_] = UTCTime}) when length(UTCTime) == 13 ->
    parse_time({generalTime, utctime_century(Y1, Y2) ++ UTCTime});
parse_time({generalTime, [Y1, Y2, Y3, Y4, M1, M2, D1, D2,
                          H1, H2, Mn1, Mn2, S1, S2, $Z]}) ->
    Date = {dddd_to_int(Y1, Y2, Y3, Y4), dd_to_int(M1, M2), dd_to_int(D1, D2)},
    Time = {dd_to_int(H1, H2), dd_to_int(Mn1, Mn2), dd_to_int(S1, S2)},
    {Date, Time}.

%%--------------------------------------------------------------------
dddd_to_int(A, B, C, D) ->
    d_to_int(A) * 1000 +
    d_to_int(B) * 100 +
    dd_to_int(C, D).

%%--------------------------------------------------------------------
dd_to_int($0, B) ->
    d_to_int(B);
dd_to_int(A, B) when ?is_digit(A) andalso ?is_digit(B) ->
    d_to_int(A) * 10 + d_to_int(B).

%%--------------------------------------------------------------------
d_to_int(A) when ?is_digit(A) ->
    A - $0.

-compile({inline, [{dddd_to_int, 4},
                   {dd_to_int, 2},
                   {d_to_int, 1}]}).

% ex: set ft=erlang fenc=utf-8 sts=4 ts=4 sw=4 et:
