-ifndef(aptest_hrl_5121dfaff01d4cd38b6445f308bca6d2).
-define(aptest_hrl_5121dfaff01d4cd38b6445f308bca6d2, true).

-define(MIN_APNS_VER, 2).
-define(MAX_APNS_VER, 3).
-define(MAX_APNS_BADGE, 16#7FFFFFFF). % Signed 32 bits,could maybe be 64 bits?

-define(trace(Fmt, Msg),
        _ = begin
                get(trace) =:= true andalso
                (fun({_,{M, F, A}}) ->
                         io:format(standard_error,
                                   "~s\n"
                                   "[~p:~p/~B](~B)::\n   " ++ Fmt ++ "\n",
                                   ["=== TRACE ===",
                                    M, F, A, ?LINE | Msg]),
                         true
                 end)(erlang:process_info(self(), current_function))
            end).
-endif.
