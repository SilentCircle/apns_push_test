# Summary

This is a simple APNS push token tester. It supports APNS v2 ("enhanced" binary API) and v3 (`HTTP/2`).

You will require the push certificate and the unencrypted push key in PEM format, as well as a valid push token.
You also need outbound access on port 443 (for `HTTP/2`) or 2195 to Apple's 17.0.0.0 IPv4 address range.

# Building

* Building requires Erlang 18 and `rebar3`.
* `rebar3` is automatically downloaded if not present.
* It has only been built and tested on Debian Jessie.
* It is not guaranteed to build or work on other platforms, although it probably will if Erlang 18 is installed.

```
git clone https://github.com/SilentCircle/apns_push_test
cd apns_push_test
make
```

# Usage

    Usage: aptest [--send] [-c <apns_cert>] [-e [<apns_env>]] [-k <apns_key>]
                  [-p [<apns_port>]] [-t <apns_token>] [-v [<apns_version>]]
                  [-b [<badge>]] [-h] [-m <message>] [-r [<raw_json>]]
                  [-s [<sound>]] [-V [<verbose>]]

      --send              Send notification
      -c, --apns-cert     APNS certificate file
      -e, --apns-env      APNS environment (prod|dev) [default: prod]
      -k, --apns-key      APNS private key file
      -p, --apns-port     APNS port [default: 2197]
      -t, --apns-token    APNS hexadecimal token
      -v, --apns-version  APNS protocol version [default: 2]
      -b, --badge         APNS badge count [-1: unchanged] [default: -1]
      -h, --help          Show help
      -m, --message       APNS alert text
      -r, --raw-json      Raw APNS JSON notification [default: ]
      -s, --sound         APNS sound file name                [default: ]
      -V, --verbose       Verbose output [default: false]

---

# Running

## APNS v2

    ./aptest -t 843f************************************************4860aafb7362 \
             -c com.example.cert.pem \
             -k com.example.key.pem \
             -m 'Testing 123' \
             --apns-version=2 \
             --badge=123
    [2016-06-23T22:36:13.253554Z] Connecting over TLS to gateway.push.apple.com:2195
    [2016-06-23T22:36:14.240639Z] Connected.
    [2016-06-23T22:36:14.263168Z] Packet decode check:

    Command version: v2
    Notification ID: 1
    Expiry         : 4294967295
    Token          : 843f************************************************4860aafb7362
    Payload        : {"aps":{"alert":"Testing 123","content-available":1,"badge":123}}
    Priority       : 10
    Rest           : <<>>

    [2016-06-23T22:36:14.274531Z] Sending APNS v2 packet:
    00000000: 02 00 00 00 79 01 00 20 84 3f ** ** ** ** ** **   ....y.. .?...&..
    00000010: ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** **   ..X../a.....m..3
    00000020: ** ** 48 60 aa fb 73 62 02 00 41 7b 22 61 70 73   (.H`..sb..A{"aps
    00000030: 22 3a 7b 22 61 6c 65 72 74 22 3a 22 54 65 73 74   ":{"alert":"Test
    00000040: 69 6e 67 20 31 32 33 22 2c 22 63 6f 6e 74 65 6e   ing 123","conten
    00000050: 74 2d 61 76 61 69 6c 61 62 6c 65 22 3a 31 2c 22   t-available":1,"
    00000060: 62 61 64 67 65 22 3a 31 32 33 7d 7d 03 00 04 00   badge":123}}....
    00000070: 00 00 01 04 00 04 ff ff ff ff 05 00 01 0a         ..............
    [2016-06-23T22:36:14.274947Z] Waiting for error response.
    [2016-06-23T22:36:15.390155Z] Pushed without receiving APNS error!


---

## APNS v3

    ./aptest -t 843f************************************************4860aafb7362 \
             -c com.example.cert.pem \
             -k com.example.key.pem \
             -m 'Testing 123' \
             --apns-version=3 \
             --badge=123
    [2016-06-23T22:35:28.113332Z] Connecting with HTTP/2 to api.push.apple.com:443
    [2016-06-23T22:35:28.864767Z] Connected.
    [2016-06-23T22:35:28.864951Z] Sending synchronous request:
    Headers: [{<<":method">>,<<"POST">>},
              {<<":path">>,
               <<"/3/device/843f************************************************4860aafb7362">>},
              {<<":scheme">>,<<"https">>},
              {<<"apns-id">>,<<"19499bf9-e634-4ba1-bb41-67ab708dedd0">>},
              {<<"apns-topic">>,<<"com.example.AppId">>}]
    Body: <<"{\"aps\":{\"alert\":\"Testing 123\",\"content-available\":1,\"badge\":123}}">>
    [2016-06-23T22:35:29.027213Z] Response time: 146075 microseconds
    Response headers: [{<<":status">>,<<"200">>},
                       {<<"apns-id">>,<<"19499bf9-e634-4ba1-bb41-67ab708dedd0">>}]
    Response body: undefined
    [2016-06-23T22:35:29.027484Z] Pushed without receiving APNS error!

---

# Issues

* The `--apns-port` option is currently ignored. Ports are chosen based on which APNS version is being used (v2: 2195; v3: 443).
* It has not been tested with `--raw-json`.
* It needs to be run through dialyzer.

# Other information

## APNS version 2

* Apple Production push FQDN used: `gateway.push.apple.com:2195`
* Apple Development push FQDN used: `gateway.sandbox.push.apple.com:2195`

## APNS Version 3

* Apple Production push FQDN used: `api.push.apple.com:443`
* Apple Development push FQDN used: `api.development.push.apple.com:443`

