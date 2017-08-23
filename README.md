# Summary

This is a fairly simple APNS push token tester.

It supports

- APNS v3 (newer `HTTP/2` API).
- APNS v2 ("enhanced" binary API - DEPRECATED)

The APNS v2 support will be removed at some point in the future.

Users of this tool will require the following:

- If using a push certificate, the push certificate and the corresponding
  unencrypted key in PEM format.

- If using token-based authentication, the authentication private key file as
  provided by Apple, the issuer ID (your Team ID), and the key id (`kid`).  The
  `topic` is the app id, e.g. `com.example.MyApp`.

- A valid push token for the environment (sandbox or production), corresponding
  to the app id/topic.


# Building

* Building requires Erlang 18 or 19 and `rebar3`. It will not build on Erlang
  20 until some further investigation is done.
* `rebar3` is automatically downloaded if not present.
* It has only been built and tested on Debian Jessie and Stretch.
* It is not guaranteed to build or work on other platforms, although it
  probably will if Erlang 18 or 19 is installed.

```
git clone https://github.com/SilentCircle/apns_push_test
cd apns_push_test
make
cp _build/default/aptest $BIN_DIR/
```

# Usage

```
Usage: aptest [-h] [--connect] [--send] [--showcert] [--version]
              [-a [<apns_auth>]] [-c [<apns_cert>]] [-A [<apns_ca_cert>]]
              [-e [<apns_env>]] [-x [<apns_expiration>]]
              [-k [<apns_key>]] [-H [<apns_host>]] [-i [<apns_id>]]
              [-I [<apns_issuer>]] [-K [<apns_kid>]] [-p [<apns_port>]]
              [-P [<apns_priority>]] [-t [<apns_token>]]
              [-T [<apns_topic>]] [-v [<apns_version>]] [-b [<badge>]]
              [-m [<message>]] [-n [<no_check_json>]] [-N [<no_json>]]
              [-S [<no_ssl>]] [-r [<raw_json>]] [-L [<relaxed>]]
              [-s [<sound>]] [--trace [<trace>]] [-V [<verbose>]]

  -h, --help             Show help
  --connect              Test connection to APNS
  --send                 Send notification
  --showcert             Show certificate information
  --version              Show aptest version
  -a, --apns-auth        APNS token-based auth private key file [default: ]
  -c, --apns-cert        APNS TLS certificate file [default: ]
  -A, --apns-ca-cert     APNS CA chain certificate file [default: ]
  -e, --apns-env         APNS environment (prod|dev) [default: prod]
  -x, --apns-expiration  APNS expiration time (optional) [default: -1]
  -k, --apns-key         APNS TLS certificate private key file [default: ]
  -H, --apns-host        APNS host (optional) [default: ]
  -i, --apns-id          APNS uuid (optional) [default: ]
  -I, --apns-issuer      APNS JWT `iss` (for apns-auth) [default: ]
  -K, --apns-kid         APNS JWT `kid` (for apns-auth) [default: ]
  -p, --apns-port        APNS port (optional) [default: -1]
  -P, --apns-priority    APNS priority (optional) [default: -1]
  -t, --apns-token       APNS hexadecimal token [default: ]
  -T, --apns-topic       APNS topic (required for apns-auth) [default: ]
  -v, --apns-version     APNS protocol version [default: 3]
  -b, --badge            APNS badge count [-1: unchanged] [default: -1]
  -m, --message          APNS alert text [default: ]
  -n, --no-check-json    Allow invalid raw JSON [default: false]
  -N, --no-json          Omit the APNS payload [default: false]
  -S, --no-ssl           Use HTTP without SSL for debugging [default:
                         false]
  -r, --raw-json         Raw APNS JSON notification [default: ]
  -L, --relaxed-mode     Allow some invalid notification data [default:
                         false]
  -s, --sound            APNS sound file name [default: ]
  --trace                Trace output (implies verbose) [default: false]
  -V, --verbose          Verbose output [default: false]
```

---

# Running

## APNS v3

### Using push certificate

    ./aptest -t 843f************************************************4860aafb7362 \
             -c com.example.cert.pem \
             -k com.example.key.pem \
             -m 'Testing 123' \
             --apns-version=3 \
             --badge=123
    [2016-06-23T22:35:28.113332Z] Connecting with HTTP/2 to api.push.apple.com:443
    [2016-06-23T22:35:28.864767Z] Connected.
    [2016-06-23T22:35:28.864951Z] Sending synchronous request:
    Headers: {":method":"POST",":path":"/3/device/843f************************************************4860aafb7362",":scheme":"https","apns-topic":"com.example.AppId","apns-id":"19499bf9-e634-4ba1-bb41-67ab708dedd0"}
    Body: {"aps":{"alert":"Testing 123","content-available":1,"badge":123}}
    [2016-06-23T22:35:29.027213Z] Response time: 146075 microseconds
    Response headers: {":status":"200","apns-id":"19499bf9-e634-4ba1-bb41-67ab708dedd0"}
    Response body:
    [2016-06-23T22:35:29.027484Z] Pushed without receiving APNS error!

### Using token-based authentication

#### Example of a good response

    aptest --send \
           --apns-issuer ABCDE12345 \
           --apns-kid 1ABCDE2JJJ \
           --apns-auth APNSAuthKey_1ABCDE2JJJ.p8 \
           --apns-env dev \
           --apns-topic com.example.MyApp \
           --apns-token 408***********************************************************1e \
           --message 'Hello'
    [2017-08-24T16:10:06.838782Z] Connecting with HTTP/2 to https://api.development.push.apple.com:443
    [2017-08-24T16:10:07.493847Z] Connected in 625362 microseconds.
    [2017-08-24T16:10:07.495344Z] Sending synchronous request:
    Headers: {":method":"POST",":path":"/3/device/408***********************************************************1e",":scheme":"https","apns-topic":"com.example.MyApp","authorization":"bearer ****.****.****"}
    Body: {"aps":{"alert":"Hello","content-available":1}}
    [2017-08-24T16:10:07.624948Z]
    Response time: 128947 microseconds
    Response headers: {":status":"200","apns-id":"2122F155-808A-E3CD-A92F-2B90B7DB1281"}
    Response body:
    [2017-08-24T16:10:07.625313Z] Pushed without receiving APNS error!

#### Example of an error response

    aptest --send \
           --apns-issuer ABCDE12345 \
           --apns-kid 1ABCDE2JJJ \
           --apns-auth APNSAuthKey_1ABCDE2JJJ.p8 \
           --apns-env prod \
           --apns-topic com.example.MyApp \
           --apns-token 408***********************************************************1e \
           --message 'Hello'
    [2017-08-24T16:02:30.869413Z] Connecting with HTTP/2 to https://api.push.apple.com:443
    [2017-08-24T16:02:31.702170Z] Connected in 802593 microseconds.
    [2017-08-24T16:02:31.703459Z] Sending synchronous request:
    Headers: {":method":"POST",":path":"/3/device/408***********************************************************1e",":scheme":"https","apns-topic":"com.example.MyApp","authorization":"bearer ****.****.****"}
    Body: {"aps":{"alert":"Hello","content-available":1}}
    [2017-08-24T16:02:31.909911Z]
    Response time: 206165 microseconds
    Response headers: {":status":"400","apns-id":"52BB2B4B-BC3B-F75A-151A-2630C815448D"}
    Response body: {"reason":"BadDeviceToken"}
    [2017-08-24T16:02:31.935612Z] APNS error:
    id:             52BB2B4B-BC3B-F75A-151A-2630C815448D
    status:         400
    status_desc:    Bad request
    reason:         BadDeviceToken
    reason_desc:    The specified device token was bad. Verify that the request contains a valid token and that the token matches the environment.
    json:           {"reason":"BadDeviceToken"}

---

## APNS v2 (DEPRECATED)

The APNS v2 module has not been tested for a while because push certificates
are no longer used in my environment, and there are no valid push
certificates, so testing becomes difficult.

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

# Other information

## APNS Version 3

* Apple Production push FQDN used: `api.push.apple.com:443`
* Apple Development push FQDN used: `api.development.push.apple.com:443`

## APNS version 2 (DEPRECATED)

* Apple Production push FQDN used: `gateway.push.apple.com:2195`
* Apple Development push FQDN used: `gateway.sandbox.push.apple.com:2195`

