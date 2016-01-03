# Summary

This is a simple, very rudimentary APNS push token tester. The error messages are ugly and the command line is simplistic. Maybe sometime there will be time to make it pretty.

You will require the push certificate and the unencrypted push key in PEM format, as well as your push token in hex format. You also need outbound access on port 2195 to Apple's 17.0.0.0 IPv4 address range.

# Building

This has only been built and tested on Debian Jessie, using Erlang R17. It is not guaranteed to build or work on other platforms, although it probably will if Erlang R17 is installed.

This requires the installation of `rebar` >= 2.6.0, `Erlang R17`, and GNU `make`.

# Obtaining and building rebar

`rebar` can be built from github as follows (requires Erlang to be installed):

```
git clone https://github.com/rebar/rebar
cd rebar
git checkout 2.6.0
make
```

Make sure the `rebar` executable is somewhere on the `PATH`, like `/usr/local/bin`.

# Building aptest

```
git clone https://github.com/SilentCircle/apns_push_test
cd apns_push_test
make
```

# Running

```
aptest token message path/to/apns/cert.pem path/to/apns/key.pem [prod|dev]
```

Defaults to `prod`.

# Success output

Mainly, you will see the push message on your device.

```
$ aptest 8f72e8890000000000000000000000000000000000000000819bd64324bacc6c 'Sent to XXX from aptest' com.example.Example.cert.pem com.example.Example.key.pem
[2015-03-16T21:45:30.734697Z] Connecting over TLS to gateway.push.apple.com:2195
[2015-03-16T21:45:31.691279Z] Connected.
[2015-03-16T21:45:31.694936Z] Packet decode check:

Command version: v2
Notification ID: 1
Expiry         : 4294967295
Token          : 8f72e8890000000000000000000000000000000000000000819bd64324bacc6c
Payload        : {"aps":{"alert":"Sent to XXX from aptest","sound":"wopr"}}
Priority       : 10
Rest           : <<>>

[2015-03-16T21:45:31.700619Z] Sending packet:
00000000: 02 00 00 00 72 01 00 20 8f 72 e8 89 00 00 00 00   ....r.. .r......
00000010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00000020: 81 9b d6 43 24 ba cc 6c 02 00 3a 7b 22 61 70 73   ...C$..l..:{"aps
00000030: 22 3a 7b 22 61 6c 65 72 74 22 3a 22 53 65 6e 74   ":{"alert":"Sent
00000040: 20 74 6f 20 58 58 58 20 66 72 6f 6d 20 61 70 74    to XXX from apt
00000050: 65 73 74 22 2c 22 73 6f 75 6e 64 22 3a 22 77 6f   est","sound":"wo
00000060: 70 72 22 7d 7d 03 00 04 00 00 00 01 04 00 04 ff   pr"}}...........
00000070: ff ff ff 05 00 01 0a                              .......
[2015-03-16T21:45:31.701055Z] Waiting for error response.
[2015-03-16T21:45:32.871234Z] Pushed without receiving APNS error!
```

# Error output

This varies widely. Giving the wrong path to a certificate, for example, will result in ugly Erlangish abuse being heaped on you. Giving a bad token obtains more polite output.

```
# Bad token
$ aptest 0000000000000000000000000000000000000000000000000000000000000000 'Sent to XXX from aptest' com.example.Example.cert.pem com.example.Example.key.unencrypted.pem
[2015-03-16T21:54:23.299539Z] Connecting over TLS to gateway.push.apple.com:2195
[2015-03-16T21:54:23.701062Z] Connected.
[2015-03-16T21:54:23.704643Z] Packet decode check:

Command version: v2
Notification ID: 1
Expiry         : 4294967295
Token          : 0000000000000000000000000000000000000000000000000000000000000000
Payload        : {"aps":{"alert":"Sent to XXX from aptest","sound":"wopr"}}
Priority       : 10
Rest           : <<>>

[2015-03-16T21:54:23.709625Z] Sending packet:
00000000: 02 00 00 00 72 01 00 20 00 00 00 00 00 00 00 00   ....r.. ........
00000010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00000020: 00 00 00 00 00 00 00 00 02 00 3a 7b 22 61 70 73   ..........:{"aps
00000030: 22 3a 7b 22 61 6c 65 72 74 22 3a 22 53 65 6e 74   ":{"alert":"Sent
00000040: 20 74 6f 20 58 58 58 20 66 72 6f 6d 20 61 70 74    to XXX from apt
00000050: 65 73 74 22 2c 22 73 6f 75 6e 64 22 3a 22 77 6f   est","sound":"wo
00000060: 70 72 22 7d 7d 03 00 04 00 00 00 01 04 00 04 ff   pr"}}...........
00000070: ff ff ff 05 00 01 0a                              .......
[2015-03-16T21:54:23.709834Z] Waiting for error response.
[2015-03-16T21:54:23.751801Z] SSL socket closed
[2015-03-16T21:54:24.752115Z] APNS error: id: 1 status: invalid_token status_code: 8 status_desc: Invalid token
```


# Other information

* Apple Production push FQDN used: `gateway.push.apple.com:2195`
* Apple Development push FQDN used: `gateway.sandbox.push.apple.com:2195`

