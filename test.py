import awstrust

test_doc = """-----BEGIN PKCS7-----
MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggGoewog
ICJkZXZwYXlQcm9kdWN0Q29kZXMiIDogbnVsbCwKICAicHJpdmF0ZUlwIiA6ICIxMC4yMS4xMC4x
MjAiLAogICJhdmFpbGFiaWxpdHlab25lIiA6ICJ1cy13ZXN0LTJhIiwKICAiYWNjb3VudElkIiA6
ICI3MjY2NjA4Mjg1NTIiLAogICJ2ZXJzaW9uIiA6ICIyMDEwLTA4LTMxIiwKICAiaW5zdGFuY2VJ
ZCIgOiAiaS1jMDBlNzU1NCIsCiAgImJpbGxpbmdQcm9kdWN0cyIgOiBudWxsLAogICJpbnN0YW5j
ZVR5cGUiIDogImM0LjJ4bGFyZ2UiLAogICJwZW5kaW5nVGltZSIgOiAiMjAxNi0xMi0xNFQwMjoy
Mzo1M1oiLAogICJhcmNoaXRlY3R1cmUiIDogIng4Nl82NCIsCiAgImltYWdlSWQiIDogImFtaS0z
ODMzOTk1OCIsCiAgImtlcm5lbElkIiA6IG51bGwsCiAgInJhbWRpc2tJZCIgOiBudWxsLAogICJy
ZWdpb24iIDogInVzLXdlc3QtMiIKfQAAAAAAADGCARcwggETAgEBMGkwXDELMAkGA1UEBhMCVVMx
GTAXBgNVBAgTEFdhc2hpbmd0b24gU3RhdGUxEDAOBgNVBAcTB1NlYXR0bGUxIDAeBgNVBAoTF0Ft
YXpvbiBXZWIgU2VydmljZXMgTExDAgkAlrpI2eVeGmcwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJ
AzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE2MTIxNDAyMjQwNlowIwYJKoZIhvcNAQkE
MRYEFGmllXlaywI6YZzjBq+xvKt+h6JwMAkGByqGSM44BAMELjAsAhRkA+0vaHSKEN3DLsNMyoJ7
mImIKgIUaPkUH6EkAhp9Rc4oiIzm2OhKjGQAAAAAAAA=
-----END PKCS7-----"""

print(awstrust.verify_pkcs7(test_doc))
