@echo off
::curl https://45.76.36.33:1443/ -k
curl --tlsv1.2 --tls-max 1.2 -k https://45.76.36.33:443/ua
curl --tlsv1.2 --tls-max 1.2 -k https://45.76.36.33:4443/
echo ===============================================================
curl --tlsv1.2 --tls-max 1.2 -k https://45.76.36.33:443/ua --socks5 209.38.110.113:1081
curl --tlsv1.2 --tls-max 1.2 -k https://45.76.36.33:4443/ --socks5 209.38.110.113:1081
