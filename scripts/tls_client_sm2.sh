gmssl_dir="$(pwd)/../ext/gmssl/bin"
${gmssl_dir}/gmssl s_client -gmtls --state -connect localhost:443 -cipher SM2-WITH-SMS4-SM3 