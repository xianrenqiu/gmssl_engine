tls_server_path="$(pwd)/../tls_server"
cd ${tls_server_path}
gmssl_dir="$(pwd)/../ext/gmssl/bin"
${gmssl_dir}/gmssl s_server -gmtls --state -port 443 -key SS.pem -cert SS.pem -dkey SE.pem -dcert SE.pem -engine libgmssl_engine -cipher SM2-WITH-SMS4-SM3 -WWW ./
