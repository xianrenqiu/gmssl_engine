tls_server_path="$(pwd)/../tls_server"
cd ${tls_server_path}
gmssl_dir="$(pwd)/../ext/gmssl/bin"
${gmssl_dir}/gmssl s_server --state -named_curve prime256v1 --state -port 443 -key srv_privkey.pem -cert srv_cert.pem -tls1_2 -engine libgmssl_engine -cipher ECDHE-ECDSA-AES128-GCM-SHA256  -WWW ./ 
