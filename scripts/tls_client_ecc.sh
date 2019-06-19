gmssl_dir="$(pwd)/../ext/gmssl/bin"
cd ${gmssl_dir}
./gmssl s_client --state -debug -msg -connect localhost:443 -sigalgs ECDSA+SHA256
