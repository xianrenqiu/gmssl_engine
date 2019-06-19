gmssl_dir="$(pwd)/../ext"

if [ ! -d "${gmssl_dir}/gmssl" ]; then
    cd ${gmssl_dir} 
    unzip GmSSL-master.zip
    cd GmSSL-master 
    chmod +x config
    ./config no-shared --prefix=${gmssl_dir}/gmssl -debug
    make 
    make install_sw 
    mkdir ${gmssl_dir}/gmssl/ssl
    cp apps/openssl.cnf ${gmssl_dir}/gmssl/bin
    cp apps/openssl.cnf ${gmssl_dir}/gmssl/ssl
    cd ${gmssl_dir} 
    rm -rf GmSSL-master
fi
