# cmake 3.8.2
# wget https://cmake.org/files/v3.8/cmake-3.8.2-Linux-x86_64.sh --no-check-certificate
yes | sh cmake-3.8.2-Linux-x86_64.sh | cat
rm -rf /opt/cmake-3.8.2-Linux-x86_64
mv cmake-3.8.2-Linux-x86_64 /opt/
echo "export PATH=/opt/cmake-3.8.2-Linux-x86_64/bin:\$PATH" >> /root/.bashrc
source /root/.bashrc
cmake --version
