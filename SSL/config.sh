cd ~
wget http://www.openssl.org/source/openssl-1.0.1c.tar.gz
tar -zxvf openssl-1.0.1c.tar.gz
cd openssl-1.0.1c
./config  --prefix=/usr/local/openssl-1.0.1c --openssldir=/usr/local/openssl-1.0.1c/ssl
make
sudo make install

cd ~
wget https://www.openssl.org/source/openssl-1.1.1f.tar.gz
tar -zxvf openssl-1.1.1f.tar.gz
cd openssl-1.1.1f
./config  --prefix=/usr/local/openssl-1.1.1f --openssldir=/usr/local/openssl-1.1.1f/ssl
make
sudo make install