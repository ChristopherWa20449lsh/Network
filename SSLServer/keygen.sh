# 生成私钥
openssl genrsa -out server.key 2048
# 生成证书请求
openssl req -new -key server.key -out server.csr
# 生成自签证书
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt