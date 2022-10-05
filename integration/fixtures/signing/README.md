# This is how the certs were created

```bash
openssl genrsa -out rsa.key 2048
openssl rsa -in rsa.key -outform PEM -pubout -out rsa.crt
openssl genrsa -out another.rsa.key 2048
openssl rsa -in another.rsa.key -outform PEM -pubout -out another.rsa.crt
openssl ecparam -genkey -name prime256v1 -noout -out es256.key
openssl ec -in es256.key -pubout -out es256.crt
openssl ecparam -genkey -name prime256v1 -noout -out another.es256.key
openssl ec -in another.es256.key -pubout -out another.es256.crt
openssl ecparam -genkey -name secp384r1 -noout -out es384.key
openssl ec -in es384.key -pubout -out es384.crt
openssl ecparam -genkey -name secp384r1 -noout -out another.es384.key
openssl ec -in another.es384.key -pubout -out another.es384.crt
openssl ecparam -genkey -name secp521r1 -noout -out es512.key
openssl ec -in es512.key -pubout -out es512.crt
openssl ecparam -genkey -name secp521r1 -noout -out another.es512.key
openssl ec -in another.es512.key -pubout -out another.es512.crt
```