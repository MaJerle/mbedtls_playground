@echo ON

:: Generate root certificate and self sign it
echo "generate root CA"
openssl ecparam -genkey -name prime256v1 -out ec_root.key
openssl req -x509 -new -nodes -key ec_root.key -sha256 -days 1024 -out ec_root.crt -subj "/C=US/ST=CA/O=MyOrg, Inc./CN=root"

:: ec_user certificate, signed with root CA
echo "generate ec_user CA"
openssl ecparam -genkey -name prime256v1 -out ec_user.key
openssl req -new -sha256 -key ec_user.key -out ec_user.csr -subj "/C=US/ST=CA/O=MyOrg, Inc./CN=ec_user"
openssl x509 -req -in ec_user.csr -CA ec_root.crt -CAkey ec_root.key -CAcreateserial -out ec_user.crt -days 500 -sha256

:: Print
echo "print certificates"
openssl x509 -in ec_root.crt -text
openssl x509 -in ec_user.crt -text

:: Verify user 1 certificate trust chain w/o untrusted mode
echo 
echo 
openssl verify -verbose -CAfile ec_root.crt ec_user.crt



