@echo ON

:: Generate root certificate and self sign it
echo "generate root CA"
openssl ecparam -genkey -name prime256v1 -out ec_oem.key
openssl ec -in ec_oem.key -pubout -out ec_oem_pub.key
openssl req -x509 -new -nodes -key ec_oem.key -sha256 -days 99999 -out ec_oem.crt -subj "/C=US/ST=CA/O=MyOrg, Inc./CN=root"

:: ec_device certificate, signed with root CA
echo "generate ec_device CA"
openssl ecparam -genkey -name prime256v1 -out ec_device.key
openssl ec -in ec_device.key -pubout -out ec_device_pub.key
openssl req -new -sha256 -key ec_device.key -out ec_device.csr -subj "/C=US/ST=CA/O=MyOrg, Inc./CN=ec_device"
openssl x509 -req -in ec_device.csr -CA ec_oem.crt -CAkey ec_oem.key -CAcreateserial -out ec_device.crt -days 99999 -sha256

:: Print
echo "print certificates"
openssl x509 -in ec_oem.crt -text
openssl x509 -in ec_device.crt -text

:: Verify user 1 certificate trust chain w/o untrusted mode
echo 
echo 
openssl verify -verbose -CAfile ec_oem.crt ec_device.crt

:: Convert text files into C array sequence, ready for MCU C build
python ../../scripts/ca.py convert_file_to_hex --path . --grp ec_*.crt ec_*.key
