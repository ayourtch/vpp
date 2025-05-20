wget --method=PUT --body-file=/tmp/geneve_capture_worker0.pcapng.gz  http://localhost:3000/capture3.dat


# Create directory for certificates
mkdir -p ./certs

# Generate CA key and certificate
openssl genrsa -out ./certs/ca.key 2048
openssl req -x509 -new -nodes -key ./certs/ca.key -sha256 -days 1024 -out ./certs/ca.crt -subj "/CN=My Test CA"

# Generate server key and CSR
openssl genrsa -out ./certs/server.key 2048
openssl req -new -key ./certs/server.key -out ./certs/server.csr -subj "/CN=localhost"

# Sign the server certificate with the CA
openssl x509 -req -in ./certs/server.csr -CA ./certs/ca.crt -CAkey ./certs/ca.key -CAcreateserial -out ./certs/server.crt -days 365 -sha256

# Generate client key and CSR
openssl genrsa -out ./certs/client.key 2048
openssl req -new -key ./certs/client.key -out ./certs/client.csr -subj "/CN=testclient"

# Sign the client certificate with the CA
openssl x509 -req -in ./certs/client.csr -CA ./certs/ca.crt -CAkey ./certs/ca.key -CAcreateserial -out ./certs/client.crt -days 365 -sha256

# Create a PKCS12 file for client (useful for browser testing)
openssl pkcs12 -export -out ./certs/client.pfx -inkey ./certs/client.key -in ./certs/client.crt -certfile ./certs/ca.crt -password pass:password



# Test with client certificate
curl -k -v --cert ./certs/client.crt --key ./certs/client.key \
     --cacert ./certs/ca.crt -X PUT --data-binary @large_file.dat \
     https://localhost:3443/path/to/save/file.dat

# Test streaming upload with client certificate
cat large_file.dat | curl -k -v --cert ./certs/client.crt --key ./certs/client.key \
                          --cacert ./certs/ca.crt -X PUT --data-binary @- \
                          https://localhost:3443/path/to/save/file.dat


# Test HTTPS without client certificate
curl -k -v -X PUT --data-binary @large_file.dat https://localhost:3443/path/to/save/file.dat

# Test HTTP
curl -v -X PUT --data-binary @large_file.dat http://localhost:3000/path/to/save/file.dat


# Basic HTTPS upload with wget
wget --method=PUT \
     --body-file=large_file.dat \
     --no-check-certificate \
     https://localhost:3443/path/to/save/file.dat


# Upload with client certificate authentication
wget --method=PUT \
     --body-file=large_file.dat \
     --certificate=./certs/client.crt \
     --private-key=./certs/client.key \
     --ca-certificate=./certs/ca.crt \
     https://localhost:3443/path/to/save/file.dat# Upload with client certificate authentication


