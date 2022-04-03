### Server implementation
The servers shall be configured as follow:
1. In `user.txt` all users' usernames shall be inserted divided by a comma e.g., Alice,Bob,Pippo
3. For each user, in `Docs` shall be inserted the relative RSA public key named Username.pem
2. In the `Docs` directory shall be inserted the server certificate named SecureChat_cert.pem 
3. In the `Docs` directory shall be inserted the server RSA private key named SecureChat_key.pem

##### The application is served at INADDR_ANY 8888 
