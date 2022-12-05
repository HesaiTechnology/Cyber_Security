### Compile:

To support PTCs, use the following compilation method:
    make SSL=on

If only PTC is supported, use this compilation method instead:
    make

### Configure the shared secret key (SSK) for point cloud signature:

SSK is stored in `./ucs/ssk/ssk.nky` and can be changed.
Default: 12345678

Set the SSK on the Cybersecurity page of lidar web control to be the same as that in `./ucs/ssk/ssk.nky`.

Afterwards, use the following command to make the shared secret key effective:
        ./ptcs_sig 192.168.1.201 9347 signatureStart 2368 ucs/ssk/ssk.nky

### Configure the certificates:

The following three macro definitions in `tcp_command_client.c` are used for configuring the paths of certificates:

        ```
        /**
        * Under mTLS (two-way auth) mode, specify the client end-entity certificate and its private key. 
        * The lidar uses this certificate to verify the client's identity.
        */
        #define CLIENT_CRT "cert/client.test.cert.pem"
        #define CLIENT_RSA_PRIVATE  "cert/client.test.key.pem"

        /**
        * Under both TLS (one-way auth) and mTLS mode, specify Hesai CA certificate chain.
        * The client uses this certificate chain to verify the validity of a lidar unit's end-entity certificate.
        */
        #define CA_SERVER_CRT "cert/ca_client.pem"
        ```
