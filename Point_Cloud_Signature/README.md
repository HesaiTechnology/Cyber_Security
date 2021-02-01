### Compile:

If you want to support PTCS, the compilation method is as follows:
    make SSL=on

If only PTC is supported, the compilation method is as follows:
    make

### Configuration description of point cloud signature shared secret key:

    Create a file in the ./ucs/ssk/ssk.nky. The content of './ucs/ssk/ssk.nky' 
is same as the shared secret key set on the web page!

    You can use the following command to make the shared secret key effective:
        ./ptcs_sig 192.168.1.201 9347 signatureStart 2368 ucs/ssk/ssk.nky

### Certificate configuration:

    You can find the following three macro definitions in the file tcp_command_client.c. 
These macro definitions are used to configure the path of certificate, which is used to 
implement TLS or MTLS.

        ```
        /**
        * Specify the client certificate and the corresponding
        * private key for double-end authentication of PTCs. 
        * The certificate is sent to Lidar to verify the identity of the client.
        */
        #define CLIENT_CRT "cert/client.test.cert.pem"
        #define CLIENT_RSA_PRIVATE  "cert/client.test.key.pem"
        /**
        * Specify the client certificate chain for 
        * single-ended verification of PTCs to verify 
        * the validity of the certificate sent by the server.
        */
        #define CA_SERVER_CRT "cert/ca_client.pem"
        ```
