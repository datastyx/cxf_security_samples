# Sample SOAP service with security

This sample has the CXF Hello world sample with added security.
The code allows runing a service and it's correpsonding client.

Current version has as a requisit to run a WS-Trust1.4 STS has an external service (e.g. wso2is v5.10, product available at https://github.com/wso2/product-is/releases/tag/v5.10.0 and configuration steps available at https://is.docs.wso2.com/en/5.10.0/setup/changing-the-hostname/ and then at https://is.docs.wso2.com/en/5.10.0/learn/configuring-ws-trust-security-token-service/) 


The sample uses Maven. It can be built and run from the command line:

## Configuration prerequisits :
The STS must have the certificates of the Client and the Service deployed.

The client's keystore already includes the service's certificate for the TLS (HTTPS) connexion but also needs the STS's certificate for the same purpose.
1. Remove previous STS certificate in the client's keystore :
```keytool -delete -alias wso2is -keystore clientKeystore.jks -storepass client```
2. Add the current STS certificate in the client's keystore : 
```keytool -import -alias <sts_cert_alias> -file <path/to/cert> -keystore clientKeystore.jks -storepass client```

The service validates the client's request including the SAML security token issued by the STS.  Therefore the STS's certificate has to be included in the service's keystore.

1. Remove previous STS certificate :
```keytool -delete -alias wso2is -keystore serviceKeystore.jks -storepass service```
2. Add the current STS certificate : 
```keytool -import -alias <sts_cert_alias> -file <path/to/cert> -keystore serviceKeystore.jks -storepass service```

## The service 

To run the service use Maven :

```
$ mvn spring-boot:run
```

http://localhost:9001/SoapContext/SoapPort will now offer the hello world endpoint.


## The client

to run the client run in a new terminal window with Maven:
(quotes are windows specific)
```
$ mvn spring-boot:run -D"spring-boot.run.arguments=--spring.profiles.active=client"
```
