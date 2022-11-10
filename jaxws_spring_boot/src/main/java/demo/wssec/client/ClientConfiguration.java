package demo.wssec.client;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.xml.namespace.QName;

import org.apache.cxf.Bus;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.ext.logging.LoggingFeature;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.ws.security.trust.STSClient;
import org.apache.hello_world_soap_http.Greeter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import demo.wssec.common.CommonConfiguration;
import demo.wssec.common.ISubCallbackHandler;
import demo.wssec.common.KeystoreSubCallbackHandler;
import demo.wssec.common.WSPasswordCallbackHandler;

@Profile("client")
@Configuration
public class ClientConfiguration {

    @Value("${client.user}")
    String clientUsername;

    @Value("${client.sts.merlin.propertyfile}")
    String merlinPropertyFile;

    @Value("${client.sts.keystore.user.encrypt.pubkey.alias}")
    String encryptionUsername;

    @Value("${client.keystore.user.pubkey.alias}")
    String stsTokenUsername;

    String keystoreLocation = "/clientKeystore.jks";
    String keystorePassword = "client";
    String keyPassword = "client";

    String stsTokenProperties = "src/main/resources/clientKeystore.properties";
    String wsdlLocation = "src/main/resources/hello_world.wsdl";
    QName serviceName = new QName("http://apache.org/hello_world_soap_http", "SOAPService");
    QName endpointName = new QName("http://apache.org/hello_world_soap_http", "SoapPort");

    @Autowired
    LoggingFeature loggingFeature;

    @Autowired
    Bus cxf;

    @Bean
    ClaimsCallbackHandler claimsCallbackHandler() {
        return new ClaimsCallbackHandler();
    }

    @Bean
    KeystoreSubCallbackHandler keystoreSubCallbackHandler() {
        return new KeystoreSubCallbackHandler("client");
    }

    @Bean
    UsernameTokenSubCallbackHandler usernameTokenSubCallbackHandler() {
        return new UsernameTokenSubCallbackHandler();
    }

    @Bean
    WSPasswordCallbackHandler wsPasswordCallbackHandler() {
        final List<ISubCallbackHandler> list = new ArrayList<ISubCallbackHandler>();
        list.add(keystoreSubCallbackHandler());
        list.add(usernameTokenSubCallbackHandler());
        WSPasswordCallbackHandler wsPasswordCallbackHandler = new WSPasswordCallbackHandler();
        wsPasswordCallbackHandler.setSubCallbackHandlers(list);
        return wsPasswordCallbackHandler;
    }

    @Bean
    STSClient stsClient() throws IOException, GeneralSecurityException {
        STSClient stsClient = new STSClient(cxf);
        stsClient.setRequiresEntropy(false);
        stsClient.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        stsClient.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey");
        stsClient.setAddressingNamespace("http://schemas.xmlsoap.org/ws/2004/08/addressing");
        stsClient.setWsdlLocation("src/main/resources/ws-trust.wsdl");
        stsClient.setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512/}wso2carbon-sts");
        stsClient.setEndpointName(
                "{http://docs.oasis-open.org/ws-sx/ws-trust/200512/}wso2carbon-stsHttpsSoap12Endpoint");
        stsClient.setClaimsCallbackHandler(claimsCallbackHandler());
        stsClient.setFeatures(Arrays.asList(loggingFeature));
        final Map<String, Object> propertyMap = new HashMap<String, Object>();
        propertyMap.put("security.username", clientUsername);
        propertyMap.put("security.encryption.properties", merlinPropertyFile);
        propertyMap.put("security.encryption.username", encryptionUsername);
        propertyMap.put("security.sts.token.username", stsTokenUsername);
        propertyMap.put("security.sts.token.properties", stsTokenProperties);
        propertyMap.put("security.sts.token.usecert", "true");
        propertyMap.put("security.callback-handler", wsPasswordCallbackHandler());
        stsClient.setProperties(propertyMap);
        stsClient.setTlsClientParameters(tlsClientParameters());
        return stsClient;
    }

    @Bean
    SAML2stsCallbackHandler saml2stsCallbackHandler() throws IOException, GeneralSecurityException {
        SAML2stsCallbackHandler saml2stsCallbackHandler = new SAML2stsCallbackHandler("https://service/services/echo");
        saml2stsCallbackHandler.setStsClient(stsClient());

        return saml2stsCallbackHandler;
    }

    @Bean
    JaxWsProxyFactoryBean wssProxyFactory() throws IOException, GeneralSecurityException {
        JaxWsProxyFactoryBean jaxWsProxyFactoryBean = new JaxWsProxyFactoryBean();
        jaxWsProxyFactoryBean.setBus(cxf);
        jaxWsProxyFactoryBean.setServiceClass(org.apache.hello_world_soap_http.Greeter.class);
        jaxWsProxyFactoryBean.setWsdlLocation(wsdlLocation);
        jaxWsProxyFactoryBean.setServiceName(serviceName);
        jaxWsProxyFactoryBean.setEndpointName(endpointName);
        jaxWsProxyFactoryBean.setFeatures(Arrays.asList(loggingFeature));
        final Map<String, Object> propertyMap = new HashMap<String, Object>();
        propertyMap.put("security.callback-handler", wsPasswordCallbackHandler());
        propertyMap.put("security.signature.properties", "clientKeystore.properties");
        propertyMap.put("security.saml-callback-handler", saml2stsCallbackHandler());
        jaxWsProxyFactoryBean.setProperties(propertyMap);
        return jaxWsProxyFactoryBean;
    }

    @Bean
    Greeter greeter() throws IOException, GeneralSecurityException {
        Greeter greeter = (Greeter) wssProxyFactory().create();
        org.apache.cxf.endpoint.Client proxy = ClientProxy.getClient(greeter);
        HTTPConduit conduit = (HTTPConduit) proxy.getConduit();
        conduit.setTlsClientParameters(tlsClientParameters());

        return greeter;

    }

 
    @Bean
    TLSClientParameters tlsClientParameters() throws IOException, GeneralSecurityException {
        TLSClientParameters tlsClientParameters = new TLSClientParameters();
        // TODO has to be checked in production
        tlsClientParameters.setDisableCNCheck(true);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ClientConfiguration.class.getResourceAsStream(keystoreLocation), keystorePassword.toCharArray());
        KeyManager[] keyManagers = CommonConfiguration.getKeyManagers(keyStore, keyPassword);
        tlsClientParameters.setKeyManagers(keyManagers);
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(ClientConfiguration.class.getResourceAsStream(keystoreLocation), keystorePassword.toCharArray());
        tlsClientParameters.setTrustManagers(CommonConfiguration.getTrustManagers(trustStore));
        return tlsClientParameters;
    }
}
