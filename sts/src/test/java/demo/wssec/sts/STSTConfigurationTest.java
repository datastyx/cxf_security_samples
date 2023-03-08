package demo.wssec.sts;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.namespace.QName;
import javax.xml.ws.Endpoint;
import javax.xml.ws.soap.AddressingFeature;

import org.apache.cxf.Bus;
import org.apache.cxf.bus.spring.SpringBus;
import org.apache.cxf.configuration.jsse.TLSServerParameters;
import org.apache.cxf.ext.logging.LoggingFeature;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.cxf.sts.StaticSTSProperties;
import org.apache.cxf.sts.operation.TokenIssueOperation;
import org.apache.cxf.sts.operation.TokenValidateOperation;
import org.apache.cxf.sts.service.StaticService;
import org.apache.cxf.sts.token.delegation.SAMLDelegationHandler;
import org.apache.cxf.sts.token.provider.SAMLTokenProvider;
import org.apache.cxf.sts.token.validator.SAMLTokenValidator;
import org.apache.cxf.transport.http_jetty.JettyHTTPServerEngineFactory;
import org.apache.cxf.ws.security.sts.provider.SecurityTokenServiceProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class STSTConfigurationTest {

    String stsIssuerName = "Backend_STS";
    int port = 8090; // Must match in WSLD
    String serverAddress = "http://localhost:" + port + "/SecurityTokenService/UT";
    String stsEndpoint = "http://localhost:(\\d)*/SoapContext/SoapPort";
    String stsKeystoreProperties = "sts.properties";
    String stsSignatureUsername = "sts";
    String wsdlPath = "src/main/resources/ws-trust.wsdl";

    // TODO externalize
    String keystoreLocation = "/keys/sts.jks";
    String keystorePassword = "sts-passwd";
    String keyPassword = "sts-passwd";
    QName portName = new QName("http://docs.oasis-open.org/ws-sx/ws-trust/200512/", "STS_Port");
    QName serviceName = new QName("http://docs.oasis-open.org/ws-sx/ws-trust/200512/", "SecurityTokenService");
    // String bindingUri = "{http://schemas.xmlsoap.org/wsdl/}Greeter_SOAPBinding";

    String serviceKeystorePropertyfile = "serviceKeystore.properties";

    @Bean(name = Bus.DEFAULT_BUS_ID)
    public SpringBus cxf(LoggingFeature loggingFeature) {
        SpringBus cxfbus = new SpringBus();
        cxfbus.getFeatures().add(loggingFeature);
        return cxfbus;
    }

    @Bean
    public LoggingFeature loggingFeature() {

        LoggingFeature loggingfeature = new LoggingFeature();
        loggingfeature.setPrettyLogging(true);

        return loggingfeature;
    }

    public static TrustManager[] getTrustManagers(KeyStore trustStore)
            throws NoSuchAlgorithmException, KeyStoreException {
        String alg = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory fac = TrustManagerFactory.getInstance(alg);
        fac.init(trustStore);
        return fac.getTrustManagers();
    }

    public static KeyManager[] getKeyManagers(KeyStore keyStore, String keyPassword)
            throws GeneralSecurityException, IOException {
        String alg = KeyManagerFactory.getDefaultAlgorithm();
        char[] keyPass = keyPassword != null
                ? keyPassword.toCharArray()
                : null;
        KeyManagerFactory fac = KeyManagerFactory.getInstance(alg);
        fac.init(keyStore, keyPass);
        return fac.getKeyManagers();
    }

    @Bean
    JettyHTTPServerEngineFactory jettyHTTPServerEngineFactory() throws IOException, GeneralSecurityException {
        JettyHTTPServerEngineFactory jettyHTTPServerEngineFactory = new JettyHTTPServerEngineFactory();
        // jettyHTTPServerEngineFactory.setTLSServerParametersForPort(port, tlsServerParameters());
        jettyHTTPServerEngineFactory.setBus(cxf(loggingFeature()));
        return jettyHTTPServerEngineFactory;
    }

    // @Bean
    // TLSServerParameters tlsServerParameters() throws IOException, GeneralSecurityException {
    //     TLSServerParameters tlsServerParameters = new TLSServerParameters();
    //     // TODO has to be checked in production

    //     KeyStore keyStore = KeyStore.getInstance("JKS");
    //     keyStore.load(STSTConfiguration.class.getResourceAsStream(keystoreLocation), keystorePassword.toCharArray());
    //     KeyManager[] keyManagers = getKeyManagers(keyStore, keyPassword);
    //     tlsServerParameters.setKeyManagers(keyManagers);
    //     KeyStore trustStore = KeyStore.getInstance("JKS");
    //     trustStore.load(STSTConfiguration.class.getResourceAsStream(keystoreLocation),
    //             keystorePassword.toCharArray());
    //     tlsServerParameters.setTrustManagers(getTrustManagers(trustStore));
    //     return tlsServerParameters;
    // }

    @Bean
    public StaticSTSProperties utSTSProperties() {
        StaticSTSProperties staticSTSProperties = new StaticSTSProperties();
        staticSTSProperties.setSignatureCryptoProperties(stsKeystoreProperties);
        staticSTSProperties.setSignatureUsername(stsSignatureUsername);
        staticSTSProperties.setCallbackHandler(stsCallbackHandler());
        staticSTSProperties.setIssuer("STS");
        return staticSTSProperties;
    }

    @Bean
    public StaticService utService() {
        StaticService staticService = new StaticService();
        staticService.setEndpoints(Arrays.asList(stsEndpoint));
        return staticService;
    }

    @Bean
    public SAMLTokenProvider utSamlTokenProvider() {
        SAMLTokenProvider samlTokenProvider = new SAMLTokenProvider();
        samlTokenProvider.setConditionsProvider(new DelegationConditionsProvider());
        samlTokenProvider.setAttributeStatementProviders(Arrays.asList(new CustomActAsAttributeStatementProvider()));
        return samlTokenProvider;
    }

    @Bean
    public SAMLTokenValidator utSamlTokenValidator() {
        return new SAMLTokenValidator();
    }

    @Bean
    public TokenValidateOperation utValidateDelegate() {
        TokenValidateOperation tokenValidateOperation = new TokenValidateOperation();
        tokenValidateOperation.setTokenValidators(Arrays.asList(utSamlTokenValidator()));
        tokenValidateOperation.setStsProperties(utSTSProperties());
        return tokenValidateOperation;
    }

    @Bean
    public TokenIssueOperation utIssueDelegate() {
        TokenIssueOperation tokenIssueOperation = new TokenIssueOperation();
        tokenIssueOperation.setTokenProviders(Arrays.asList(utSamlTokenProvider()));
        tokenIssueOperation.setDelegationHandlers(Arrays.asList(new SAMLDelegationHandler())); // delegation support
                                                                                               // handler
        tokenIssueOperation.setTokenValidators(Arrays.asList(new SAMLTokenValidator())); // delegated SAML token
                                                                                         // validator
        tokenIssueOperation.setServices(Arrays.asList(utService()));
        tokenIssueOperation.setStsProperties(utSTSProperties());
        ;
        return tokenIssueOperation;
    }

    @Bean
    public SecurityTokenServiceProvider utSTSProviderBean() throws Exception {
        SecurityTokenServiceProvider securityTokenServiceProvider = new SecurityTokenServiceProvider();
        securityTokenServiceProvider.setIssueOperation(utIssueDelegate());
        securityTokenServiceProvider.setValidateOperation(utValidateDelegate());
        return securityTokenServiceProvider;
    }

    @Bean
    public STSCallbackHandler stsCallbackHandler() {
        return new STSCallbackHandler();
    }

    @Bean
    public Endpoint stsEndpoint() throws Exception {
        EndpointImpl endpoint = new EndpointImpl(cxf(loggingFeature()), utSTSProviderBean());
        final Map<String, Object> propertyMap = new HashMap<String, Object>();
        propertyMap.put("security.callback-handler", stsCallbackHandler());
        propertyMap.put("security.signature.properties", stsKeystoreProperties);
        propertyMap.put("security.signature.username", stsSignatureUsername);
        // propertyMap.put("ws-security.enable.streaming", true); // activate XML Stax
        // streaming

        propertyMap.put(javax.xml.ws.Endpoint.WSDL_PORT, portName);
        propertyMap.put(javax.xml.ws.Endpoint.WSDL_SERVICE, serviceName);
        endpoint.setProperties(propertyMap);

        endpoint.setWsdlLocation(wsdlPath);
        endpoint.getServerFactory().getJaxWsServiceFactory()
                .setWsFeatures(Arrays.asList(new AddressingFeature(), loggingFeature()));
        endpoint.publish(serverAddress);
        endpoint.setServiceName(serviceName);
        endpoint.setEndpointName(portName);
        ;

        return endpoint;
    }
}
