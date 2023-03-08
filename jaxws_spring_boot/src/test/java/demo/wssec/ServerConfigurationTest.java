package demo.wssec;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.xml.namespace.QName;
import javax.xml.ws.Endpoint;
import javax.xml.ws.soap.AddressingFeature;

import org.apache.cxf.Bus;
import org.apache.cxf.binding.soap.saaj.SAAJInInterceptor;
import org.apache.cxf.binding.soap.saaj.SAAJOutInterceptor;
import org.apache.cxf.bus.spring.SpringBus;
import org.apache.cxf.configuration.jsse.TLSServerParameters;
import org.apache.cxf.ext.logging.LoggingFeature;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.cxf.transport.http_jetty.JettyHTTPServerEngineFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import demo.wssec.common.CommonConfiguration;
import demo.wssec.server.GreeterImpl;
import demo.wssec.server.Server;
import demo.wssec.server.ServerCallbackHandler;

@Configuration
@SpringBootTest(classes = Server.class, webEnvironment = WebEnvironment.RANDOM_PORT)
public class ServerConfigurationTest {

    String keystoreLocation = "/clientKeystore.jks";
    String keystorePassword = "client";
    String keyPassword = "client";
    QName endpointName = new QName("http://apache.org/hello_world_soap_http", "SoapPort");
    QName serviceName = new QName("http://apache.org/hello_world_soap_http", "SOAPService");
    String bindingUri = "{http://schemas.xmlsoap.org/wsdl/}Greeter_SOAPBinding";
    String wsdlPath = "/hello_world.wsdl";

    // String serverAddress = "https://localhost:9001/SoapContext/SoapPort";
    int port = 49001;

    String serviceKeystorePropertyfile = "serviceKeystore.properties";

    public int getPort() {
        return port;
    }

    @Bean(name=Bus.DEFAULT_BUS_ID)
    public SpringBus springBus(LoggingFeature loggingFeature) {
  
      SpringBus cxfbus = new  SpringBus();
      cxfbus.getFeatures().add(loggingFeature);
  
      return cxfbus;
    }

    @Bean
    public LoggingFeature loggingFeature() {

        LoggingFeature loggingfeature = new LoggingFeature();
        loggingfeature.setPrettyLogging(true);

        return loggingfeature;
    }

    @Bean
    JettyHTTPServerEngineFactory jettyHTTPServerEngineFactory() throws IOException, GeneralSecurityException {
        JettyHTTPServerEngineFactory jettyHTTPServerEngineFactory = new JettyHTTPServerEngineFactory();
        // jettyHTTPServerEngineFactory.setTLSServerParametersForPort(getPort(), tlsServerParameters());
        return jettyHTTPServerEngineFactory;
    }

    // @Bean
    // TLSServerParameters tlsServerParameters() throws IOException, GeneralSecurityException {
    //     TLSServerParameters tlsServerParameters = new TLSServerParameters();
    //     // TODO has to be checked in production

    //     KeyStore keyStore = KeyStore.getInstance("JKS");
    //     keyStore.load(ServerConfigurationTest.class.getResourceAsStream(keystoreLocation),
    //             keystorePassword.toCharArray());
    //     KeyManager[] keyManagers = CommonConfiguration.getKeyManagers(keyStore, keyPassword);
    //     tlsServerParameters.setKeyManagers(keyManagers);
    //     KeyStore trustStore = KeyStore.getInstance("JKS");
    //     trustStore.load(ServerConfigurationTest.class.getResourceAsStream(keystoreLocation),
    //             keystorePassword.toCharArray());
    //     tlsServerParameters.setTrustManagers(CommonConfiguration.getTrustManagers(trustStore));
    //     return tlsServerParameters;
    // }

    @Bean
    public Endpoint endpoint() {
        EndpointImpl endpoint = new EndpointImpl(springBus(loggingFeature()), new GreeterImpl());
        final Map<String, Object> propertyMap = new HashMap<String, Object>();
        propertyMap.put("security.callback-handler", ServerCallbackHandler.class);
        propertyMap.put("security.signature.properties", serviceKeystorePropertyfile);
        propertyMap.put("security.enableRevocation", "false");
        // TODO True in production
        propertyMap.put("security.validate.audience-restriction", "false");
        propertyMap.put(javax.xml.ws.Endpoint.WSDL_PORT, endpointName);
        propertyMap.put(javax.xml.ws.Endpoint.WSDL_SERVICE, serviceName);
        endpoint.setProperties(propertyMap);
        endpoint.setWsdlLocation(wsdlPath);
        endpoint.getServerFactory().getJaxWsServiceFactory()
                .setWsFeatures(Arrays.asList(new AddressingFeature(), loggingFeature()));
        endpoint.getInInterceptors().add(new SAAJInInterceptor());
        endpoint.getOutInterceptors().add(new SAAJOutInterceptor());
        endpoint.publish("http://localhost:"+this.getPort()+ "/SoapContext/SoapPort");

        return endpoint;
    }
}
