/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package demo.wssec;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;

import java.io.IOException;
import java.io.StringReader;
import java.security.GeneralSecurityException;

import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.ws.Endpoint;

import org.apache.hello_world_soap_http.Greeter;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.rule.OutputCapture;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.ws.client.core.WebServiceTemplate;

@RunWith(SpringRunner.class)
@EnableAutoConfiguration
@TestPropertySource(locations = "classpath:application-test.properties")
@ContextConfiguration(classes = { ServerConfigurationTest.class, ClientConfigurationTest.class })
public class SampleWsApplicationTest {

    // CHECKSTYLE:OFF
    @Rule
    public OutputCapture output = new OutputCapture(); // SUPPRESS CHECKSTYLE
    // CHECKSTYLE:ON

    private WebServiceTemplate webServiceTemplate = new WebServiceTemplate();

    // @LocalServerPort
    // private int port;

    @Autowired
    ServerConfigurationTest serverConfigurationTest;

    @Autowired
    ClientConfigurationTest clientConfigurationTest;

    @Before
    public void setUp() {
        // this.webServiceTemplate.setDefaultUri("http://localhost:" + this.port +
        // "/SoapContext/SoapPort");
        this.webServiceTemplate
                .setDefaultUri("http://localhost:" + serverConfigurationTest.getPort() + "/SoapContext/SoapPort");
    }

    @Test
    public void testHelloRequest() throws IOException, GeneralSecurityException {
        // final String request =
        // "<q0:sayHello xmlns:q0=\"http://service.ws.sample\">Elan</q0:sayHello>";
        String request = "<q0:greetMe xmlns:q0=\"http://apache.org/hello_world_soap_http/types\">alice</q0:greetMe>";

        StreamSource source = new StreamSource(new StringReader(request));
        StreamResult result = new StreamResult(System.out);

        Endpoint endpoint = serverConfigurationTest.endpoint();
        assertThat("Server endpoint must be published", endpoint.isPublished());

        Greeter greeter = clientConfigurationTest.greeter();
        greeter.greetMe("alice");

        this.webServiceTemplate.sendSourceAndReceiveToResult(source, result);
        assertThat(this.output.toString(),
                containsString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                        + "<ns2:sayHelloResponse xmlns:ns2=\"http://apache.org/hello_world_soap_http/\">"
                        + "<return>Hello, Welcome to CXF Spring boot Elan!!!</return>"
                        + "</ns2:sayHelloResponse>"));
    }

}
