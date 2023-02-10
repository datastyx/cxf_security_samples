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
package demo.wssec.sts;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import javax.xml.bind.JAXBElement;

import org.apache.cxf.jaxws.context.WrappedMessageContext;
import org.apache.cxf.message.MessageImpl;
import org.apache.cxf.rt.security.claims.Claim;
import org.apache.cxf.rt.security.claims.ClaimCollection;
import org.apache.cxf.sts.QNameConstants;
import org.apache.cxf.sts.STSConstants;
import org.apache.cxf.sts.StaticSTSProperties;
import org.apache.cxf.sts.claims.ClaimTypes;
import org.apache.cxf.sts.claims.ClaimsHandler;
import org.apache.cxf.sts.claims.ClaimsManager;
import org.apache.cxf.sts.claims.CombinedClaimsAttributeStatementProvider;
import org.apache.cxf.sts.request.KeyRequirements;
import org.apache.cxf.sts.request.ReceivedToken;
import org.apache.cxf.sts.request.ReceivedToken.STATE;
import org.apache.cxf.sts.request.TokenRequirements;
import org.apache.cxf.sts.service.EncryptionProperties;
import org.apache.cxf.sts.token.provider.AttributeStatementProvider;
import org.apache.cxf.sts.token.provider.SAMLTokenProvider;
import org.apache.cxf.sts.token.provider.TokenProvider;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.cxf.sts.token.provider.TokenProviderResponse;
import org.apache.cxf.ws.security.sts.provider.model.secext.AttributedString;
import org.apache.cxf.ws.security.sts.provider.model.secext.UsernameTokenType;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.CustomTokenPrincipal;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.util.DOM2Writer;
import org.junit.Assert;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.ext.saml2delrestrict.DelegationRestrictionType;
import org.opensaml.saml.saml2.core.Condition;
import org.w3c.dom.Element;

/**
 * Some unit tests for creating SAML Tokens with an ActAs element.
 */
public class DelegateSAML2AssertionTest {

    /**
     * Create a default Saml2 Bearer Assertion with ActAs from a SAML1 Assertion
     */
    @org.junit.Test
    public void testDefaultSaml2ActAsAssertionSaml1() throws Exception {
        saml2ActAsAssertion(WSS4JConstants.WSS_SAML_TOKEN_TYPE);
    }

    /**
     * Create a default Saml2 Bearer Assertion with ActAs from a SAML2 Assertion
     */
    @org.junit.Test
    public void testDefaultSaml2ActAsAssertionSaml2() throws Exception {
        saml2ActAsAssertion(WSS4JConstants.WSS_SAML2_TOKEN_TYPE);
    }

    public void saml2ActAsAssertion(String assertionSamlVersion) throws Exception {
        TokenProvider samlTokenProvider = new SAMLTokenProvider();
        // custom ActAs configuration
        ((SAMLTokenProvider) samlTokenProvider).setConditionsProvider(new DelegationConditionsProvider());
        ((SAMLTokenProvider) samlTokenProvider).setAttributeStatementProviders(Arrays
                .asList(new CustomActAsAttributeStatementProvider(), new CombinedClaimsAttributeStatementProvider()));
        String user = "bob";
        Element samlAssertion = getSAMLAssertion(assertionSamlVersion);

        TokenProviderParameters providerParameters = createProviderParameters(
                WSS4JConstants.WSS_SAML2_TOKEN_TYPE, STSConstants.BEARER_KEY_KEYTYPE, samlAssertion);
        // Principal must be set in ReceivedToken/ActAs
        providerParameters.getTokenRequirements().getActAs().setPrincipal(
                new CustomTokenPrincipal(user));

        assertTrue(samlTokenProvider.canHandleToken(WSS4JConstants.WSS_SAML2_TOKEN_TYPE));
        TokenProviderResponse providerResponse = samlTokenProvider.createToken(providerParameters);
        assertNotNull(providerResponse);
        assertTrue(providerResponse.getToken() != null && providerResponse.getTokenId() != null);

        // Verify the token
        Element token = (Element) providerResponse.getToken();
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(token);
        Assert.assertEquals("technical-user", assertion.getSubjectName());

        boolean foundActAsAttribute = false;
        for (org.opensaml.saml.saml2.core.AttributeStatement attributeStatement : assertion.getSaml2()
                .getAttributeStatements()) {
            for (org.opensaml.saml.saml2.core.Attribute attribute : attributeStatement.getAttributes()) {
                if ("ActAs".equals(attribute.getName())) {
                    for (XMLObject attributeValue : attribute.getAttributeValues()) {
                        Element attributeValueElement = attributeValue.getDOM();
                        String text = attributeValueElement.getTextContent();
                        if (text.contains("bob")) {
                            foundActAsAttribute = true;
                            break;
                        }
                    }
                }
            }
        }
        assertTrue(foundActAsAttribute);

        // check if delegationRestrictionType was inserted
        boolean hasDelegateRestrictionType = false;
        for (Condition condition : assertion.getSaml2().getConditions().getConditions()) {
            hasDelegateRestrictionType |= (condition instanceof DelegationRestrictionType);
        }
        assertTrue(hasDelegateRestrictionType);

        // Check that claims are also present
        String tokenString = DOM2Writer.nodeToString(token);
        assertTrue(tokenString.contains(providerResponse.getTokenId()));
        assertTrue(tokenString.contains(ClaimTypes.EMAILADDRESS.toString()));
        assertTrue(tokenString.contains(ClaimTypes.FIRSTNAME.toString()));
        assertTrue(tokenString.contains(ClaimTypes.LASTNAME.toString()));
    }

    /**
     * Create a Saml1 Bearer Assertion with ActAs from a UsernameToken. The
     * SAMLTokenProvider is
     * configured with a custom Attribute Provider that instead creates a
     * "CustomActAs" attribute.
     */
    @org.junit.Test
    public void testCustomHandlingUsernameToken() throws Exception {
        TokenProvider samlTokenProvider = new SAMLTokenProvider();

        UsernameTokenType usernameToken = new UsernameTokenType();
        AttributedString username = new AttributedString();
        username.setValue("bob");
        usernameToken.setUsername(username);
        JAXBElement<UsernameTokenType> usernameTokenType = new JAXBElement<UsernameTokenType>(
                QNameConstants.USERNAME_TOKEN, UsernameTokenType.class, usernameToken);

        TokenProviderParameters providerParameters = createProviderParameters(
                WSS4JConstants.WSS_SAML_TOKEN_TYPE, STSConstants.BEARER_KEY_KEYTYPE, usernameTokenType);
        // Principal must be set in ReceivedToken/ActAs
        providerParameters.getTokenRequirements().getActAs().setPrincipal(
                new CustomTokenPrincipal(username.getValue()));

        assertTrue(samlTokenProvider.canHandleToken(WSS4JConstants.WSS_SAML_TOKEN_TYPE));
        TokenProviderResponse providerResponse = samlTokenProvider.createToken(providerParameters);
        assertNotNull(providerResponse);
        assertTrue(providerResponse.getToken() != null && providerResponse.getTokenId() != null);

        Element token = (Element) providerResponse.getToken();
        String tokenString = DOM2Writer.nodeToString(token);
        assertTrue(tokenString.contains(providerResponse.getTokenId()));
        assertTrue(tokenString.contains("AttributeStatement"));
        assertTrue(tokenString.contains("bob"));

        assertFalse(tokenString.contains("CustomActAs"));

        List<AttributeStatementProvider> customProviderList = Collections.singletonList(new CustomAttributeProvider());
        ((SAMLTokenProvider) samlTokenProvider).setAttributeStatementProviders(customProviderList);

        providerResponse = samlTokenProvider.createToken(providerParameters);
        assertNotNull(providerResponse);
        assertTrue(providerResponse.getToken() != null && providerResponse.getTokenId() != null);

        token = (Element) providerResponse.getToken();
        tokenString = DOM2Writer.nodeToString(token);
        assertTrue(tokenString.contains("CustomActAs"));
    }

    @org.junit.Test
    public void testSAML2ActAsUsernameTokenClaims() throws Exception {
        TokenProvider samlTokenProvider = new SAMLTokenProvider();
        // custom ActAs configuration
        ((SAMLTokenProvider) samlTokenProvider).setConditionsProvider(new DelegationConditionsProvider());
        ((SAMLTokenProvider) samlTokenProvider).setAttributeStatementProviders(Arrays
                .asList(new CustomActAsAttributeStatementProvider(), new CombinedClaimsAttributeStatementProvider()));
        UsernameTokenType usernameToken = new UsernameTokenType();
        AttributedString username = new AttributedString();
        username.setValue("bob");
        usernameToken.setUsername(username);
        JAXBElement<UsernameTokenType> usernameTokenType = new JAXBElement<UsernameTokenType>(
                QNameConstants.USERNAME_TOKEN, UsernameTokenType.class, usernameToken);

        TokenProviderParameters providerParameters = createProviderParameters(
                WSS4JConstants.WSS_SAML2_TOKEN_TYPE, STSConstants.BEARER_KEY_KEYTYPE, usernameTokenType);
        // Principal must be set in ReceivedToken/ActAs
        providerParameters.getTokenRequirements().getActAs().setPrincipal(
                new CustomTokenPrincipal(username.getValue()));

        // Add Claims
        ClaimsManager claimsManager = new ClaimsManager();
        ClaimsHandler claimsHandler = new CustomClaimsHandler();
        claimsManager.setClaimHandlers(Collections.singletonList(claimsHandler));
        providerParameters.setClaimsManager(claimsManager);

        ClaimCollection claims = createClaims();
        providerParameters.setRequestedPrimaryClaims(claims);

        assertTrue(samlTokenProvider.canHandleToken(WSS4JConstants.WSS_SAML2_TOKEN_TYPE));
        TokenProviderResponse providerResponse = samlTokenProvider.createToken(providerParameters);
        assertNotNull(providerResponse);
        assertTrue(providerResponse.getToken() != null && providerResponse.getTokenId() != null);

        // Verify the token
        Element token = (Element) providerResponse.getToken();
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(token);
        Assert.assertEquals("technical-user", assertion.getSubjectName());

        boolean foundActAsAttribute = false;
        for (org.opensaml.saml.saml2.core.AttributeStatement attributeStatement : assertion.getSaml2()
                .getAttributeStatements()) {
            for (org.opensaml.saml.saml2.core.Attribute attribute : attributeStatement.getAttributes()) {
                if ("ActAs".equals(attribute.getName())) {
                    for (XMLObject attributeValue : attribute.getAttributeValues()) {
                        Element attributeValueElement = attributeValue.getDOM();
                        String text = attributeValueElement.getTextContent();
                        if (text.contains("bob")) {
                            foundActAsAttribute = true;
                            break;
                        }
                    }
                }
            }
        }

        assertTrue(foundActAsAttribute);

        // check if delegationRestrictionType was inserted
        boolean hasDelegateRestrictionType = false;
        for (Condition condition : assertion.getSaml2().getConditions().getConditions()) {
            hasDelegateRestrictionType |= (condition instanceof DelegationRestrictionType);
        }
        assertTrue(hasDelegateRestrictionType);

        // Check that claims are also present
        String tokenString = DOM2Writer.nodeToString(token);
        assertTrue(tokenString.contains(providerResponse.getTokenId()));
        assertTrue(tokenString.contains(ClaimTypes.EMAILADDRESS.toString()));
        assertTrue(tokenString.contains(ClaimTypes.FIRSTNAME.toString()));
        assertTrue(tokenString.contains(ClaimTypes.LASTNAME.toString()));
    }

    private Element getSAMLAssertion(String assertionSamlVersion) throws Exception {
        TokenProvider samlTokenProvider = new SAMLTokenProvider();
        TokenProviderParameters providerParameters = createProviderParameters(assertionSamlVersion,
                STSConstants.BEARER_KEY_KEYTYPE, null);
        providerParameters.setPrincipal(new CustomTokenPrincipal("bob"));

        // Add Claims
        ClaimsManager claimsManager = new ClaimsManager();
        ClaimsHandler claimsHandler = new CustomClaimsHandler();
        claimsManager.setClaimHandlers(Collections.singletonList(claimsHandler));
        providerParameters.setClaimsManager(claimsManager);
        ClaimCollection claims = createClaims();
        providerParameters.setRequestedPrimaryClaims(claims);

        assertTrue(samlTokenProvider.canHandleToken(assertionSamlVersion));
        TokenProviderResponse providerResponse = samlTokenProvider.createToken(providerParameters);
        assertNotNull(providerResponse);
        assertTrue(providerResponse.getToken() != null && providerResponse.getTokenId() != null);

        return (Element) providerResponse.getToken();
    }

    private TokenProviderParameters createProviderParameters(
            String tokenType, String keyType, Object actAs) throws WSSecurityException {
        TokenProviderParameters parameters = new TokenProviderParameters();

        TokenRequirements tokenRequirements = new TokenRequirements();
        tokenRequirements.setTokenType(tokenType);

        if (actAs != null) {
            ReceivedToken actAsToken = new ReceivedToken(actAs);
            actAsToken.setState(STATE.VALID);
            tokenRequirements.setActAs(actAsToken);
        }
        parameters.setTokenRequirements(tokenRequirements);

        KeyRequirements keyRequirements = new KeyRequirements();
        keyRequirements.setKeyType(keyType);
        parameters.setKeyRequirements(keyRequirements);

        parameters.setPrincipal(new CustomTokenPrincipal("technical-user"));
        // Mock up message context
        MessageImpl msg = new MessageImpl();
        WrappedMessageContext msgCtx = new WrappedMessageContext(msg);
        parameters.setMessageContext(msgCtx);

        parameters.setAppliesToAddress("http://dummy-service.com/dummy");

        // Add STSProperties object
        StaticSTSProperties stsProperties = new StaticSTSProperties();
        Crypto crypto = CryptoFactory.getInstance(getEncryptionProperties());
        stsProperties.setSignatureCrypto(crypto);
        stsProperties.setSignatureUsername("sts");
        stsProperties.setCallbackHandler(new PasswordCallbackHandler());
        stsProperties.setIssuer("STS");
        parameters.setStsProperties(stsProperties);

        parameters.setEncryptionProperties(new EncryptionProperties());

        return parameters;
    }

    private Properties getEncryptionProperties() {
        Properties properties = new Properties();
        properties.put(
                "org.apache.wss4j.crypto.provider", "org.apache.wss4j.common.crypto.Merlin");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.password", "sts-passwd");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.file", "keys/sts.jks");

        return properties;
    }

    /**
     * Create a set of parsed Claims
     */
    private ClaimCollection createClaims() {
        ClaimCollection claims = new ClaimCollection();

        Claim claim = new Claim();
        claim.setClaimType(ClaimTypes.FIRSTNAME);
        claims.add(claim);

        claim = new Claim();
        claim.setClaimType(ClaimTypes.LASTNAME);
        claims.add(claim);

        claim = new Claim();
        claim.setClaimType(ClaimTypes.EMAILADDRESS);
        claims.add(claim);

        return claims;
    }

}