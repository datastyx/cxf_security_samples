package demo.wssec.sts;

import java.util.List;

import org.apache.cxf.sts.request.ReceivedToken;
import org.apache.cxf.sts.request.TokenRequirements;
import org.apache.cxf.sts.token.provider.ActAsAttributeStatementProvider;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.cxf.ws.security.sts.provider.STSException;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.AttributeBean;
import org.apache.wss4j.common.saml.bean.AttributeStatementBean;
import org.opensaml.core.xml.XMLObject;
import org.w3c.dom.Element;

public class CustomActAsAttributeStatementProvider extends ActAsAttributeStatementProvider {

    /**
     * Get an AttributeStatementBean using the given parameters.
     */
    @Override
    public AttributeStatementBean getStatement(TokenProviderParameters providerParameters) {
        AttributeStatementBean attrBean = super.getStatement(providerParameters);

        TokenRequirements tokenRequirements = providerParameters.getTokenRequirements();
        ReceivedToken actAs = tokenRequirements.getActAs();
        try {
            if (actAs != null) {
                List<AttributeBean> attributeList = attrBean.getSamlAttributes();

                if (actAs.getToken() instanceof Element) {
                    SamlAssertionWrapper wrapper = new SamlAssertionWrapper((Element) actAs.getToken());

                    // Check for other ActAs attributes here + add them in
                    if (wrapper.getSaml2() != null) {
                        for (org.opensaml.saml.saml2.core.AttributeStatement attributeStatement : wrapper.getSaml2()
                                .getAttributeStatements()) {
                            for (org.opensaml.saml.saml2.core.Attribute attribute : attributeStatement
                                    .getAttributes()) {
                                for (XMLObject attributeValue : attribute.getAttributeValues()) {
                                    AttributeBean parameterBean = new AttributeBean();
                                    parameterBean.setQualifiedName(attribute.getName());
                                    parameterBean.setNameFormat(attribute.getNameFormat());
                                    Element attributeValueElement = attributeValue.getDOM();
                                    String text = attributeValueElement.getTextContent();
                                    parameterBean.addAttributeValue(text);
                                    attributeList.add(parameterBean);
                                }
                            }
                        }
                    } else if (wrapper.getSaml1() != null) {
                        for (org.opensaml.saml.saml1.core.AttributeStatement attributeStatement : wrapper.getSaml1()
                                .getAttributeStatements()) {
                            for (org.opensaml.saml.saml1.core.Attribute attribute : attributeStatement
                                    .getAttributes()) {
                                for (XMLObject attributeValue : attribute.getAttributeValues()) {
                                    AttributeBean parameterBean = new AttributeBean();
                                    parameterBean.setQualifiedName(
                                            attribute.getAttributeNamespace() + '/' + attribute.getAttributeName());
                                    Element attributeValueElement = attributeValue.getDOM();
                                    String text = attributeValueElement.getTextContent();
                                    parameterBean.addAttributeValue(text);
                                    attributeList.add(parameterBean);
                                }
                            }
                        }
                    }
                }
                attrBean.setSamlAttributes(attributeList);
            }
        } catch (WSSecurityException ex) {
            throw new STSException(ex.getMessage(), ex);
        }
        return attrBean;
    }

}