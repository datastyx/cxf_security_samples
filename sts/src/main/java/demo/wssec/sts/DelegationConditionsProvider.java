package demo.wssec.sts;

import java.time.Instant;
import java.util.Arrays;

import org.apache.cxf.sts.request.ReceivedToken;
import org.apache.cxf.sts.request.TokenRequirements;
import org.apache.cxf.sts.token.provider.DefaultConditionsProvider;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.cxf.ws.security.sts.provider.model.secext.UsernameTokenType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.bean.DelegateBean;
import org.apache.wss4j.common.saml.bean.NameIDBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

public class DelegationConditionsProvider extends DefaultConditionsProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(DelegationConditionsProvider.class);

    /**
     * Get a ConditionsBean object.
     */
    @Override
    public ConditionsBean getConditions(TokenProviderParameters providerParameters) {
        ConditionsBean newConditions = super.getConditions(providerParameters);

        TokenRequirements tokenRequirements = providerParameters.getTokenRequirements();
        ReceivedToken actAs = tokenRequirements.getActAs();
        if (actAs != null) {
            DelegateBean delegateBean = new DelegateBean();
            delegateBean.setDelegationInstant(Instant.now());
            NameIDBean nameIDBean = new NameIDBean();
            nameIDBean.setNameValue(actAs.getPrincipal().getName());
            delegateBean.setNameIDBean(nameIDBean);
            newConditions.setDelegates(Arrays.asList(delegateBean));

            if (!actAs.isUsernameToken() && !actAs.isBinarySecurityToken()) {
                Element token = (Element) actAs.getToken();

                try {
                    SamlAssertionWrapper assertion = new SamlAssertionWrapper(token);
                    if (assertion.getSaml2() != null) {
                        assertion.getSaml2().getSubject().getSubjectConfirmations().forEach(subjectConf -> {
                            delegateBean.setConfirmationMethod(subjectConf.getMethod());
                        });
                    } else if (assertion.getSaml1() != null) {
                        assertion.getSaml1().getSubjectStatements().forEach(subjectStatement -> {
                            subjectStatement.getSubject().getSubjectConfirmation().getConfirmationMethods().forEach(confirmationMethod ->{
                                delegateBean.setConfirmationMethod(confirmationMethod.getConfirmationMethod());
                            });
                            
                        });
                    }

                } catch (WSSecurityException e) {
                    LOGGER.error(
                            "Trying to add delagator confirmation method to token failed :" + e.getLocalizedMessage(),
                            e);
                }
            }
        }

        return newConditions;
    }

}
