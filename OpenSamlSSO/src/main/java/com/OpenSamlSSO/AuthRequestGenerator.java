package com.OpenSamlSSO;

import java.util.Random;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;


/**
 * @author mmeshram
 *
 */
public class AuthRequestGenerator {
	
	private static XMLObjectBuilderFactory xmlObjectBuilderFactory;
	
	public AuthRequestGenerator()
	{
		
	}
	    static
	    {
	        try
	        {
	            DefaultBootstrap.bootstrap();
	             xmlObjectBuilderFactory = Configuration.getBuilderFactory();
	        }
	        catch (ConfigurationException e)
	        {
	            System.out.println();
	        }
	    }
	
	public static AuthnRequest generateAuthnRequest()
		      throws Exception {

		 XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		    
		    AuthnRequestBuilder authnRequestBuilder = (AuthnRequestBuilder) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME); 
		    AuthnRequest authnRequest = authnRequestBuilder.buildObject(); 
		    
		    //authnRequest.setForceAuthn(true);
		    authnRequest.setForceAuthn(false);
		   //authnRequest.setSignature(newSignature);
		    authnRequest.setIsPassive(false);
		    authnRequest.setIssueInstant(new DateTime());
		    //authnRequest.setDestination("https://www.google.com/");
		    authnRequest.setDestination("http://10.128.174.51:8080/AM-eval-5.5.1/SSORedirect/metaAlias/idp1");
		    //authnRequest.setDestination("https://nice-mohitmeshram.okta.com/app/niceorg621633_opensamltest_1/exkm5g4ilNtnEUDtI356/sso/saml");
		    
		    //authnRequest.setProtocolBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		    authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		    //authnRequest.setAssertionConsumerServiceURL("http://openam.nice.com:8080/AM-eval-5.5.1/SSORedirect/metaAlias/idp3");
		    authnRequest.setAssertionConsumerServiceURL("http://localhost:8080/test");
		    authnRequest.setID(generateId());

		    Issuer issuer = ((IssuerBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME)).buildObject();
		    //issuer.setValue("pallavi_sp_entity_id_1");
		    issuer.setValue("POC_SP");
		    authnRequest.setIssuer(issuer);

		    NameIDPolicy nameIDPolicy = ((NameIDPolicyBuilder) builderFactory.getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME)).buildObject();
		    nameIDPolicy.setSPNameQualifier("POC_SP");
		    nameIDPolicy.setAllowCreate(true);
		    nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");

		    authnRequest.setNameIDPolicy(nameIDPolicy);

		    RequestedAuthnContext requestedAuthnContext = ((RequestedAuthnContextBuilder) builderFactory.getBuilder(RequestedAuthnContext.DEFAULT_ELEMENT_NAME)).buildObject();
		    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

		    AuthnContextClassRef authnContextClassRef = ((AuthnContextClassRefBuilder) builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME)).buildObject();
		    authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

		    requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
		    authnRequest.setRequestedAuthnContext(requestedAuthnContext);

		    return authnRequest;
		  }
	
	   public static Endpoint getEndpoint()
	    {
	        SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) xmlObjectBuilderFactory
	                .getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
	        Endpoint samlEndpoint = endpointBuilder.buildObject();
	        samlEndpoint.setLocation("http://10.128.174.51:8080/AM-eval-5.5.1/SSORedirect/metaAlias/idp1");
	        //samlEndpoint.setLocation("https://nice-mohitmeshram.okta.com/app/niceorg621633_opensamltest_1/exkm5g4ilNtnEUDtI356/sso/saml");
	        
	        //samlEndpoint.setResponseLocation("http://cust1.demo:80/");
	        samlEndpoint.setResponseLocation("http://localhost:8080/test");
	        return samlEndpoint;
	    }
	   
	   private static String generateId()
	    {
	        return "_"
	                + Integer.toHexString(new Random().nextInt(Integer.MAX_VALUE))
	                + "-"
	                + Integer.toHexString(new Random().nextInt(Integer.MAX_VALUE));
	    }

}
