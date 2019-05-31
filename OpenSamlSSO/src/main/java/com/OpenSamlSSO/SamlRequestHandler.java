package com.OpenSamlSSO;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SamlRequestHandler /*implements IAuthClientHandler*/{

	   private static final String SAML_REQUEST_POST_PARAM_NAME = "SAMLRequest"; 
	   
	
	public static AuthenticationResponse execute(HttpServletRequest request,
			HttpServletResponse response) {
		
		AuthenticationResponse authResponse = new AuthenticationResponse();
		try
		{
			 //String domain = request.getParameter(AuthenticationConstants.DOMAIN_KEY);
			String domain="nice";
			 //String returnUrl = request.getParameter(AuthenticationConstants.TARGET_URL);
			 String returnUrl="https://www.google.com/";
            // StringBuffer relayBuffer = new StringBuffer(AuthenticationConstants.TARGET_URL + "=" + returnUrl);
			 //StringBuffer relayBuffer =new StringBuffer("https://www.google.com/");
			 StringBuffer relayBuffer =new StringBuffer("http://localhost:8080/test");
             
             long enterpriseId;
             EnterpriseConfig enterpriseConfig= new EnterpriseConfig();
             
             enterpriseId =1;
		     SAMLMessageHandler.doEncodeAndSubmit(enterpriseConfig,
                     relayBuffer.toString(), response);
		     System.out.println("Sent SAML request for" + domain + "("
                     + enterpriseId + ")");
		     //authResponse.setStatus(AuthenticationResponseType.SUCCESS);
			 
			/*AuthnRequest authnRequest = AuthRequestGenerator.generateAuthnRequest();
			String relayState = request.getParameter(RelayState.DEFAULT_ELEMENT_LOCAL_NAME);
			SAMLMessageHandler.doEncodeAndSubmit(authnRequest,response,relayState);*/
			 
		     
		}
		catch(Exception e)
		{
			System.out.println("Exception occured"+e);
			authResponse.setStatus(AuthenticationResponseType.FAILURE);
            return authResponse;
		}
		return authResponse;
	}
	
	
	
	
	
}
