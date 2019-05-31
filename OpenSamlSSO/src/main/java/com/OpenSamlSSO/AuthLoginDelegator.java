package com.OpenSamlSSO;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthLoginDelegator {
	
	 private static final String SAML_RESPONSE_POST_PARAM_NAME = "SAMLResponse"; 
	
	 AuthenticationResponse authResponse= new AuthenticationResponse();
	 
	public void handleSSORequest(HttpServletRequest request,
            HttpServletResponse response) throws Exception
 {

		String samlResponse = request.getParameter(SAML_RESPONSE_POST_PARAM_NAME);

		if (samlResponse == null) {
			authResponse = SamlRequestHandler.execute(request, response);
		} else {
			System.out
					.println("SAML2Response received.  Invoking AssertionConsumerService");
			authResponse = SAMLSPResponseHandler.execute(request, response);
		}

		if (authResponse == null) {
			System.out.println("Response is NULL");
		}

		if (authResponse.getStatus() == AuthenticationResponseType.FAILURE) {
			System.out.println("Auth failure" + request + " " + response + ""
					+ authResponse.getErrorMessage());
		}

		if (authResponse.getStatus() == AuthenticationResponseType.SUCCESS) {
			
		}
		


	}
}
