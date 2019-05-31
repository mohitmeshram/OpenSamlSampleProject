package com.OpenSamlSSO;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.codec.binary.Base64;

import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.ecp.RelayState;

public class SAMLSPResponseHandler {
	
	 private static final String SAML_RESPONSE_POST_PARAM_NAME = "SAMLResponse"; 
	 public static AuthenticationResponse execute(HttpServletRequest request,
	            HttpServletResponse response)
	    {
        System.out.println("Inside SAML SP Response Handler");
        
        String username = "";
        
        try
        {
            org.opensaml.DefaultBootstrap.bootstrap();
        }
        catch (Exception e)
        {
            System.out.println("Bootstrap initilization error."+e.getMessage());
            
        }
 
        AuthenticationResponse authResponse = new AuthenticationResponse();
    	String samlResponse = request
				.getParameter(SAML_RESPONSE_POST_PARAM_NAME);
        
        SAMLResponseContext context=null;
        try
        {
            String relayStateUrl = request
                    .getParameter(RelayState.DEFAULT_ELEMENT_LOCAL_NAME);
            if (relayStateUrl.isEmpty())
            {
               System.out.println("Relay State URL is empty.");
                authResponse.setStatus(AuthenticationResponseType.FAILURE);
                return authResponse;
            }
          

            EnterpriseConfig enterpriseConfig = new EnterpriseConfig();
            String domain=enterpriseConfig.getEnterpriseIdfier();
            if(null!=domain)
            {
                domain=domain.trim().toLowerCase();
            }
            if (enterpriseConfig.isSamlEnabled())
            {
                System.out.println("SAML SSO enabled for Domain : " + domain);
                // String relayState = request.getParameter(TARGET_URL_KEY);
                try {
                	context = SAMLMessageHandler
                            .doDecodeAndValidate(request, enterpriseConfig);
                }catch(Exception e) {
                	e.printStackTrace();
                }
                
                
                if (!StringUtils.isEmpty(context.getErrorMsg()))
                {
                   
                    System.out.println("SAML Response Validation failed: "+ context);
                    authResponse.setErrorMessage(context.getErrorMsg());
                    authResponse.setStatus(AuthenticationResponseType.FAILURE);
                    authResponse.setEnterpriseidfier(domain);
                    authResponse.setUserName(context.getUserName());
                }
                else
                {
                    authResponse.setStatus(AuthenticationResponseType.SUCCESS);
                    try
                    {
                       username = context.getUserName();
                       System.out.println("Username : " + username);
                    }
                    catch (Exception ex)
                    {
                   System.out.println("Failed to Validate the SAML response"+ex);
                   System.out.println("Failed to Validate the SAML response for context"+context);
                        authResponse
                                .setErrorMessage("SSO AUTH invalid request");
                        authResponse
                                .setStatus(AuthenticationResponseType.FAILURE);
                    }
                }
            }
            else
            {
                System.out.println("SAML SSO not enabled for the domain."+ context);
                authResponse
                        .setErrorMessage("SSO not enabled");
                authResponse.setStatus(AuthenticationResponseType.FAILURE);
            }
            if (null != authResponse
                    && AuthenticationResponseType.SUCCESS != authResponse
                            .getStatus())
            {
            
                handleErrorMessage(authResponse, relayStateUrl,samlResponse,
                        context);
            }
            return authResponse;
        }
        catch (Exception e)
        {
            System.out.println("Exception while validating the SAML Response"+e.getMessage());
            authResponse
                    .setErrorMessage("SSO auth invalid request");
            authResponse.setStatus(AuthenticationResponseType.FAILURE);
        }
        return authResponse;
        
	    }
	 
	 
	 private static void handleErrorMessage(AuthenticationResponse authResponse,
	            String relayStateUrl, String samlResponse,
	            SAMLResponseContext context)
	    {
	      
	        StringBuffer msg = new StringBuffer("SAML Single Sign on failed:")
	                .append("\n-----------------------------\n")
	                .append("Domain :")
	                .append(authResponse.getEnterpriseidfier())
	                .append("\n")
	                .append("User :")
	                .append(authResponse.getUserName())
	                .append("\n\n")
	                .append("\n\nRelaystate received:")
	                .append("\n--------------------\n")
	                .append(relayStateUrl)
	                .append("\n\n")
	                .append("SAMLResponse received:")
	                .append("\n--------------------\n")
	                .append(decodeAuthnResponse(samlResponse)).append("\n----------");
	        System.out.println("Decoded Response:::"+msg);

	    }
	 
	 private static String decodeAuthnResponse(String samlResponse)
	    {
	        try
	        {
	            if (null != samlResponse)
	            {
	                Base64 base64Decoder = new Base64();
	                byte[] xmlBytes = samlResponse.getBytes("UTF-8");
	                byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);
	                String value = new String(base64DecodedByteArray, "UTF-8");
	                return value;
	            }
	        }
	        catch (Exception e)
	        {
	            System.out.println("Decoding saml response failed"+e.getMessage());
	        }
	        return samlResponse;
	    }

}
