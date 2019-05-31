package com.OpenSamlSSO;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.opensaml.common.binding.BasicSAMLMessageContext;

import org.opensaml.saml2.binding.decoding.BaseSAML2MessageDecoder;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.encoding.BaseSAML2MessageEncoder;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;

public class SAMLMessageHandler {
	
	
	 private static Map<String, BaseSAML2MessageEncoder> bindInHandlerMap = new HashMap<String, BaseSAML2MessageEncoder>();
	    /* Out Bind handler should be registered here */
	    private static Map<String, BaseSAML2MessageDecoder> bindOutHandlerMap = new HashMap<String, BaseSAML2MessageDecoder>();
	    private static final String POST_BINDING_TMP = "/com/satmetrix/core/server/security/sso/saml/templates/saml2-post-binding.vm";
	    private static final String RELAY_STATE = "RelayState";
	    static
	    {
	        VelocityEngine velocityEngine = new VelocityEngine();
	        velocityEngine.setProperty(RuntimeConstants.ENCODING_DEFAULT, "UTF-8");
	        velocityEngine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
	        velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER,
	                "classpath");
	        velocityEngine
	                .setProperty("classpath.resource.loader.class",
	                        "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
	        try
	        {
	            velocityEngine.init();
	            System.out.println("Velocity Engine initialized");

	        }
	        catch (Exception e)
	        {
	        	System.out.println("Failed to start velocity enginge"+e.getMessage());
	        }
	        bindInHandlerMap.put("POST", new HTTPPostEncoder(velocityEngine,
	                POST_BINDING_TMP));
	        bindOutHandlerMap.put("POST", new HTTPPostDecoder());
	    }

	
	
	public static void doEncodeAndSubmit(EnterpriseConfig enterpriceConfig,String relayState,HttpServletResponse response) throws Exception {
          
           //Creating Auth request
           AuthnRequest authnRequest = AuthRequestGenerator.generateAuthnRequest();
           
           System.out.println("Auth request is :"+authnRequest);
   	     // Creating IDP endpoint
		 Endpoint endpoint = AuthRequestGenerator.getEndpoint();
		 
	        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
	     
	        BasicSAMLMessageContext msgContext = createMessageContext(authnRequest,endpoint, response, relayState);
	        System.out.println("Redirecting to IDP");
	        encoder.encode(msgContext);
	        System.out.println("Request submitted successfully");
		 
	}	
	
	 private static BasicSAMLMessageContext createMessageContext(
	            AuthnRequest samlMessage, Endpoint samlEndpoint,
	            HttpServletResponse response, String relayState)
	    {

	        HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(
	                response, false);
	        BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
	        messageContext.setOutboundMessageTransport(outTransport);
	        messageContext.setPeerEntityEndpoint(samlEndpoint);
	        messageContext.setOutboundSAMLMessage(samlMessage);
	        messageContext.setRelayState(relayState);
	        return messageContext;
	    }
	 
	 private static BaseSAML2MessageEncoder getEncoder(String key)
	    {
	        return bindInHandlerMap.get(key);
	    }

	    private static BaseSAML2MessageDecoder getDecoder(String key)
	    {
	        return bindOutHandlerMap.get(key);
	    }
	    
	    public static SAMLResponseContext doDecodeAndValidate(
	            HttpServletRequest request, EnterpriseConfig enterpriseConfig)
	            throws Exception
	    {
	        System.out.println("Response Validation starts");

	        BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
	        messageContext
	                .setInboundMessageTransport(new HttpServletRequestAdapter(
	                        request));
	        /*BaseSAML2MessageDecoder decoder = getDecoder(enterpriseConfig
	                .getOutbind());*/
	       // HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
	        HTTPPostDecoder decoder = new HTTPPostDecoder();
	        
	        if (decoder == null)
	        {
	            System.out.println("Decoder is null. Please check the saml_conf.xml");
	        }
	        decoder.decode(messageContext);
	        Response response = (Response) messageContext.getInboundSAMLMessage();
	        SAMLResponseContext context = null;
	        try {
	        	context = SAML2ReponseValidator.validate(response);
	        	String relayState = request.getParameter(RELAY_STATE);
		        context.setRelayStateUrl(relayState);
		        System.out.println("Response Validation ends");
		        return context;
	        }catch(Exception e) {
	        	e.printStackTrace();
	        }
	        
	        return context;
	    }
	 

		
}
