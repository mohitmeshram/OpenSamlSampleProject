package com.OpenSamlSSO;


import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml.saml2.profile.impl.DecryptAssertions;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.encryption.ChainingEncryptedKeyResolver;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
//import org.springframework.jdbc.core.JdbcTemplate;

public class SAML2ReponseValidator {
	

    public SAML2ReponseValidator(EnterpriseConfig enterpriseConfig)
    {
        try
        {
            org.opensaml.DefaultBootstrap.bootstrap();
        }
        catch (Exception e)
        {
            System.out.println("Can not load saml classes"+e.getMessage());
        }

    }

	public static SAMLResponseContext validate(Response rsp) {
		
		//return null;
		
		SAMLResponseContext context=null;
        try
        {
            context = new SAMLResponseContext();
            //context.setEnterpriseId(enterpriseConfig.getEnterpriseIdfier());
            Signature signatureToValidate = rsp.getSignature();
            // get the id of the originating request
            // Look in the SAML Response to pull out the Subject information
            // Get the list of assertions
            java.util.List<Assertion> assertionsList = rsp.getAssertions();
            if (assertionsList == null)
            {
               /* SAMLSsoLogger
                        .logError(
                                logger,
                                "Validating the received Response: Assertion list is not found.",
                                null, context);
                context
                        .setErrorMsg(AuthenticationConstants.SSO_SAML_ASSERTION_LIST_EMPTY);*/
            	
            	context.setErrorMsg("Validating the received Response: Assertion list is not found.");
                return context;
            }
            int size = assertionsList.size();
            // Make sure at least one is present
            if (size > 0)
            {
                // Get the first one only
                Assertion assertion = (Assertion) assertionsList.get(0);
                if (null == assertion)
                {
                   /* SAMLSsoLogger
                            .logError(
                                    logger,
                                    "Validating the received Response: Assertion is not found.",
                                    null, context);
                    context
                            .setErrorMsg(AuthenticationConstants.SSO_SAML_ASSERTION_NULL);*/
                	
                	context.setErrorMsg("Validating the received Response: Assertion list is not found.");
                	
                    return context;
                }
                if (signatureToValidate == null)
                {
                   /* SAMLSsoLogger
                            .logError(
                                    logger,
                                    "Validating the received Response: SAML Response is not signed, checking whether Assertion is signed",
                                    null, context);*/
                	//context.setErrorMsg("Validating the received Response: SAML Response is not signed, checking whether Assertion is signed");
                    signatureToValidate = assertion.getSignature();
                    System.out.println("signatureToValidate :::"+signatureToValidate.toString());
                    if (signatureToValidate == null)
                    {
                        /*SAMLSsoLogger
                                .logError(
                                        logger,
                                        "Validating the received Response: SAML Response and Assertion, both are not signed, unable to locate the signature to validate.",
                                        null, context);
                        context
                                .setErrorMsg(AuthenticationConstants.SSO_SAML_SIGNATURE_NULL);*/
                    	context.setErrorMsg("Validating the received Response: SAML Response and Assertion, both are not signed, unable to locate the signature to validate.");
                        return context;
                    }
                }
                String enterpriseIdfier="nice",email="";
                List<Statement> listOfStatements = assertion.getStatements();
               /* if ((listOfStatements != null) && (!listOfStatements.isEmpty()))
                {
                    enterpriseIdfier = getEnterpriseIdfier(listOfStatements);
                    email=getAttributeValue(listOfStatements, EMAIL_ATTR);
                }*/
               // System.out.println("Validating the received Response: EnterpriseIdfier:"+ enterpriseIdfier);
                /*if (StringUtils.isBlank(enterpriseIdfier)
                        && null != enterpriseConfig)
                {
                    SAMLSsoLogger
                            .logError(
                                    logger,
                                    "Validating the received Response: Domain name is empty in assertion",
                                    null, context);
                    enterpriseIdfier = enterpriseConfig.getEnterpriseIdfier();
                }
                if (enterpriseIdfier == null
                        || enterpriseIdfier.trim().isEmpty())
                {
                    context.setErrorMsg(AuthenticationConstants.SSO_SAML_DOMAIN_NULL);
                    SAMLSsoLogger
                            .logError(
                                    logger,
                                    "Validating the received Response: Domain name is not found.",
                                    null, context);
                    return context;
                }
                enterpriseIdfier = enterpriseIdfier.trim();
                RequestContextHolder.setEnterpriseIdfier(enterpriseIdfier);*/
                
                
                Subject subject = assertion.getSubject();
                if (subject == null)
                {
                    /*SAMLSsoLogger
                            .logError(
                                    logger,
                                    "Validating the received Response: Assertion subject is not found.",
                                    null, context);
                    context
                            .setErrorMsg(AuthenticationConstants.SSO_SAML_SUBJECT_NULL);*/
                	context.setErrorMsg("Validating the received Response: Assertion subject is not found.");
                    return context;
                }
                
                Status responseStatus = rsp.getStatus();
                StatusCode statusCode = responseStatus.getStatusCode();
                String statusValue = statusCode.getValue();

                if (!statusValue.equals("success")) {
                    System.out.println("SAML Response did not have a success status, instead status was {}"+statusValue);
                	context.setErrorMsg("SAML Response did not have a success status");
                }    
                
                NameID nameID = subject.getNameID();
                
                if (nameID == null && StringUtils.isBlank(email))
                {
                    /*SAMLSsoLogger
                            .logError(
                                    logger,
                                    "Validating the received Response: NameID is not found.",
                                    null, context);
                    context
                            .setErrorMsg(AuthenticationConstants.SSO_SAML_NAMEID_NULL);*/
                	context.setErrorMsg("Validating the received Response: NameID is not found.");
                    return context;
                }
                String username =null;
                if (null != nameID)
                {
                    username = nameID.getValue();
                    System.out.println("**************************************** USERNAME ****************************************	" + username);
                }
                if (StringUtils.isBlank(username)
                        && !StringUtils.isBlank(email))
                {
                    username = email;
                    System.out.println("**************************************** USERNAME/EMAIL ****************************************	" + username);
                }
                context.setUserName(username);
                
                Issuer issuer = assertion.getIssuer();
                
                
                if (issuer == null)
                {
                    /*SAMLSsoLogger
                    .logError(
                            logger,"Validating the received Response: Assertion issuer is null",null, context);
                    context.setErrorMsg(AuthenticationConstants.SSO_SAML_ISSUER_NOT_SET);*/
                	System.out.println("Validating the received Response: Assertion issuer is null");
                    return context;
                }
                String issuerValue = issuer.getValue();
               
                System.out.println("Assertion:Issuer Value:" + issuerValue);
  
                if ((issuerValue == null) || (issuerValue.isEmpty()))
                {
                    /*SAMLSsoLogger
                    .logError(
                            logger,"Validating the received Response: Assertion issuer value is null",null, context);
                    context.setErrorMsg(AuthenticationConstants.SSO_SAML_ISSUER_NOT_SET);*/
                	System.out.println("Validating the received Response: Assertion issuer  value is null");
                    return context;
                }
                
                
                Assertion assertion1=getAssertion(rsp,null);
                           
                boolean isValidAssertion = isValidAssertion(assertion, context);
                System.out.println("isValidAssertion:"+isValidAssertion);
                if (!isValidAssertion)
                {
                    /*SAMLSsoLogger
                            .logError(
                                    logger,
                                    "Validating the received Response: SAML condition on time ('NotOnOrAfter'/'NotBefore') is failed.",
                                    null, context);*/
                	System.out.println("Validating the received Response: SAML condition on time ('NotOnOrAfter'/'NotBefore') is failed");
                    return context;
                }
                
                String certificatePath = "C:\\SSOSAMLDEMO\\OpenSamlSSO\\src\\main\\resources\\test.cer";
                certificatePath = certificatePath.trim();
                System.out.println("certificatePath :: " + certificatePath);
                X509Certificate entityCert = getCertificate(certificatePath);
                if (entityCert == null)
                {
                    System.out.println("Validating the received Response: Unable to retrieve Certificate from the uploaded certficate path-("
                                    + certificatePath);
                    context.setErrorMsg("SSO_SAML_INVALID_CERT_FROM_PATH");
                    return context;
                }
                BasicX509Credential cred = new BasicX509Credential();
                cred.setEntityCertificate(entityCert);
                cred.setPublicKey(entityCert.getPublicKey());
                
                System.out.println("entityCert.getPublicKey() :: " + entityCert.getPublicKey());
                SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
                try
                {
                    profileValidator.validate(signatureToValidate);
                }
                catch (ValidationException e)
                {
                	System.out.println("SAMLSignatureProfileValidator throws exception");
                	System.out.println(e.getMessage());
                }
                SignatureValidator validator = new SignatureValidator(cred);
                validator.validate(signatureToValidate);
                context.setEnterpriseId(enterpriseIdfier);
                context.setUserName(username);
                return context;
                
            }
            
            else
            {
            	System.out.println("Validating the received Response: Assertion list size is zero."+context);
                context.setErrorMsg("SSO_SAML_ASSERTION_LIST_EMPTY");
                return context;
            }
        }
        
        catch (Exception e)
        {
            if(null==context)
            {
            context = new SAMLResponseContext();
            }
            /*context.setErrorMsg(AuthenticationConstants.SSO_SAML_RESP_VALIDATION_FAILED);
            SAMLSsoLogger.logError(logger,
                    "Validating the received Response: Validation error", e,
                    context);
            if (null != e && e instanceof CoreAuthenticationException)
            {
                String messageCode = ((CoreAuthenticationException) e)
                        .getMessageCode();
                if (null != messageCode)
                {
                    context.setErrorMsg(messageCode);
                }
            }*/
            return context;
        }

	}

	
	  private static boolean isValidAssertion(Assertion assertion, SAMLResponseContext context)
	    {
	        Conditions conditions = assertion.getConditions();
	        if (conditions == null)
	        {
	            return false;
	        }
	        DateTime notBeforeDateTime = conditions.getNotBefore();
	        DateTime notOnOrAfterDateTime = conditions.getNotOnOrAfter();
	        DateTime currentDateTime = new DateTime();
	        System.out.println("Validating the received Response: Time Condition: 'NotBefore' set as:"+ notBeforeDateTime);
	     
	        System.out.println("Validating the received Response: Time Condition: 'NotOnOrAfter' set as :"+ notOnOrAfterDateTime);
	        System.out.println("Validating the received Response:  Response received time on  Server is :"+ currentDateTime);
	        if (notBeforeDateTime == null && notOnOrAfterDateTime == null)
	        {
	        	 System.out.println("Either of 'NotBefore' Time/'NotOnOrAfter' Time is null, so time validation by passed."+context);
	            return true;
	        }
	        if (currentDateTime == null)
	        {     context.setErrorMsg("SSO SAML Response validation failed");
	        	 System.out.println("Validating the received Response: Unable to get the Server time.");
	            return false;
	        }
	        Calendar notBeforeCalendar = Calendar.getInstance();
	        Calendar notOnOrAfterCalendar = Calendar.getInstance();
	        Calendar currentCalendar = Calendar.getInstance();
	        currentCalendar.setTimeInMillis(currentDateTime.getMillis());
	        if (null != notBeforeDateTime)
	        {
	            notBeforeCalendar.setTimeInMillis(notBeforeDateTime.getMillis());
	            if (currentCalendar.before(notBeforeCalendar))
	            {
	                context.setErrorMsg("SSO SAML NotBefore condition failed");
	           System.out.println("Validating the received Response: SAML Response 'NotBefore' condition failed, Response received time on Satmetrix Server was before the 'NotBefore' time set in SAML Response.");
	                return false;
	            }
	        }
	        if (null != notOnOrAfterDateTime)
	        {
	            notOnOrAfterCalendar.setTimeInMillis(notOnOrAfterDateTime
	                    .getMillis());
	            if (currentCalendar.after(notOnOrAfterCalendar))
	            {
	                context.setErrorMsg("SSO SAML NOTAFTER condition failed");
	                System.out.println("Validating the received Response: SAML Response 'NotOnOrAfter' condition failed, Response received time on Satmetrix Server was after the 'NotOnOrAfter' time set in SAML Response.");
	                return false;
	            }
	        }
	        return true;
	    }
	
	  public static X509Certificate getCertificate(String fileName)
	            throws Exception
	    {
	        try
	        {
	            InputStream ins = getInputStream(fileName);
	            if (ins != null)
	            {
	                CertificateFactory cf = CertificateFactory.getInstance("X.509");
	                Certificate cert = cf.generateCertificate(ins);
	                return (X509Certificate) cert;
	            }
	            return null;
	        }
	        catch (Exception e)
	        {
	           System.out.println("Could not create certificate object from file: "+e);
	           e.printStackTrace();
	         
	        }
			return null;
	    }
	  
	  private static InputStream getInputStream(String fileName)
	    {
	        try
	        {
	            return new FileInputStream(fileName);
	        }

	        catch (Exception e)
	        {
	            return null;
	        }
	    }
	  
	  
	  protected static boolean isAssertionEncrypted(org.opensaml.saml2.core.Response samlResponse) {
	        if (samlResponse.getEncryptedAssertions() != null && samlResponse.getEncryptedAssertions().size() != 0) {
	            return true;
	        }
	        return false;
	    }

	    protected static Assertion decryptAssertion(EncryptedAssertion encryptedAssertion, KeyStore.PrivateKeyEntry keystoreEntry) {
	        BasicX509Credential decryptionCredential = new BasicX509Credential();

	        decryptionCredential.setPrivateKey(keystoreEntry.getPrivateKey());

	        StaticKeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(decryptionCredential);

	        ChainingEncryptedKeyResolver keyResolver = new ChainingEncryptedKeyResolver();
	        keyResolver.getResolverChain().add(new InlineEncryptedKeyResolver());
	        keyResolver.getResolverChain().add(new EncryptedElementTypeEncryptedKeyResolver());
	        keyResolver.getResolverChain().add(new SimpleRetrievalMethodEncryptedKeyResolver());

	        Decrypter decrypter = new Decrypter(null, resolver, keyResolver);
	        decrypter.setRootInNewDocument(true);
	        Assertion assertion = null;
	        try {
	            assertion = decrypter.decrypt(encryptedAssertion);
	        } catch (DecryptionException e) {
	            System.out.println("Unable to decrypt SAML assertion"+null);
	        }
	        return assertion;
	    }

	    
	    public static Assertion getAssertion(org.opensaml.saml2.core.Response samlResponse, KeyStore.PrivateKeyEntry keystoreEntry) {
	        Assertion assertion;
	        if (isAssertionEncrypted(samlResponse)) {
	            assertion = decryptAssertion(samlResponse.getEncryptedAssertions().get(0), keystoreEntry);
	        } else {
	            assertion = samlResponse.getAssertions().get(0);
	        }
	        return assertion;
	    }


}

