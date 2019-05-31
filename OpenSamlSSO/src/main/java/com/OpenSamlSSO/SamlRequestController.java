package com.OpenSamlSSO;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

//@RestController
//@RequestMapping("/SS0")
@RestController
public class SamlRequestController {
	
	@RequestMapping("/testSaml")
public void testSaml(HttpServletRequest request,
        HttpServletResponse response) throws Exception
{
		
		String samlResponse = request.getParameter("SAMLResponse");
		System.out.println("SAMLResponse: " + samlResponse);
		System.out.println("Received saml response !!!");

			AuthLoginDelegator authLoginDelegator =new AuthLoginDelegator();
			authLoginDelegator.handleSSORequest(request, response);
	
	
}
	
	@RequestMapping("/test")
public void Redirected(HttpServletRequest request,
        HttpServletResponse response) throws Exception
{
		
	System.out.println("Redirected after response validating/authenticated");
	String samlResponse = request.getParameter("SAMLResponse");
	 System.out.println("SAMLResponse: " + samlResponse);
	 if (samlResponse !=null) {
		 AuthLoginDelegator authLoginDelegator =new  AuthLoginDelegator(); 
		 authLoginDelegator.handleSSORequest(request, response);
			  } 
	
}
	
	/*
	 * @RequestMapping(value="/test" , method=RequestMethod.POST) public void
	 * responseHandler(HttpServletRequest request,HttpServletResponse response)
	 * throws Exception {
	 * 
	 * String samlResponse = request.getParameter("SAMLResponse");
	 * System.out.println("SAMLResponse: " + samlResponse);
	 * System.out.println("Received saml response !!!");
	 * 
	 * if (samlResponse !=null) { AuthLoginDelegator authLoginDelegator =new
	 * AuthLoginDelegator(); authLoginDelegator.handleSSORequest(request, response);
	 * } }
	 */
	
	
	
	

}
