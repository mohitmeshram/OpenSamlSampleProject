package com.OpenSamlSSO;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface IAuthClientHandler {
	
	  public AuthenticationResponse execute(HttpServletRequest request,
	            HttpServletResponse response);

}
