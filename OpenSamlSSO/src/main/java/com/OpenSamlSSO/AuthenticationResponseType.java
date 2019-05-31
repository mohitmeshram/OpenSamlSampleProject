package com.OpenSamlSSO;

public enum AuthenticationResponseType {
	
	 SUCCESS("success", 1), FAILURE("failure", 2), NO_RESPONSE("noresponse", 3);
	    String name;
	    int id;

	    AuthenticationResponseType(String name, int id)
	    {
	        this.name = name;
	        this.id = id;
	    }

}
