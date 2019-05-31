package com.OpenSamlSSO;

public class SAMLResponseContext {
	
	 private String relayStateUrl;
	    private String userName;
	    private String errorMsg;
	    private String enterpriseId;
	    private String serviceUrl;
	    private StringBuffer logMessage;

	    public String getRelayStateUrl()
	    {
	        return relayStateUrl;
	    }

	    public void setRelayStateUrl(String relayStateUrl)
	    {
	        this.relayStateUrl = relayStateUrl;
	    }

	    public String getUserName()
	    {
	        return userName;
	    }

	    public void setUserName(String userName)
	    {
	        this.userName = userName;
	    }

	    public String getErrorMsg()
	    {
	        return errorMsg;
	    }

	    public void setErrorMsg(String errorMsg)
	    {
	        this.errorMsg = errorMsg;
	    }

	    public String getEnterpriseId()
	    {
	        return enterpriseId;
	    }

	    public void setEnterpriseId(String enterpriseId)
	    {
	        this.enterpriseId = enterpriseId;
	    }

	    public String getServiceUrl()
	    {
	        return serviceUrl;
	    }

	    public void setServiceUrl(String serviceUrl)
	    {
	        this.serviceUrl = serviceUrl;
	    }

	    public StringBuffer getLogMessage()
	    {
	        return logMessage;
	    }

	    public void setLogMessage(StringBuffer logMessage)
	    {
	        this.logMessage = logMessage;
	    }


}
