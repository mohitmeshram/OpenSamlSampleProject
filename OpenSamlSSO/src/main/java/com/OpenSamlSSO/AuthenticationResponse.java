package com.OpenSamlSSO;

public class AuthenticationResponse {
	
	private AuthenticationResponseType status;

    private String errorMessage;

    private String targetUrl;

    private String urlParams;

    private String enterpriseidfier;

    private String userName;

    public AuthenticationResponseType getStatus()
    {
        return status;
    }

    public void setStatus(AuthenticationResponseType status)
    {
        this.status = status;
    }

    public String getErrorMessage()
    {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage)
    {
        this.errorMessage = errorMessage;
    }

    public String getTargetUrl()
    {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl)
    {
        this.targetUrl = targetUrl;
    }

    public String getEnterpriseidfier()
    {
        return enterpriseidfier;
    }

    public void setEnterpriseidfier(String enterpriseidfier)
    {
        this.enterpriseidfier = enterpriseidfier;
    }

    public String getUserName()
    {
        return userName;
    }

    public void setUserName(String userName)
    {
        this.userName = userName;
    }

    public String getUrlParams()
    {
        return urlParams;
    }

    public void setUrlParams(String urlParams)
    {
        this.urlParams = urlParams;
    }

}
