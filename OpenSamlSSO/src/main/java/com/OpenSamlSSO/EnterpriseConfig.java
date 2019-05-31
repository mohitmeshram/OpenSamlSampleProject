package com.OpenSamlSSO;

public class EnterpriseConfig {
	
	
	 private String enterpriseIdfier;

	    private long enterpriseId;

	    private String acsUrl;

	    private String idpUrl;

	    private boolean isSamlEnabled;

	    private String inbind;

	    private String outbind;

	    private String certificatePath;

	    public EnterpriseConfig()
	    {

	        this.enterpriseIdfier = "nice";
	        this.enterpriseId = enterpriseId;
	        String acsUrl = "http://openam.nice.com:8080/AM-eval-5.5.1/SSORedirect/metaAlias/idp3";
	        this.acsUrl = acsUrl;

	        String idpUrl = "";
	        this.idpUrl = idpUrl;

	        String isSamlEnabled = "Y";
	        this.isSamlEnabled = ("Y").equalsIgnoreCase(isSamlEnabled);

	        String inBind = "POST";
	        this.inbind = inBind;

	        String outBind = "POST";
	        this.outbind = outBind;

	        String certPath ="";
	        this.certificatePath = certPath;

	    }

	    public String getAcsUrl()
	    {
	        return acsUrl;
	    }

	    public void setAcsUrl(String acsUrl)
	    {
	        this.acsUrl = acsUrl;
	    }

	    public String getIdpUrl()
	    {
	        return idpUrl;
	    }

	    public void setIdpUrl(String idpUrl)
	    {
	        this.idpUrl = idpUrl;
	    }

	    public boolean isSamlEnabled()
	    {
	        return isSamlEnabled;
	    }

	    public void setSamlEnabled(boolean isSamlEnabled)
	    {
	        this.isSamlEnabled = isSamlEnabled;
	    }

	    public String getInbind()
	    {
	        return inbind;
	    }

	    public void setInbind(String inbind)
	    {
	        this.inbind = inbind;
	    }

	    public String getOutbind()
	    {
	        return outbind;
	    }

	    public void setOutbind(String outbind)
	    {
	        this.outbind = outbind;
	    }

	    public String getEnterpriseIdfier()
	    {
	        return enterpriseIdfier;
	    }

	    public void setEnterpriseIdfier(String enterpriseIdfier)
	    {
	        this.enterpriseIdfier = enterpriseIdfier;
	    }

	    public long getEnterpriseId()
	    {
	        return enterpriseId;
	    }

	    public void setEnterpriseId(long enterpriseId)
	    {
	        this.enterpriseId = enterpriseId;
	    }

	    public String getCertificatePath()
	    {
	        return certificatePath;
	    }

	    public void setCertificatePath(String certificatePath)
	    {
	        this.certificatePath = certificatePath;
	    }


}
