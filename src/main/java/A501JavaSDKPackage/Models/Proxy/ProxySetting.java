package A501JavaSDKPackage.Models.Proxy;

public class ProxySetting {
    private String proxyHostName;
    private Integer proxyPort;
    private String proxyUserName;
    private String proxyPassword;

    public ProxySetting(
            String proxyHostName,
            Integer proxyPort,
            String proxyUserName,
            String proxyPassword
    ) {
        this.proxyHostName = proxyHostName;
        this.proxyPort = proxyPort;
        this.proxyUserName = proxyUserName;
        this.proxyPassword = proxyPassword;
    }

    public String getProxyHostName() {
        return proxyHostName;
    }

    public Integer getProxyPort() {
        return proxyPort;
    }

    public String getProxyUserName() {
        return proxyUserName;
    }
    public String getProxyPassword() {
        return proxyPassword;
    }
}
