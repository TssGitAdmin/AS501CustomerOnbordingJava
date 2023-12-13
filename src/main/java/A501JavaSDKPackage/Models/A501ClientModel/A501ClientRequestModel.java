package A501JavaSDKPackage.Models.A501ClientModel;

import A501JavaSDKPackage.Models.A501.A501RequestDto;
import A501JavaSDKPackage.Models.Proxy.ProxySetting;

public class A501ClientRequestModel {
    private String apiToken;
    private String requestId;
    private byte[] privateKey;
    private byte[] publicKey;
    private A501RequestDto requestModel;
    private String privateKeyPassword;
    private String apiURL;
    private String csrfToken;
    private String cluster;
    private ProxySetting proxySetting;

    public A501ClientRequestModel(String apiToken, String requestId, byte[] privateKey, byte[] publicKey,
                                  A501RequestDto a501RequestDto, String privateKeyPassword, String apiURL,
                                  String cluster, String csrfToken,  ProxySetting proxySetting) {
        if (apiToken == null || apiToken.isEmpty())
            throw new IllegalArgumentException("Token cannot be empty");
        if (requestId == null || requestId.isEmpty())
            throw new IllegalArgumentException("RequestId cannot be empty");
        if (privateKey == null)
            throw new IllegalArgumentException("Token PrivateKey cannot be empty");
        if (publicKey == null)
            throw new IllegalArgumentException("Token PublicKey cannot be empty");
        if (a501RequestDto == null)
            throw new IllegalArgumentException("Token a501RequestDto cannot be empty");
        if (privateKeyPassword == null || privateKeyPassword.isEmpty())
            throw new IllegalArgumentException("Token PrivateKeyPassword cannot be empty");
        if (apiURL == null || apiURL.isEmpty())
            throw new IllegalArgumentException("Token APIUrl cannot be empty");

        this.apiToken = apiToken;
        this.requestId = requestId;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.requestModel = a501RequestDto;
        this.privateKeyPassword = privateKeyPassword;
        this.apiURL = apiURL;
        this.csrfToken = csrfToken;
        this.cluster = cluster;
        this.proxySetting = proxySetting;
    }

    public String getApiToken() {
        return apiToken;
    }

    public String getRequestId() {
        return requestId;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public A501RequestDto getRequestModel() {
        return requestModel;
    }

    public String getPrivateKeyPassword() {
        return privateKeyPassword;
    }

    public String getApiURL() {
        return apiURL;
    }

    public String getCsrfToken() {
        return csrfToken==null ? "" : csrfToken;
    }

    public String getCluster() {
        return cluster.isEmpty() || cluster == null ? "CL1_User": cluster;
    }

    public ProxySetting getProxySetting() {
        return proxySetting;
    }
}
