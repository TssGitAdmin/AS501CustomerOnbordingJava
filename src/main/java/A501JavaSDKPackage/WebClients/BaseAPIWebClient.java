package A501JavaSDKPackage.WebClients;

import A501JavaSDKPackage.Models.A501ClientModel.A501ClientRequestModel;
import A501JavaSDKPackage.Models.Encryption.EncryptedResponseModel;
import A501JavaSDKPackage.Models.Proxy.ProxySetting;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;


import org.apache.http.HttpHost;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;


public class BaseAPIWebClient {

    protected static boolean IsNullOrEmpty(String val)
    {
        return val == null || val.isEmpty();
    }

    protected static Key generateSessionKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        Key sessionKey = null;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = new SecureRandom();
            int keyBitSize = 128;
            keyGenerator.init(keyBitSize, secureRandom);
            sessionKey = keyGenerator.generateKey();
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return sessionKey;
    }

    protected static String encryptUsingPublicKey(Key sessionKey, byte[] PublicKey) throws IOException, GeneralSecurityException {
        String encryptedKey = null;
        try{

            ByteArrayInputStream inputStream = new ByteArrayInputStream(PublicKey);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate)cf.generateCertificate(inputStream);

            PublicKey publicKey1 = cert.getPublicKey();

            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey1.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            Key publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

            Cipher c = Cipher.getInstance("RSA");
            c.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[]  encodeKey = sessionKey.getEncoded();
            byte[] base64 = Base64.getEncoder().encode(encodeKey);

            byte[] s = c.doFinal(base64);

            encryptedKey = Base64.getEncoder().encodeToString(s);

        }catch (Exception e){
            e.printStackTrace();
        }
        return encryptedKey;
    }

    protected String ReadFile(String jsonPath) throws IOException{
        try {
            File xmlFile = new File(jsonPath);
            Reader fileReader = new FileReader(xmlFile);
            BufferedReader bufReader = new BufferedReader(fileReader);
            StringBuilder sb = new StringBuilder();
            String line = bufReader.readLine();
            while( line != null){
                sb.append(line).append("\n");
                line = bufReader.readLine();
            }
            String xmlString = sb.toString();
            System.out.println(xmlString);
            bufReader.close();
            return xmlString;
        }
        catch (IOException e) {
            System.out.println("Error while retrieving data…");
            throw e;
        }
    }

    protected static String encryptUsingSessionKey(Key sessionKey, String plainText)
    {
        String encryptedData = null;
        try{
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey);

            byte[] cipherText = cipher.doFinal(plainText.getBytes());

            encryptedData =  Base64.getEncoder()
                    .encodeToString(cipherText);

        }catch (Exception e){
            e.printStackTrace();
        }
        return encryptedData;
    }

    protected static PrivateKey getPrivateKey(byte[] privateKey, String privateKeyPassword) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, java.security.cert.CertificateException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(privateKey);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(inputStream,privateKeyPassword.toCharArray());
        String alias = keyStore.aliases().nextElement().toString();
        PrivateKey privateKeyN = (PrivateKey) keyStore.getKey(alias, privateKeyPassword.toCharArray());
        return privateKeyN;
    }

    protected static String signData(PrivateKey _privateKey, String signingParams){
        String signedJson = "";
        try {
            Signature sig = Signature.getInstance("SHA512WithRSA");
            sig.initSign(_privateKey);
            sig.update(signingParams.getBytes("UTF-16LE"));
            signedJson = Base64.getEncoder().encodeToString(sig.sign());
        }catch (Exception e){
            e.printStackTrace();
        }
        return signedJson;
    }

    protected static boolean verifyJson(EncryptedResponseModel encryptedRespomsemodel, PublicKey publicKey){
        try{
            String resposneJson = encryptedRespomsemodel.encryptedData + encryptedRespomsemodel.encryptionKey;
            byte[] data = resposneJson.getBytes("UTF-16LE");
            byte[] signature = Base64.getDecoder().decode(encryptedRespomsemodel.signature);
            Signature sig = Signature.getInstance("SHA512withRSA");
            sig.initVerify(publicKey);
            sig.update(data);

            return sig.verify(signature);
        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }

    protected static void verifySignature(EncryptedResponseModel encryptedRespomsemodel, byte[] publicKeyBytes) throws Exception {
        PublicKey publicKey = GetPublicKey(publicKeyBytes);
        if (!verifyJson(encryptedRespomsemodel, publicKey))
        {
            throw new Exception("Signature Not Verified");
        }
    }

    protected static PublicKey GetPublicKey(byte[] publicKeyBytes) {
        PublicKey publicKey = null;
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(publicKeyBytes);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inputStream);

            PublicKey publicKey1 = cert.getPublicKey();

            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey1.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    protected static Key decryptDataAsymmetrically(String sessionKey, String privatePassword, byte[] privateKeyBytes){
        Key SessionKey = null;
        try {


            ByteArrayInputStream inputStream = new ByteArrayInputStream(privateKeyBytes);
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load( inputStream,privatePassword.toCharArray());
            String alias = keyStore.aliases().nextElement().toString();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, privatePassword.toCharArray());

            Cipher c = Cipher.getInstance("RSA");
            c.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] encodeKey = Base64.getDecoder().decode(sessionKey.getBytes());
            byte[] s = c.doFinal(encodeKey);

            byte[] decodedSessionKey = Base64.getDecoder().decode(s);

            SessionKey = new SecretKeySpec(decodedSessionKey, "AES");

        }catch (Exception e){
            e.printStackTrace();
        }

        return SessionKey;

    }

    protected static String decryptDataSymmetrically(Key sessionKey, String encryptedData){
        String decryptedText = "";
        try {
            byte[] decodeData = Base64.getDecoder().decode(encryptedData);

            Cipher Decipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            Decipher.init(Cipher.DECRYPT_MODE, sessionKey);

            byte[] cipherText = Decipher.doFinal(decodeData);
            decryptedText = new String(cipherText);
        }catch (Exception e)
        {
            e.printStackTrace();
        }
        return decryptedText;
    }

    public static String WebClientPost(String data, A501ClientRequestModel a501ClientRequestModel) throws NoSuchAlgorithmException
    {
        DefaultHttpClient httpClient = new DefaultHttpClient();
        String responseContent = "";

        try {
            HttpPost httpPost = new HttpPost(a501ClientRequestModel.getApiURL());

            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("Domain", a501ClientRequestModel.getApiURL());
            httpPost.setHeader("ApiToken", a501ClientRequestModel.getApiToken());
            httpPost.setHeader("Cluster", a501ClientRequestModel.getCluster());

            if (!IsNullOrEmpty(a501ClientRequestModel.getCsrfToken())) {
                httpPost.setHeader("CSRF", a501ClientRequestModel.getCsrfToken());
                httpPost.setHeader("XsrfToken", a501ClientRequestModel.getCsrfToken());
            }

            StringEntity stringEntity = new StringEntity(data);
            httpPost.setEntity(stringEntity);

            ProxySetting proxySetting = a501ClientRequestModel.getProxySetting();
            if (proxySetting != null && !IsNullOrEmpty(proxySetting.getProxyHostName()) && proxySetting.getProxyPort() != null ) {
                HttpHost proxy = new HttpHost(proxySetting.getProxyHostName(), proxySetting.getProxyPort());

                httpClient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);

                HttpContext context = new BasicHttpContext();

                if(!IsNullOrEmpty(proxySetting.getProxyPassword()) && !IsNullOrEmpty(proxySetting.getProxyUserName()))
                {
                    AuthScope authScope = new AuthScope(proxySetting.getProxyHostName(), proxySetting.getProxyPort());
                    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(proxySetting.getProxyUserName(), proxySetting.getProxyPassword());
                    context.setAttribute("http.auth.proxy-scope", authScope);
                    context.setAttribute("http.auth.credentials", credentials);
                }

                HttpResponse response = httpClient.execute(httpPost, context);

                responseContent = EntityUtils.toString(response.getEntity());
            } else {
                HttpResponse response = httpClient.execute(httpPost);

                responseContent = EntityUtils.toString(response.getEntity());
            }

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            httpClient.getConnectionManager().shutdown();
        }
        return responseContent;
    }

}