package A501JavaSDKPackage.WebClients;

import A501JavaSDKPackage.Models.A501.A501ResponseDto;
import A501JavaSDKPackage.Models.A501ClientModel.A501ClientRequestModel;
import A501JavaSDKPackage.Models.A501ClientModel.A501ClientResponseModel;
import A501JavaSDKPackage.Models.Encryption.EncryptedRequestModel;
import A501JavaSDKPackage.Models.Encryption.EncryptedResponseModel;

import java.io.IOException;
import java.security.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

public class A501WebClient extends BaseAPIWebClient {
    public  A501ClientResponseModel execute(A501ClientRequestModel a501ClientRequestModel) throws Exception {
        String signedJsonApiRequest = getSignedJsonApiRequest(a501ClientRequestModel);

        String jsonResponse = WebClientPost(signedJsonApiRequest, a501ClientRequestModel);

        return verifyAndReturnResponse(a501ClientRequestModel, jsonResponse);
    }

    private  A501ClientResponseModel verifyAndReturnResponse(A501ClientRequestModel a501ClientRequestModel, String jsonResponse) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();

        EncryptedResponseModel encryptedResponseModel = objectMapper.readValue(jsonResponse, new TypeReference<EncryptedResponseModel>() {});

        if (IsNullOrEmpty(encryptedResponseModel.signature) || IsNullOrEmpty(encryptedResponseModel.encryptionKey) || IsNullOrEmpty(encryptedResponseModel.encryptedData))
            throw new Exception("Unexpected Error in API.");

        verifySignature(encryptedResponseModel, a501ClientRequestModel.getPublicKey());

        Key sessionKey = decryptDataAsymmetrically(encryptedResponseModel.encryptionKey, a501ClientRequestModel.getPrivateKeyPassword(), a501ClientRequestModel.getPrivateKey());

        String responseA501InternalJson = decryptDataSymmetrically(sessionKey, encryptedResponseModel.encryptedData);

        A501ResponseDto a501ResponseDto = objectMapper.readValue(responseA501InternalJson, new TypeReference<A501ResponseDto>() {});

        A501ClientResponseModel a501ClientResponseModel = new A501ClientResponseModel();
        a501ClientResponseModel.ValidationCode = encryptedResponseModel.validationCode;
        a501ClientResponseModel.ValidationDescription = encryptedResponseModel.validationDescription;
        a501ClientResponseModel.RequestId = encryptedResponseModel.requestId;
        a501ClientResponseModel.A501ResponseDto = a501ResponseDto;

        return  a501ClientResponseModel;
    }

    private  String getSignedJsonApiRequest(A501ClientRequestModel a501ClientRequestModel) throws Exception
    {
        EncryptedRequestModel encryptedRequestModel = new EncryptedRequestModel();

        if (a501ClientRequestModel == null)
            throw new Exception("A501ClientRequestModel object cannot be empty.");

        ObjectMapper objectMapper = new ObjectMapper();

        String reqJson = objectMapper.writeValueAsString(a501ClientRequestModel.getRequestModel());

        encryptRequestDataAndSessionKey(reqJson, a501ClientRequestModel.getPublicKey(), encryptedRequestModel);

        PrivateKey pvtKey = getPrivateKey(a501ClientRequestModel.getPrivateKey(), a501ClientRequestModel.getPrivateKeyPassword());
        encryptedRequestModel.signature = signData(pvtKey, encryptedRequestModel.encryptedData +encryptedRequestModel.encryptionKey);

        encryptedRequestModel.requestId = a501ClientRequestModel.getRequestId();

        return objectMapper.writeValueAsString(encryptedRequestModel);
    }

    private  void encryptRequestDataAndSessionKey(String reqJson, byte[] publicKey, EncryptedRequestModel encryptedRequestModel) throws GeneralSecurityException, IOException {
        Key sessionKey = generateSessionKey();

        String encryptedReqData = encryptUsingSessionKey(sessionKey, reqJson);

        String encryptedSessionKey = encryptUsingPublicKey(sessionKey, publicKey);

        encryptedRequestModel.encryptedData = encryptedReqData;
        encryptedRequestModel.encryptionKey = encryptedSessionKey;
    }
}
