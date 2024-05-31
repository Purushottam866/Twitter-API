package com.pexels;



import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

@Service
public class TwitterOAuthHelper {
    private static final String CONSUMER_KEY = "26tJLCqvHYhYMswSLwobvCDli";
    private static final String CONSUMER_SECRET = "14EbMLfdmQf8HmMjZCiPlSCZfjtdbQMAZ0GwMxTO0BtBPvkCPI";
    private static final String ACCESS_TOKEN = "1783061094237425664-9zzov4I9UJUQn5G2evVFeKoiYL5tUh";
    private static final String ACCESS_TOKEN_SECRET = "gNfdtzTJ5QfVL647YZFiAMdmo1lukoHP2UmZNt1d3j9wM";

    public String generateOAuth1Header(String url, String httpMethod, String requestBody) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        String nonce = generateNonce(11);
        String timestamp = String.valueOf(System.currentTimeMillis() / 1000);

        String signatureBase = generateSignatureBase(url, httpMethod, nonce, timestamp, requestBody);
        String signingKey = generateSigningKey();

        String signature = generateSignature(signatureBase, signingKey);

        StringBuilder headerBuilder = new StringBuilder();
        headerBuilder.append("OAuth ");
        headerBuilder.append("oauth_consumer_key=\"" + CONSUMER_KEY + "\", ");
        headerBuilder.append("oauth_nonce=\"" + nonce + "\", ");
        headerBuilder.append("oauth_signature=\"" + URLEncoder.encode(signature, StandardCharsets.UTF_8.toString()) + "\", ");
        headerBuilder.append("oauth_signature_method=\"HMAC-SHA1\", ");
        headerBuilder.append("oauth_timestamp=\"" + timestamp + "\", ");
        headerBuilder.append("oauth_token=\"" + ACCESS_TOKEN + "\", ");
        headerBuilder.append("oauth_version=\"1.0\"");

        return headerBuilder.toString();
    }

    private String generateNonce(int length) {
        StringBuilder nonce = new StringBuilder();
        SecureRandom random = new SecureRandom();
        String characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        for (int i = 0; i < length; i++) {
            nonce.append(characters.charAt(random.nextInt(characters.length())));
        }

        return nonce.toString();
    }

    private String generateSignatureBase(String url, String httpMethod, String nonce, String timestamp, String requestBody) throws UnsupportedEncodingException {
        List<String> parameters = new ArrayList<>();
        parameters.add("oauth_consumer_key=" + CONSUMER_KEY);
        parameters.add("oauth_nonce=" + nonce);
        parameters.add("oauth_signature_method=HMAC-SHA1");
        parameters.add("oauth_timestamp=" + timestamp);
        parameters.add("oauth_token=" + ACCESS_TOKEN);
        parameters.add("oauth_version=1.0");

        // Parse and add query parameters from the URL
        // For simplicity, we skip parsing query parameters here

        // Add body parameters
        if (requestBody != null && !requestBody.isEmpty()) {
            parameters.add(requestBody);
        }

        Collections.sort(parameters);
        String parameterString = String.join("&", parameters);

        String encodedUrl = URLEncoder.encode(url, StandardCharsets.UTF_8.toString());
        String encodedParameters = URLEncoder.encode(parameterString, StandardCharsets.UTF_8.toString());

        return httpMethod.toUpperCase() + "&" + encodedUrl + "&" + encodedParameters;
    }

    private String generateSigningKey() throws UnsupportedEncodingException {
        String encodedConsumerSecret = URLEncoder.encode(CONSUMER_SECRET, StandardCharsets.UTF_8.toString());
        String encodedAccessTokenSecret = URLEncoder.encode(ACCESS_TOKEN_SECRET, StandardCharsets.UTF_8.toString());

        return encodedConsumerSecret + "&" + encodedAccessTokenSecret;
    }

    private String generateSignature(String signatureBase, String signingKey) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA1");
        SecretKeySpec secretKeySpec = new SecretKeySpec(signingKey.getBytes(StandardCharsets.UTF_8), "HmacSHA1");
        mac.init(secretKeySpec);
        byte[] signatureBytes = mac.doFinal(signatureBase.getBytes(StandardCharsets.UTF_8));

        return new String(Base64.getEncoder().encode(signatureBytes), StandardCharsets.UTF_8);
    }
}
