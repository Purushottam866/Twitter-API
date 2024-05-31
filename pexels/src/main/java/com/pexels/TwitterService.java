package com.pexels;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Service
public class TwitterService {

//	 @Value("${twitter.api.url}")
//	    private String apiUrl;

	    @Value("${twitter.api.consumer-key}")
	    private String consumerKey;

	    @Value("${twitter.api.consumer-secret}")
	    private String consumerSecret;

	    @Value("${twitter.api.oauth-token}")
	    private String oauthToken;

	    @Value("${twitter.api.oauth-token-secret}")
	    private String oauthTokenSecret;

	   RestTemplate restTemplate = new RestTemplate();
	   HttpHeaders headers = new HttpHeaders();
	   
	   @Autowired
	   TwitterOAuthHelper authHelper;
//
//	  
//	    private final String twitterApiBaseUrl = "https://api.twitter.com/2/tweets";
//	    private final String consumerKey = "26tJLCqvHYhYMswSLwobvCDli";
//	    private final String consumerKeySecret = "14EbMLfdmQf8HmMjZCiPlSCZfjtdbQMAZ0GwMxTO0BtBPvkCPI";
//	    private final String accessToken = "1783061094237425664-9zzov4I9UJUQn5G2evVFeKoiYL5tUh";
//	    private final String accessTokenSecret = "gNfdtzTJ5QfVL647YZFiAMdmo1lukoHP2UmZNt1d3j9wM";
//
//	    
//	    public ResponseEntity<String> tweet(String tweetText) {
//	        HttpHeaders headers = new HttpHeaders();
//	        headers.setContentType(MediaType.APPLICATION_JSON);
//
//	        String oauthSignature = generateOAuthSignature(tweetText);
//	        System.out.println("oauthSignature" + oauthSignature);
//	        
//	        String timestamp = Long.toString(System.currentTimeMillis() / 1000);
//	        System.out.println("timestamp" + timestamp);
//	        
//	        String nonce = generateNonce(11);
//	        System.out.println("nonce" + nonce );
//
//	        String oauthHeader = generateOAuthHeader(oauthSignature, timestamp, nonce);
//
//	        HttpEntity<String> request = new HttpEntity<>("{\"text\": \"" + tweetText + "\"}", headers);
//
//	        String url = twitterApiBaseUrl + "tweets";
//
//	        headers.add("Authorization", oauthHeader);
//
//	        return restTemplate.postForEntity(url, request, String.class);
//	    }
//
//	    private String generateNonce(int length) {
//	        String characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
//	        Random random = new Random();
//	        StringBuilder nonceBuilder = new StringBuilder();
//	        for (int i = 0; i < length; i++) {
//	            nonceBuilder.append(characters.charAt(random.nextInt(characters.length())));
//	        }
//	        return nonceBuilder.toString();
//	    }
//
//	    private String generateOAuthSignature(String tweetText) {
//	        String method = "POST";
//	        String baseUrl = twitterApiBaseUrl + "tweets";
//
//	        String parameterString = "text=" + encode(tweetText);
//
//	        String signatureBaseString = method.toUpperCase() + "&" + encode(baseUrl) + "&" + encode(parameterString);
//
//	        String signingKey = encode(consumerKeySecret) + "&" + encode(accessTokenSecret);
//
//	        String oauthSignature = "";
//	        try {
//	            Mac mac = Mac.getInstance("HmacSHA1");
//	            SecretKeySpec secretKeySpec = new SecretKeySpec(signingKey.getBytes(), "HmacSHA1");
//	            mac.init(secretKeySpec);
//	            byte[] rawHmac = mac.doFinal(signatureBaseString.getBytes());
//	            oauthSignature = Base64.getEncoder().encodeToString(rawHmac);
//	        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
//	            e.printStackTrace();
//	        }
//
//	        return oauthSignature;
//	    }
//
//	    private String generateOAuthHeader(String oauthSignature, String timestamp, String nonce) {
//	        return "OAuth "
//	                + "oauth_consumer_key=\"" + encode(consumerKey) + "\", "
//	                + "oauth_signature_method=\"HMAC-SHA1\", "
//	                + "oauth_timestamp=\"" + timestamp + "\", "
//	                + "oauth_nonce=\"" + nonce + "\", "
//	                + "oauth_token=\"" + encode(accessToken) + "\", "
//	                + "oauth_version=\"1.0\", "
//	                + "oauth_signature=\"" + encode(oauthSignature) + "\"";
//	    }
//
//	    private String encode(String value) {
//	        try {
//	            return URLEncoder.encode(value, "UTF-8");
//	        } catch (UnsupportedEncodingException e) {
//	            throw new IllegalArgumentException("Cannot encode value: " + value, e);
//	        }
//	    }
	   
	   
//	   public String postTweet(String tweetText) {
//	        String url = "https://api.twitter.com/2/tweets";
//	        
//	        headers.set("Content-Type", "application/json");
//	        headers.set("Authorization", "OAuth oauth_consumer_key=\"26tJLCqvHYhYMswSLwobvCDli\",oauth_token=\"1783061094237425664-9zzov4I9UJUQn5G2evVFeKoiYL5tUh\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"1714368516\",oauth_nonce=\"V6wN5lTPWwi\",oauth_version=\"1.0\",oauth_signature=\"66s5QkN0X1mkpg3tgZ8ohLAMSy8%3D\""  );
//	        
//	        String requestBody = "{ \"text\": \"" + tweetText + "\" }";
//	        HttpEntity<String> entity = new HttpEntity<>(requestBody, headers);
//	        System.out.println(headers);
//	        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
//	        return response.getBody();
		   
		   
	   // TRYING TO POST WITH PARAMETERS
	  
	   private static final String CONSUMER_KEY = "26tJLCqvHYhYMswSLwobvCDli";
	    private static final String CONSUMER_SECRET = "14EbMLfdmQf8HmMjZCiPlSCZfjtdbQMAZ0GwMxTO0BtBPvkCPI";
	    private static final String ACCESS_TOKEN = "1783061094237425664-9zzov4I9UJUQn5G2evVFeKoiYL5tUh";
	    private static final String ACCESS_TOKEN_SECRET = "gNfdtzTJ5QfVL647YZFiAMdmo1lukoHP2UmZNt1d3j9wM";

	    


	    private static final String BASE_URL = "https://api.twitter.com/1.1/statuses/update.json";

	    public String postTweet(String tweetText) throws Exception {
	        String requestMethod = "POST";
	        String oauthSignatureMethod = "HMAC-SHA1";
	        String oauthTimestamp = String.valueOf(System.currentTimeMillis() / 1000); // Current timestamp
	        String oauthNonce = UUID.randomUUID().toString().replace("-", ""); // Unique nonce

	        // Create the OAuth header
	        String oauthHeader = "OAuth " +
	                "oauth_consumer_key=\"" + CONSUMER_KEY + "\", " +
	                "oauth_nonce=\"" + oauthNonce + "\", " +
	                "oauth_signature_method=\"" + oauthSignatureMethod + "\", " +
	                "oauth_timestamp=\"" + oauthTimestamp + "\", " +
	                "oauth_token=\"" + ACCESS_TOKEN + "\", " +
	                "oauth_version=\"1.0\"";

	        // Generate the signature
	        String baseString = URLEncoder.encode(requestMethod, "UTF-8") + "&" +
	                URLEncoder.encode(BASE_URL, "UTF-8") + "&" +
	                URLEncoder.encode("status", "UTF-8") + "=" + URLEncoder.encode(tweetText, "UTF-8");
	        String signingKey = URLEncoder.encode(CONSUMER_SECRET, "UTF-8") + "&" + URLEncoder.encode(ACCESS_TOKEN_SECRET, "UTF-8");
	        String oauthSignature = generateHmacSha1Signature(baseString, signingKey);

	        // Append the signature to the OAuth header
	        oauthHeader += ", oauth_signature=\"" + URLEncoder.encode(oauthSignature, "UTF-8") + "\"";

	        // Set up the request headers
	        HttpHeaders headers = new HttpHeaders();
	        headers.set("Content-Type", "application/json");
	        headers.set("Authorization", oauthHeader);

	        // Set up the request body
	        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
	        body.add("status", tweetText);
	        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);
	        System.out.println("HEADERS => "+ headers);
	        // Send the request
	        RestTemplate restTemplate = new RestTemplate();
	        ResponseEntity<String> response = restTemplate.exchange(BASE_URL, HttpMethod.POST, entity, String.class);
	        
	        System.out.println("HEADERS => "+ entity);
	        
	        return response.getBody();    
	    }

	    private String generateHmacSha1Signature(String baseString, String key) throws Exception {
	        Mac hmacSha1 = Mac.getInstance("HmacSHA1");
	        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA1");
	        hmacSha1.init(secretKeySpec);
	        byte[] signatureBytes = hmacSha1.doFinal(baseString.getBytes(StandardCharsets.UTF_8));
	        return new String(Base64.getEncoder().encode(signatureBytes));
	    }
	   
	   
	   // UNTILL HERE, BELOW IS ANOTHER METHOD
	   
	   public String generateSigningKey(String consumerSecret, String tokenSecret) throws UnsupportedEncodingException {
	        // Percent-encode the consumer secret and token secret
	        String encodedConsumerSecret = URLEncoder.encode(consumerSecret, "UTF-8");
	        String encodedTokenSecret = URLEncoder.encode(tokenSecret, "UTF-8");

	        // Combine the encoded consumer secret and token secret with an ampersand
	        String signingKey = encodedConsumerSecret + "&" + encodedTokenSecret;
	        
	        return signingKey;
	    }
	   
	
	 public String postTweetToTwitter(String tweetText) throws UnsupportedEncodingException {
	        String url = "https://api.twitter.com/2/tweets";
	        headers.set("Content-Type", "application/json");
	        headers.set("Authorization", generateAuthorizationHeader());
	        String requestBody = "{ \"text\": \"" + tweetText + "\" }";
	        HttpEntity<String> entity = new HttpEntity<>(requestBody, headers);
	        System.out.println(headers);
	        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
	        return response.getBody();
	    }
	  
	 private String generateAuthorizationHeader() throws UnsupportedEncodingException {
		    String timestamp = String.valueOf(Instant.now().getEpochSecond());
		    System.out.println("Timestamp " + timestamp);
		    
		    String nonce = generateNonce(11);
		   System.out.println("Nonce "+ nonce);
		    
		    String baseString = "POST&https%3A%2F%2Fapi.twitter.com%2F2%2Ftweets&oauth_consumer_key%3D" + consumerKey +
		            "%26oauth_nonce%3D" + nonce + "%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D" + timestamp +
		            "%26oauth_token%3D" + oauthToken + "%26oauth_version%3D1.0%26text%3DHello%2520world%2521%2520one%2520more%2520and";

		    
		    String signingKey = generateSigningKey(consumerSecret, oauthTokenSecret); // Generate the signing key here
		    //String signingKey = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"; // Generate the signing key here
		    String signature = generateSignature(signingKey, baseString);
		    System.out.println("Signature "+ signature);


		    String authorizationHeader = "OAuth oauth_consumer_key=\"26tJLCqvHYhYMswSLwobvCDli\"," +
                    "oauth_token=\"1783061094237425664-9zzov4I9UJUQn5G2evVFeKoiYL5tUh\"," +
                    "oauth_signature_method=\"HMAC-SHA1\"," +
                    "oauth_timestamp=\"" + timestamp + "\"," +
                    "oauth_nonce=\"" + nonce + "\"," +
                    "oauth_version=\"1.0\"," +
                    "oauth_signature=\"" + signature + "\"";
		    
		    //System.out.println("Authorization Header: " + authorizationHeader);

		    return authorizationHeader;
		}

	 private String generateSignature(String signingKey, String baseString) {
		 try {
		       
			 String algorithm = "HmacSHA1";

		        SecretKeySpec secretKeySpec = new SecretKeySpec(signingKey.getBytes(StandardCharsets.UTF_8), algorithm);
		        Mac mac = Mac.getInstance(algorithm);
		        mac.init(secretKeySpec);
		        byte[] signatureBytes = mac.doFinal(baseString.getBytes(StandardCharsets.UTF_8));
		        String encodedSignature = URLEncoder.encode(Base64.getEncoder().encodeToString(signatureBytes), "UTF-8");
		        return encodedSignature;
		    } catch (NoSuchAlgorithmException | InvalidKeyException | UnsupportedEncodingException e) {
		        e.printStackTrace();
		        return null;
		    }
		}

	    private String generateNonce(int length) {
	        String charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	        StringBuilder sb = new StringBuilder();
	        for (int i = 0; i < length; i++) {
	            int randomIndex = ThreadLocalRandom.current().nextInt(charset.length());
	            sb.append(charset.charAt(randomIndex));
	        }
	        return sb.toString();
	    }
}
