package com.pexels;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TwitterController {

	@Autowired
	TwitterService twitterService;
//	
//	@PostMapping("/tweetText")
//    public ResponseEntity<String> postTweet(@RequestParam String text) {
//        return twitterService.tweet(text);
//    }
	
	
	 @GetMapping("/signing-key")
	    public String getSigningKey() throws UnsupportedEncodingException {
	        // Replace these values with your actual consumer secret and token secret
	        String consumerSecret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw";
	        String tokenSecret = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE";

	        String signingKey = twitterService.generateSigningKey(consumerSecret, tokenSecret);
	        
	        return signingKey;
	    }

	    @PostMapping("/tweetText")
	    public ResponseEntity<String> postTweet(@RequestParam String text) throws Exception {
	        String response = twitterService.postTweet(text);  
	        return new ResponseEntity<>(response, HttpStatus.OK);  
	    }
	
}
