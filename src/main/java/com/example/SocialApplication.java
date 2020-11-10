/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.social.oauth1.OAuth1Operations;
import org.springframework.social.oauth1.OAuthToken;
import org.springframework.social.twitter.connect.TwitterConnectionFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
@RestController
public class SocialApplication extends WebSecurityConfigurerAdapter {

	@Value("${my-client-id}")
	String clientId;
	@Value("${my-client-secret}")
	String clientSecret;
	@Value("${my-redirect-uri}")
	String redirectUri;

	@GetMapping("/token2")
	public String token2() {
		System.out.println("test");
		return "dada";
	}

	@RequestMapping("/token")
	public ResponseEntity<String> token() {
		/*System.out.println("test");
		RestTemplate restTemplate = new RestTemplate();

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.setContentType(MediaType.APPLICATION_JSON);
		headers.set("oauth_callback", redirectUri);
		headers.set("oauth_consumer_key", clientId);
		headers.set("oauth_consumer_secret", clientSecret);
		headers.set("oauth_token", "1216739581464317955-rgmVJECVsOudbSIRk0dUUEZID5Lflc");
		headers.set("oauth_token_secret", "ehXnUKN8nbcYdQSwTOYftylWl6Bw4GexiF1QrX7YgieOf");
		headers.set("Access-Control-Allow-Origin", "*");

		HttpEntity<String> entity = new HttpEntity<String>("parameters", headers);

		ResponseEntity<String> respEntity = restTemplate.exchange("https://api.twitter.com/oauth/request_token",
				HttpMethod.POST, entity, String.class);

		String resp = respEntity.getBody();
		return resp;*/
		TwitterConnectionFactory connectionFactory =
				new TwitterConnectionFactory(clientId, clientSecret);
		OAuth1Operations oauthOperations = connectionFactory.getOAuthOperations();
		OAuthToken requestToken = oauthOperations.fetchRequestToken("http://localhost:3000/profile", null);
		return ResponseEntity.ok("{ \"oauth_token\": \"" + requestToken.getValue() + "\" }");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		// @formatter:off
		http
			.authorizeRequests(a -> a
				.antMatchers("/", "/error", "/webjars/**", "/token", "/token2").permitAll()
				.anyRequest().authenticated()
			)
			.exceptionHandling(e -> e
				.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
			)
			.oauth2Login();
		// @formatter:on
	}

	public static void main(String[] args) {
		SpringApplication.run(SocialApplication.class, args);
	}

}
