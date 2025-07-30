package org.example.okta.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.TokenResponse;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public interface OktaService {
    public String oktaLoginURL(String state, String none);

    public TokenResponse requestTokenWithOIDC(String code) throws URISyntaxException;

    public boolean validateToken(String token) throws ParseException;

    public RSAPublicKey getPublicKey(String uri, String kid) throws JOSEException, IOException, ParseException;
}
