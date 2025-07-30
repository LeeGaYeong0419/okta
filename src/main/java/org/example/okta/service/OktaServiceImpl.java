package org.example.okta.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import org.example.okta.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

@Service
public class OktaServiceImpl implements OktaService {

    private static final Logger logger = LoggerFactory.getLogger(OktaServiceImpl.class);

    @Value("${okta.client-id}")
    private String clientId;

    @Value("${okta.client-secret}")
    private String clientSecret;

    @Value("${okta.issuer}")
    private String issuer;

    @Value("${okta.endPoint.login}")
    private String loginEndpoint;

    @Value("${okta.endPoint.token}")
    private String tokenEndPoint;

    @Value("${okta.endPoint.keys}")
    private String keysEndPoint;

    @Value("${okta.callback.uri}")
    private String callbackUri;

    //OKTA 인증 페이지로 redirect
    @Override
    public String oktaLoginURL(String state, String none) {
        String authUrl = issuer + loginEndpoint + "?"
                + Constants.OKTA_CLIENT_ID + "=" + clientId
//                + "&" + Constants.OKTA_CLIENT_SECRET + "=" + clientSecret
                + "&redirect_uri=" + callbackUri
                + "&" + Constants.OKTA_RESPONSE_TYPE + "=" + Constants.OKTA_CODE
                + "&" + Constants.OKTA_STATE + "=" + state
                + "&" + Constants.OKTA_NONE + "=" + none
                + "&scope=openid%20profile%20email";

        logger.debug(authUrl);

        return authUrl;
    }

    //code로 토큰 발급
    @Override
    public TokenResponse requestTokenWithOIDC(String code) throws URISyntaxException {
        URI uri = new URI(issuer + tokenEndPoint);
        System.out.println("Token URI: " + uri);

        AuthorizationCode authorizationCode = new AuthorizationCode(code);
        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(authorizationCode, new URI(callbackUri));

        ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret));

        TokenRequest tokenRequest = new TokenRequest(
                uri,
                clientAuth,
                codeGrant,
                new Scope("openid", "profile", "email")
        );

        try {
            HTTPResponse httpResponse = tokenRequest.toHTTPRequest().send();
            TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);

            return tokenResponse;

        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    public boolean validateToken(String token) {
        if (token == null || token.split("\\.").length != 3) {
            logger.warn("토큰이 JWT 형식이 아닙니다. token={}", token);
            return false;
        }
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            // 키 ID 추출 및 공개키 조회
            String kid = signedJWT.getHeader().getKeyID();
            RSAPublicKey publicKey = getPublicKey(issuer + keysEndPoint, kid);

            // 서명 검증
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            if (!signedJWT.verify(verifier)) {
                logger.warn("JWT signature invalid. token={}", token);
                return false;
            }

            // 클레임 확인
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            // issuer 검증
            String claimIssuer = claims.getIssuer();
            if (!issuer.equals(claimIssuer)) {
                logger.warn("Issuer 불일치: 기대값={} 실제값={}", issuer, claimIssuer);
                return false;
            }

            // audience 검증
            if (claims.getAudience() == null || !claims.getAudience().contains(clientId)) {
                logger.warn("Audience 불일치: 기대값={} 실제값={}", clientId, claims.getAudience());
                return false;
            }

            // 만료 검증
            if (claims.getExpirationTime() == null || claims.getExpirationTime().before(new Date())) {
                logger.warn("토큰 만료됨. token={}", token);
                return false;
            }

            return true;
        } catch (java.text.ParseException e) {
            logger.warn("토큰 파싱 에러: {}", e.getMessage());
            return false;
        } catch (IOException | JOSEException e) {
            logger.error("토큰 검증 시스템 에러", e);
            return false;
        } catch (Exception e) {
            logger.error("알 수 없는 토큰 검증 실패", e);
            return false;
        }
    }


    @Override
    public RSAPublicKey getPublicKey(String jwksUri, String kid) throws JOSEException, IOException, java.text.ParseException {
        // 1. JWKs 엔드포인트에서 키셋 다운로드
        JWKSet publicKeys = JWKSet.load(new URL(jwksUri));

        // 2. kid로 매칭되는 공개키 추출
        JWK jwk = publicKeys.getKeyByKeyId(kid);
        if (jwk == null) {
            throw new IllegalArgumentException("No matching JWK found for kid: " + kid);
        }
        return jwk.toRSAKey().toRSAPublicKey();
    }


}
