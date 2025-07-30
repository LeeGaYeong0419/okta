package org.example.okta.controller;

import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.example.okta.Constants;
import org.example.okta.service.OktaServiceImpl;
import org.example.okta.util.SessionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.UUID;


@Controller
@RequestMapping("/okta")
public class OktaController {
    private static final Logger logger = LoggerFactory.getLogger(OktaController.class);

    @Autowired
    private OktaServiceImpl oktaService;

    private final String LOGIN_URL = "/okta/login";

    @RequestMapping("/login")
    public String login(ModelMap model) {
        return "login";
    }

    @RequestMapping("/oktaAuth")
    public void oktaAuth(HttpServletRequest request, HttpServletResponse response) throws Exception {
        SessionUtil.invalidate(request);
        String state = UUID.randomUUID().toString();
        String none = UUID.randomUUID().toString();

        SessionUtil.put(request, Constants.OKTA_STATE ,state);
        SessionUtil.put(request, Constants.OKTA_NONE, none);
        SessionUtil.put(request, "flag", "ready");

        String oktaloginUrl = oktaService.oktaLoginURL(state,none);

        response.sendRedirect(oktaloginUrl);
    }

    @RequestMapping("/callback")
    public String callback(@RequestParam("code") String code, @RequestParam("state") String state, HttpServletRequest request, HttpServletResponse response, Model model) throws IOException, URISyntaxException {
        HttpSession session = request.getSession();
        // 1. state verify
        String savedState = (String) SessionUtil.get(request, Constants.OKTA_STATE);
        if (savedState == null || !savedState.equals(state)) {
            session.invalidate();
            response.sendRedirect(LOGIN_URL);
        }

        // 2. code로 토큰 발급
        TokenResponse tokenResponse = oktaService.requestTokenWithOIDC(code);

        // 3. OIDC 응답 파싱
        if (!tokenResponse.indicatesSuccess()) {
            session.invalidate();
            response.sendRedirect(LOGIN_URL);
        }

        OIDCTokenResponse oidcTokenResponse = (OIDCTokenResponse) tokenResponse;
        OIDCTokens oidcTokens = oidcTokenResponse.getOIDCTokens();

        // 4. 유플러스 고객인지 verify
        String id_token = oidcTokens.getIDTokenString();
        if (!oktaService.validateToken(id_token)) {
            session.invalidate();
            response.sendRedirect(LOGIN_URL);
        }

        //oktaService에 verifyIdToken 메서드 추가
        logger.debug("id_token: {}", oidcTokens.getIDToken());
        System.out.println("id_token: " + oidcTokens.getIDToken());
        logger.debug("access_token: {}", oidcTokens.getAccessToken());
        System.out.println("access_token: " + oidcTokens.getAccessToken());
        logger.debug("refresh_token: {}", oidcTokens.getRefreshToken());
        System.out.println("refresh_token: " + oidcTokens.getRefreshToken());

        // 4. 세션에 토큰 정보 저장
        SessionUtil.put(request, Constants.OKTA_ID_TOKEN, oidcTokens.getIDToken());
        SessionUtil.put(request, Constants.OKTA_ACCESS_TOKEN, oidcTokens.getAccessToken());
        if (oidcTokens.getRefreshToken() != null) {
            SessionUtil.put(request, Constants.OKTA_REFRESH_TOKEN, oidcTokens.getRefreshToken());
        }

        SessionUtil.put(request, "flag", "success");
        model.addAttribute("id_token", oidcTokens.getIDToken());
        model.addAttribute("access_token", oidcTokens.getAccessToken());
        model.addAttribute("refresh_token", oidcTokens.getRefreshToken());

        // 로그인 성공 시 진입 페이지
        return "main";
    }

    @RequestMapping("/main")
    public String main(ModelMap model) {
        return "main";
    }
}
