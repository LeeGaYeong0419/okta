package org.example.okta.interceptor;

import org.example.okta.util.SessionUtil;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginCheckInterceptor extends HandlerInterceptorAdapter {
    private final String LOGIN_URL = "/okta/login";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        String uri = request.getRequestURI();

        // 로그인, 콜백, 정적 리소스 등 예외 처리
        if (uri.equals("/okta/login") || uri.equals("/okta/callback") || uri.equals("/okta/oktaAuth")) {
            return true; // 인터셉터 통과
        }

        String flag = (String) SessionUtil.get(request, "flag");

        if (flag == null || (!flag.equals("ready") && !flag.equals("success"))) {
            response.sendRedirect(LOGIN_URL);
            return false;
        }

        return true;
    }
}
