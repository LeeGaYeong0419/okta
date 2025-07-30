package org.example.okta.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Session 객체 관리 Helper 클래스
 * 
 * <pre>
 * 패키지명        :  
 * 파일명          : 
 * 작성자          : 
 * 작성일          : 
 * 수정내용
 * ----------------------------------------------
 * 수정일      수정자  수정내용
 * ----------------------------------------------
 * 
 * </pre>
 */
public class SessionUtil {

	private static final Logger logger = LoggerFactory.getLogger(SessionUtil.class);

	/**
	 * Session 객체 조회
	 * 
	 * @param req
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static Object get(HttpServletRequest req, String key) {

		Object obj = null;
		HttpSession session = null;
		session = req.getSession(false);
		if(session != null){
			if (session.isNew()) {
				logger.debug("Session isNew true");
			} else {
				logger.debug("Session isNew false");
			}
			obj = (Object) session.getAttribute(key);			
		}
		logger.debug("## obj " + obj);
		return obj;

	}



	/**
	 * Session 객체 등록
	 * 
	 * @param req
	 * @param key
	 * @param obj
	 * @throws Exception
	 */
	public static void put(HttpServletRequest req, String key, Object obj) {

		HttpSession session = null;
		session = req.getSession(true);
		if (session.isNew()) {
			logger.debug("Session isNew true");
		} else {
			logger.debug("Session isNew false");
		}
		session.setAttribute(key, obj);

	}

	/**
	 * Session 객체 삭제
	 * 
	 * @param req
	 * @param key
	 * @param obj
	 * @throws Exception
	 */
	public static void remove(HttpServletRequest req, String key) {

		HttpSession session = null;
		session = req.getSession(false);
		if (session != null) {
			if (session.isNew()) {
				logger.debug("Session isNew true");
			} else {
				logger.debug("Session isNew false");
			}			
			session.removeAttribute(key);
		}

	}

	/**
	 * Session 종료 (logout 시 처리)
	 * 
	 * @param req
	 * @throws Exception
	 */
	public static void invalidate(HttpServletRequest req) throws Exception {

		HttpSession session = null;
		session = req.getSession(false);
		if (session != null) {
			if (session.isNew()) {
				logger.debug("Session isNew true");
			} else {
				logger.debug("Session isNew false");
			}			
			session.invalidate();
		}
	}
}
