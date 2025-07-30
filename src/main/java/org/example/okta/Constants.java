package org.example.okta;

import java.io.File;

public class Constants {

    public static final int BYTE_DIVISION = 1024;

    public static final String PREVIEW_PATH = File.separator + "files" + File.separator + "preview" + File.separator;

    public static final String PATH = File.separator + "files" + File.separator;
    
    public static final String COMMA=",";
    
    public static final String YES = "Y";
    
    public static final String NO = "N";
    
    public static final String RETRY = "R";
    
    public static final String FAIL = "F";
    
    public static final String BAD = "B";

    public static final String NEW = "N";

    public static final String DELETE = "D";

    public static final String CHANGE = "C";


    public static final String LNB_CODE = "LNB_CODE";
    
    public static final String GO_SEARCH = "goSearch";
    
    public static final String GO_PAGE = "goPage";
    
    public static final String TOTAL_COUNT = "totalCount";
    
    public static final String PAGING = "paging";
    
    public static final int PAGING_CNT_FIVE = 5;
    
    public static final int PAGING_CNT_TEN = 10;

    public static final int PAGING_CNT_TWENTY = 20;
    
    public static final int PAGING_CNT_FIFTY = 50;

    public static final String RESULT = "result";
    
    public static final String RESULT_DATA = "resultDate";
    
    public static final String RESULT_LIST = "resultList";
    
    public static final String SESSION_NAME = "USER_INFO";
    
    public static final String NOT_USER = "NU";
    
    public static final String TOP_MENU_ID = "TOP";
    
    public static final String EXIST_PHONE = "EP";
    
    public static final String NOT_EXIST_M_MOBILE = "NOT_MOBILE";
    
    public static final String FAIL_ACCOUNT_LOCK = "FAIL_ACCOUNT_LOCK";
    
    public static final String FAIL_ACCOUNT_TWO_MONTH_LOCK = "FAIL_ACCOUNT_TWO_MONTH_LOCK";
    
    public static final String FAIL_ACCOUNT_PWD_LOCK = "FAIL_ACCOUNT_PWD_LOCK";
    
    public static final String FAIL_ACCOUNT_DISABLED = "FAIL_ACCOUNT_DISABLED";
    
    public static final String FAIL_ACCOUNT_LOCK_INFO = "FAIL_ACCOUNT_LOCK_INFO";
    
    public static final String UN_USED_ID = "UN_USED_ID";
   
    public static final String FAIL_COUNT_OVER = "FAIL_COUNT_OVER";
    
    public static final String FAIL_COUNT_NOT_OVER = "FAIL_COUNT_NOT_OVER";
     
    public static final String PASSWORD_EXPIRED = "PASSWORD_EXPIRED";
    
    public static final String FAIL_ACCOUNT_CHG_PWD = "FAIL_ACCOUNT_CHG_PWD";
    
    public static final String NOT_ALLOW_FILE_EXT = "NOT_ALLOW_FILE_EXT";
    
    public static final String MESSAGE_URL = "/common/messageView.exclude";

    public static final String SYSTEM_AUTO = "SYSTEM_AUTO";
   
    public static final String ACCOUNT_NOMAL ="1";
    
    public static final String ACCOUNT_LOCK  ="2";
    
    public static final String ACCOUNT_DISABLED  ="3";
    
    public static final String ACCOUNT_PWD_LOCK  ="4";
    
    public static final String IGNORE_LAST_LOGIN_DT  ="5";
    
    public static final String YEAR ="YEAR";
    
    public static final String MONTH ="MONTH";
    
    public static final String DAY ="DAY";
    
    public static final String SYSTEM = "SYSTEM";
    
    public static final String EXIST = "E";
    
    public static final String NOT_EXIST = "NE";
    
    public static final String DUPLICATE = "D";
    
    public static final String DUPLICATE_CARD_NAME = "DCN";
    
    public static final String MAX_EXPOSURE_CARD = "MEC";
    
    public static final int MAX_EXPOSURE_CARD_CNT = 12;
    
    public static final String DUPLICATE_CARD_SROT_NUM = "DCSN";
    
    public static final String DUPLICATE_FIRM_VER = "DFV";
    
    public static final String DUPLICATE_TERMS_SORT_NUM = "DTSN";
    
    public static final String OVER = "O";
    
    public static final String ALL ="ALL";
    
    public static final String INSERT ="INSERT";
    
    public static final String UPDATE ="UPDATE";
    
    public int getBYTE_DIVISION() {
        return BYTE_DIVISION;
    }

    public String getPREVIEW_PATH() {
        return PREVIEW_PATH;
    }

    public String getPATH() {
        return PATH;
    }
    
    public static final class Table {
    	public static final String TB_BOARD = "TB_BOARD";
    	public static final String TB_COMMUNITY_FILE_INFO = "TB_COMMUNITY_FILE_INFO";
    	public static final String TB_PUSH_SEND_HISTORY = "TB_PUSH_SEND_HISTORY";
    	public static final String TB_EMAIL_SEND_HISTORY = "TB_EMAIL_SEND_HISTORY";
    	public static final String TB_SPLASH = "TB_SPLASH";
    	public static final String TB_SLEEP_EMAIL_NOTI = "TB_SLEEP_EMAIL_NOTI";
    	public static final String TB_BUSINESS_CATEGORY = "TB_BUSINESS_CATEGORY";
    }
    
    public static final class BoardMstId {
    	public static final String NOTICE = "notice";
    	public static final String BANNER = "banner";
    	public static final String PUSH = "push";
    	public static final String APPVERSION = "appversion";
    }
    
    public static final String POINT_MINUS_STATUS_CODE = "pointMinusStatusCode";
    
    public static final String CODE_0000001 = "0000001";
    public static final String CODE_0000002 = "0000002";
    public static final String CODE_0000003 = "0000003";
    public static final String CODE_0000004 = "0000004";
    public static final String CODE_0000005 = "0000005";
    public static final String CODE_0000017 = "0000017";
    public static final String CODE_0000018 = "0000018";
    public static final String CODE_0000022 = "0000022";
    public static final String CODE_0000037 = "0000037";
    
    public static final String PUSH_TYPE_102 = "102";
    public static final String PUSH_TYPE_103 = "103";
    public static final String PUSH_TYPE_104 = "104";
    public static final String PUSH_TYPE_109 = "109";
    public static final String PUSH_TYPE_110 = "110";
    
    
    public static final class BATCH_CODE {
    	/**
    	 * 사용자 이력 리포트 배치
    	 */
    	public static final String USER_HIST_REPORT_BATCH = "UHRB";
    	/**
    	 * 서비스 이용현황 등록 배치
    	 */
    	public static final String SERVICE_USE_STAT_BATCH = "SUSB";
    	/**
    	 * 상호별 리포트 등록 배치
    	 */
    	public static final String BRAND_REPORT_STAT_BATCH = "BRSB";
    	/**
    	 * 홈페이지 이용현황 등록 배치
    	 */
    	public static final String CONTACT_USE_STAT_BATCH = "CUSB";
    	/**
    	 * 홈페이지 배너 등록 배치
    	 */
    	public static final String CONTACT_BANNER_STAT_BATCH = "CBSB";
    	/**
    	 * 홈페이지 생활번호 등록 배치
    	 */
    	public static final String CONTACT_BUSINESS_CATE_BATCH = "CBCB";
    	
    }

    
    /**
	 * The enum Common code.
	 */
	public enum ResultCode {
		RESULT_CODE_0000("0000", "성공"), 
		RESULT_CODE_0001("0001", "성공( 조회시 데이터가 없는경우"),
		RESULT_CODE_3000("3000", "FIX CARD 포함"), 
		RESULT_CODE_3001("3001", "EXPOSURE CARD 포함"), 
		RESULT_CODE_4000("4000", "실패"), 
		
		
		
		/*RESULT_CODE_2000("2000", "존재하지 않는 약관 입니다."),
		RESULT_CODE_2001("2001", "요청한 약관의 수가 많거나 적습니다."),
		RESULT_CODE_2002("2002", "존재하지 않는 약관이 포함되어 있습니다."),
		
		
		RESULT_CODE_2010("2010", "지원하지 않는 좌표타입 입니다."),
		*//**
		 * 회원/인증 관련
		 *//*
		RESULT_CODE_3000("3000", "존재하지 않는 사용자 입니다."),
		RESULT_CODE_3001("3001", "사용자 인증 정보가 유효하지 않습니다."),
		RESULT_CODE_3002("3002", "허용되지 않은 CLIENT 입니다."),
		
		*//**
		 * 회원가입
		 *//*
		RESULT_CODE_2060("2060", "부정확한 AccessKey 입니다."),
		RESULT_CODE_2061("2061", "이미 존재하는 회원입니다. "),
		
		
		*//**
		 * 공통 
		 *//*
		RESULT_CODE_4002("4002", "바디 필수 파라메터 누락"), 
		RESULT_CODE_4003("4003", "지원되지 않는 http 메소드"),
		RESULT_CODE_4005("4005", "유효하지 않은 파라메터"),
		RESULT_CODE_4006("4006", "존재하지 않는 자원 호출"),		
		RESULT_CODE_4008("4008", "서비스아이디 불일치"), 
		
		RESULT_CODE_4010("4010", "제휴G/W 또는 POI 연동 오류"),
		RESULT_CODE_4012("4012", "제휴G/W 또는 POI  연동 타임아웃 발생"),
		
		RESULT_CODE_4020("4020", "No Data Result"),
		
		RESULT_CODE_4800("4800", "연동 접속 발생"),		
		RESULT_CODE_4801("4801", "연동 JSON Parsing 오류"),	
		RESULT_CODE_4802("4802", "연동 타임아웃 발생"),	
		
		RESULT_CODE_4904("4904", "IOException"), 
		RESULT_CODE_4910("4910", "DB접속 오류"), 
		RESULT_CODE_5000("5000", "서버에러(서비스)"),	
		
		
		RESULT_CODE_9997("9997", "작업공지")	,
		RESULT_CODE_9998("9998", "장애공지")	,
		RESULT_CODE_9999("9999", "FADEOUT 공지")	*/
		;
		
		private String code;

		private String msg;

		ResultCode(String code, String msg){
			this.code = code;
			this.msg = msg;
		}

		public String getCode() {
			return code;
		}

		public String getMsg() {
			return msg;
		}

		public static ResultCode keyOf(String key) {
			
			ResultCode[] areas = ResultCode.values();
			for(int i = 0; i < areas.length; i++) {
				if(areas[i].code.equals(key)) {
					return areas[i];
				}
			}
			return null;
		}		
	}

    public static final String OKTA_CLIENT_ID = "client_id";
    public static final String OKTA_CLIENT_SECRET = "client_secret";
    public static final String OKTA_RESPONSE_TYPE = "response_type";
    public static final String OKTA_CODE = "code";
    public static final String OKTA_SCOPE = "scope";
    public static final String OKTA_EMAIL = "email";
    public static final String OKTA_PROFILE = "profile";
    public static final String OKTA_STATE = "state";
    public static final String OKTA_NONE = "none";
    public static final String OKTA_ID_TOKEN = "id_token";
    public static final String OKTA_ACCESS_TOKEN = "access_token";
    public static final String OKTA_REFRESH_TOKEN = "refresh_token";

}
