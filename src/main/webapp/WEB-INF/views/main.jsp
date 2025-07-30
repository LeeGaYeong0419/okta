<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html>
<head>
  <title>Okta 인증 결과</title>
  <style>
    body { font-family: 'Malgun Gothic', Arial, sans-serif; background: #f7f8fa; }
    .container { max-width: 700px; margin: 80px auto; background: #fff; padding: 30px 40px; border-radius: 14px; box-shadow: 0 4px 20px #8882;}
    h2 { color: #007dc1; }
    .token-box { background: #f1f1f7; padding: 18px; border-radius: 10px; font-size: 0.98em; margin-bottom: 24px; }
    .user-info { background: #e7f7ff; padding: 18px; border-radius: 10px; }
    pre { overflow-x: auto; }
  </style>
</head>
<body>
<div class="container">
  <h2>Okta 인증 성공 🎉</h2>

  <div class="token-box">
    <b>Access Token:</b><br/>
    <pre>${access_token}</pre>
  </div>

  <div class="token-box">
    <b>ID Token:</b><br/>
    <pre>${id_token}</pre>
  </div>

  <div class="token-box">
    <b>Refresh Token:</b><br/>
    <pre>${refresh_token}</pre>
  </div>

</div>
</body>
</html>
