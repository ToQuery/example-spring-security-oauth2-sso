# example-spring-security-oauth2-sso

http://spring-security-oauth2-sso-jwt.toquery-example.com:8010/oauth2/authorization/toquery

Spring Security OAuth2方式SSO登录

使用cookie方式设置state信息维护, 应用内部不会使用RSA证书，秘钥信息通过授权中心的元数据获取，跨应用调用token也会共用！但password方式在OAuth2.1已经被删除，还未验证
