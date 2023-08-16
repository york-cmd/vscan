package brute

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func addfingerprints404(technologies []string, req *pkg.Response) []string {
	// StatusCode 404
	if strings.Contains(req.Body, "thinkphp") {
		technologies = append(technologies, "ThinkPHP")
	}
	if strings.Contains(req.Body, "Hypertext Transfer Protocol") {
		technologies = append(technologies, "Weblogic")
	}
	if strings.Contains(req.Body, "font-family:Tahoma,Arial,sans-serif") {
		technologies = append(technologies, "Apache Tomcat")
	}
	if strings.Contains(req.Body, "Whitelabel Error Page") {
		technologies = append(technologies, "Spring")
	}
	return technologies
}

func addfingerprints403(payload string, technologies []string) []string {
	// StatusCode 403

	switch payload {
	case "/Runtime/Logs/", "/Runtime/Logs/Home/", "/Application//Runtime/Logs/Admin/", "/App/Runtime/Logs/", "/Application/Runtime/Logs/", "/runtime/log/":
		MetchSwitch := payload
		technologies = append(technologies, fmt.Sprintf("ThinkPHP-logs:%s", MetchSwitch))
	}
	return technologies
}

func addfingerprintsnormal(payload string, technologies []string, req *pkg.Response) []string {
	// StatusCode 200, 301, 302, 401, 500

	switch payload {
	case "/manager/html":
		if req.StatusCode == 401 && req.Header.Get("Www-Authenticate") != "" {
			technologies = append(technologies, fmt.Sprintf("Tomcat登录页面:%s", req.RequestUrl))
		}
	case "/console/login/LoginForm.jsp":
		if req.StatusCode == 200 && strings.Contains(req.Body, "Oracle") {
			technologies = append(technologies, fmt.Sprintf("Weblogic登录页面:%s", req.RequestUrl))
		}
	case "/wls-wsat", "/wls-wsat/CoordinatorPortType", "/wls-wsat/CoordinatorPortType11", "/_async/AsyncResponseService", "/_async/AsyncResponseServiceSoap12", "/uddiexplorer/SearchPublicRegistries.jsp", "/ws_utc/config.do":
		if req.StatusCode == 200 && (strings.Contains(req.Body, "weblogic") || strings.Contains(req.Body, "www.bea.com")) {
			technologies = append(technologies, fmt.Sprintf("Weblogic-/wls-wsat:%s", req.RequestUrl))
		}
	case "/jmx-console/":
		if req.StatusCode == 200 && strings.Contains(req.Body, "jboss.css") {
			technologies = append(technologies, fmt.Sprintf("Jboss登录界面：%s", req.RequestUrl))
		}
	case "/seeyon/":
		if strings.Contains(req.Body, "/seeyon/common/") {
			technologies = append(technologies, "seeyon")
		}
	case "/admin", "/admin-console", "/admin.asp", "/admin.aspx", "/admin.do", "/admin.html", "/admin.jsp", "/admin.php", "/admin/", "/admin/admin", "/admin/adminLogin.do", "/admin/checkLogin.do", "/admin/index.do", "/Admin/Login", "/admin/Login.aspx", "/admin/login.do", "/admin/menu", "/Adminer", "/adminer.php", "/administrator", "/adminLogin.do", "/checkLogin.do", "/doc/page/login.asp", "/login", "/Login.aspx", "/login/login", "/login/Login.jsp", "/manage", "/manage/login.htm", "/management", "/manager", "/manager.aspx", "/manager.do", "/manager.jsp", "/manager.jspx", "/manager.php", "/memadmin/index.php", "/myadmin/login.php", "/Systems/", "/user-login.html", "/wp-login.php":
		if reqlogin, err := pkg.HttpRequset(req.RequestUrl, "GET", "", true, nil); err == nil {
			if strings.Contains(reqlogin.Body, "<input") && (strings.Contains(reqlogin.Body, "pass") || strings.Contains(reqlogin.Body, "Pass") || strings.Contains(reqlogin.Body, "PASS")) {
				technologies = append(technologies, "AdminLoginPage")
				username, password, loginurl := Admin_brute(req.RequestUrl)
				if loginurl != "" {
					technologies = append(technologies, fmt.Sprintf("Brute_admin|%s:%s", username, password))
				}
			}
		}
	case "/zabbix/":
		if strings.Contains(req.Body, "www.zabbix.com") {
			technologies = append(technologies, "zabbix")
		}
	case "/grafana/":
		if strings.Contains(req.Body, "grafana-app") {
			technologies = append(technologies, "Grafana")
		}
	case "/zentao/":
		if strings.Contains(req.Body, "zentao/theme") {
			technologies = append(technologies, "zentao")
		}
	case "/actuator", "/actuator/archaius", "/actuator/auditevents", "/actuator/autoconfig", "/actuator/bindings", "/actuator/caches", "/actuator/channels", "/actuator/conditions", "/actuator/configprops", "/actuator/env", "/actuator/env.json", "/actuator/health", "/actuator/health.json", "/actuator/heapdump", "/heapdump", "/actuator/hystrix.stream", "/actuator/integrationgraph", "/actuator/mappings", "/actuator/metrics", "/actuator/routes", "/actuator/scheduledtasks", "/actuator/service-registry":
		technologies = append(technologies, fmt.Sprintf("Find-Actuator Spring env:%s", req.RequestUrl))
	case "/actuator/gateway/routes", "/actuator/gateway/globalfilters", "/actuator/gateway/routefilters":
		technologies = append(technologies, "Spring")
		technologies = append(technologies, "SpringGateway")
		technologies = append(technologies, fmt.Sprintf("Find-SpringGateway:%s", req.RequestUrl))
	case "/vendor/phpunit/phpunit/LICENSE", "/vendor/phpunit/phpunit/README.md":
		technologies = append(technologies, "phpunit")
		technologies = append(technologies, fmt.Sprintf("Find-phpunit:%s", req.RequestUrl))
	case "/wp-config.php.bak", "/wp-content/debug.log", "/wp-content/uploads/dump.sql", "/wp-json/", "/wp-json/wp/v2/users", "/.wp-config.php.swp":
		technologies = append(technologies, "WordPress")
		technologies = append(technologies, fmt.Sprintf("Find-WordPress:%s", req.RequestUrl))
	case "/actuator;/env;.css", "/api/actuator;/env;.css", "/api;/env;.css", "/;/env;.css":
		if strings.Contains(req.Body, "java.runtime.version") {
			technologies = append(technologies, fmt.Sprintf("Find-Actuator API bypass未授权访问:%s", req.RequestUrl))
		}
	case "/env", "/api/env", "/manage/env", "/management/env", "/api/actuator/env":
		if strings.Contains(req.Body, "java.runtime.version") {
			technologies = append(technologies, fmt.Sprintf("Find-Actuator API 未授权访问:%s", req.RequestUrl))
		}
	case "/httptrace", "/actuator/httptrace", "/jeecg-boot/actuator/httptrace", "/actuator;/httptrace", "/api/actuator;/httptrace", "/api/actuator/httptrace", "/actuator/httptrace;.css":
		if strings.Contains(req.Body, "{\"traces\"") {
			technologies = append(technologies, fmt.Sprintf("Find-Actuator httptrace API 未授权访问:%s", req.RequestUrl))
		}
	case "/admin/adminer.php", "/adminer/adminer.php", "//adminer.php", "/":
		if strings.Contains(req.Body, "- Adminer") {
			technologies = append(technologies, fmt.Sprintf("Find-Adminer.php:%s", req.RequestUrl))
		}
	case "/any800/echatManager.do":
		if strings.Contains(req.Body, "Any800全渠道智能客服") {
			technologies = append(technologies, fmt.Sprintf("800全渠道智能客服：%s", req.RequestUrl))
		}
	case "/toLogin", "/xxl-job/toLogin", "/xxl-job-admin/toLogin", "/xxl/toLogin", "/xxljob/toLogin":
		if strings.Contains(req.Body, "<a><b>XXL</b>JOB</a>") {
			technologies = append(technologies, fmt.Sprintf("Find-xxl-Job：%s", req.RequestUrl))
		}
	case "/WEB-INF/web.xml", "/static?/%2557EB-INF/web.xml", "/%2e/WEB-INF/web.xml":
		if strings.Contains(req.Body, "</web-app>") {
			technologies = append(technologies, fmt.Sprintf("Find-WEB-INF/web.xml文件泄漏：%s", req.RequestUrl))
		}
	case "/api/index.html", "/api.html", "/swagger", "/api/swagger-ui.html", "/swagger-ui.html", "/Swagger/ui/index", "/api/swaggerui", "/swagger/ui", "/swagger/codes", "/api/swagger/ui", "/libs/swaggerui", "/swagger-resources/configuration/ui", "/swagger-resources/configuration/security", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json", "/api/doc", "/docs/", "/doc.html", "/api-docs", "/v1/api-docs", "/v3/api-docs", "/swagger/swagger-ui.html", "/v1.x/swagger-ui.html", "/swagger-ui.html#/api-memory-controller", "/swagger.json", "/api/swagger.json", "/v2/api-docs", "/api/v2/api-docs", "/swagger-dubbo/api-docs", "/user/swagger-ui.html", "/template/swagger-ui.html", "/distv2/index.html", "/dubbo-provider/distv2/index.html", "/spring-security-rest/api/swagger-ui.html", "/spring-security-oauth-resource/swagger-ui.html", "/api/v2/swagger.json", "/v2/swagger.json":
		if strings.Contains(req.Body, "swagger") {
			technologies = append(technologies, fmt.Sprintf("Find-Swagger 文档接口：%s", req.RequestUrl))
		}
	case "/article?id=${7899*7899}":
		if strings.Contains(req.Body, "62394201") {
			technologies = append(technologies, fmt.Sprintf("Find-SpringBoot-SpEL：%s", req.RequestUrl))
		}
	case "/#/console/css/test.css", "/#/../console/css/test.css", "/#/../../console/css/test.css", "/console/css/test.css;/../../../", "/decision/system/info", "/console":
		if strings.Contains(req.Body, "WLS Administration Console") {
			technologies = append(technologies, fmt.Sprintf("Find-Oracle Weblogic 控制台：%s", req.RequestUrl))
		}
	case "/ConvertService.ashx":
		if strings.Contains(req.Body, "<Error>-7</Error>") {
			technologies = append(technologies, fmt.Sprintf("Find-Onlyoffice-未授权访问：%s", req.RequestUrl))
		}
	case "/nacos", "/nacos/index.html":
		if strings.Contains(req.Body, "<title>Nacos</title>") {
			technologies = append(technologies, fmt.Sprintf("Find-Nacos：%s", req.RequestUrl))
		}
	case "/v1/auth/users?pageNo=1&pageSize=10", "/nacos/v1/auth/users?pageNo=1&pageSize=10":
		if strings.Contains(req.Body, "<b>XXL</b>JOB") {
			technologies = append(technologies, fmt.Sprintf("Find-Nacos-noauth：%s", req.RequestUrl))
		}
	case "/app/kibana":
		if strings.Contains(req.Body, "kibanaWelcomeView") {
			technologies = append(technologies, fmt.Sprintf("Find-Kibana 未授权访问：%s", req.RequestUrl))
		}
	case "/core/auth/login/":
		if strings.Contains(req.Body, "JumpServer") {
			technologies = append(technologies, fmt.Sprintf("Find-JumpServer：%s", req.RequestUrl))
		}
	case "/api/index.php/v1/config/application?public=true":
		if strings.Contains(req.Body, "password") {
			technologies = append(technologies, fmt.Sprintf("Find-Joomla-未授权访问：%s", req.RequestUrl))
		}
	case "/jolokia/list", "/jolokia", "/actuator/jolokia":
		if strings.Contains(req.Body, "reloadByURL") {
			technologies = append(technologies, fmt.Sprintf("Find-jolokia：%s", req.RequestUrl))
		}
	case "/hystrix", "/api/hystrix", "/actuator/hystrix":
		if strings.Contains(req.Body, ">Hystrix Dashboard<") {
			technologies = append(technologies, fmt.Sprintf("Find-Hystrix：%s", req.RequestUrl))
		}
	case "/json/version":
		if strings.Contains(req.Body, "Protocol-Version") {
			technologies = append(technologies, fmt.Sprintf("Find-Headless- 未授权访问：%s", req.RequestUrl))
		}
	case "/api/systeminfo", "/harbor/api/systeminfo":
		if strings.Contains(req.Body, "harbor_version") {
			technologies = append(technologies, fmt.Sprintf("Find-Harbor API：%s", req.RequestUrl))
		}
	case "/cluster":
		if strings.Contains(req.Body, "hadoop") {
			technologies = append(technologies, fmt.Sprintf("Find-Hadoop：%s", req.RequestUrl))
		}
	case "/h2-console/":
		if strings.Contains(req.Body, "H2 Console") {
			technologies = append(technologies, fmt.Sprintf("Find-h2-console：%s", req.RequestUrl))
		}
	case "/graphql", "/v2/graphql", "/v1/graphql":
		if strings.Contains(req.Body, "query missing") {
			technologies = append(technologies, fmt.Sprintf("Find-Graphql 接口：%s", req.RequestUrl))
		}
	case "/monitor/login", "/grafana/login":
		if strings.Contains(req.Body, "Grafana</title>") {
			technologies = append(technologies, fmt.Sprintf("Find-Grafana：%s", req.RequestUrl))
		}
	case "/_cat":
		if strings.Contains(req.Body, "/_cat/master") {
			technologies = append(technologies, fmt.Sprintf("Elasticsearch 未授权访问：%s", req.RequestUrl))
		}
	case "/help/sys/help.html", "/js":
		if strings.Contains(req.Body, "$(this).attr(\"src\",\"image/btn_help_click") {
			technologies = append(technologies, fmt.Sprintf("Find-Ecology 文档：%s", req.RequestUrl))
		}
	case "/druid/webapp.json":
		if strings.Contains(req.Body, "RequestCount") {
			technologies = append(technologies, fmt.Sprintf("Find-Druid 未授权访问：%s", req.RequestUrl))
		}
	case "/druid/login.html":
		if strings.Contains(req.Body, "druid monitor") {
			technologies = append(technologies, fmt.Sprintf("Find-Druid：%s", req.RequestUrl))
		}
	case "/druid/index.html":
		if strings.Contains(req.Body, "druid") {
			technologies = append(technologies, fmt.Sprintf("Find-Druid：%s", req.RequestUrl))
		}
	case "/version":
		if strings.Contains(req.Body, "ApiVersion") {
			technologies = append(technologies, fmt.Sprintf("Find-Docker_Remote-未授权访问：%s", req.RequestUrl))
		}
	case "/lljfafd", "/api/lljfafd":
		if strings.Contains(req.Body, "'DEBUG = True'") {
			technologies = append(technologies, fmt.Sprintf("Find-Django-开启调试模式：%s", req.RequestUrl))
		}
	case "/ping":
		if strings.Contains(req.Body, "No Content") {
			technologies = append(technologies, fmt.Sprintf("Find-Clickhouse_REST_API：%s", req.RequestUrl))
		}
	case "/apps":
		if strings.Contains(req.Body, "ownerName") {
			technologies = append(technologies, fmt.Sprintf("Find-apollo- 未授权访问：%s", req.RequestUrl))
		}
	case "/cas/login":
		if strings.Contains(req.Body, "cas") {
			technologies = append(technologies, fmt.Sprintf("Find-Apereo_cas：%s", req.RequestUrl))
		}
	case "/solr/admin/cores?wt=json&indexInfo=false", "/admin/cores?wt=json&indexInfo=false":
		if strings.Contains(req.Body, "responseHeader") {
			technologies = append(technologies, fmt.Sprintf("Find-Apache solr未授权访问：%s", req.RequestUrl))
		}
	case "/webtools/control/main":
		if strings.Contains(req.Body, "Ofbiz") {
			technologies = append(technologies, fmt.Sprintf("Find-Apache Ofbiz：%s", req.RequestUrl))
		}
	case "/ueditor/ueditor.config.js", "/Plugins/ueditor/ueditor.config.js", "/Scripts/plugins/ueditor/ueditor.config.js", "/static/ueditor/ueditor.config.js", "/Content/ueditor/ueditor.config.js", "/Scripts/ueditor/ueditor.config.js", "/public/static/js/ueditor/ueditor.config.js", "/static/js/ueditor/ueditor.config.js":
		if strings.Contains(req.Body, "UEDITOR_HOME_URL") {
			technologies = append(technologies, fmt.Sprintf("Find-ueditor 编辑器：%s", req.RequestUrl))
		}
	case "/admin/editor/login_admin.asp", "/ewebeditor/admin_login.asp":
		if strings.Contains(req.Body, "ebeditor") {
			technologies = append(technologies, fmt.Sprintf("Find-ewebeditor：%s", req.RequestUrl))
		}
	case "/axis2/", "/axis2/axis2-admin/", "/axis2-admin/":
		if strings.Contains(req.Body, "axis-style.css") {
			technologies = append(technologies, fmt.Sprintf("Find-axis2：%s", req.RequestUrl))
		}
	case "/solr/index.html", "/Solr/index.html":
		if strings.Contains(req.Body, "<title>Solr Admin</title>") {
			technologies = append(technologies, fmt.Sprintf("Find-solr：%s", req.RequestUrl))
		}
	case "/ReportServer", "/report/ReportServer", "/seeyonreport/ReportServer", "/WebReport/ReportServer":
		if strings.Contains(req.Body, "FineReport,Web Reporting Tool") {
			technologies = append(technologies, fmt.Sprintf("Find-seeyon_report：%s", req.RequestUrl))
		}
	case "/pma/index.php", "/phpmyadmin/index.php", "/PhpMyAdmin/index.php":
		if strings.Contains(req.Body, "<title>phpMyAdmin</title>") {
			technologies = append(technologies, fmt.Sprintf("Find-phpMyAdmin：%s", req.RequestUrl))
		}
	case "/.git/config":
		if strings.Contains(req.Body, "[core]") {
			technologies = append(technologies, fmt.Sprintf("Find-/.git/config：%s", req.RequestUrl))
		}
	case "/dwr/index.html", "/_dwr/index.html":
		if strings.Contains(req.Body, "DWR Test Index") {
			technologies = append(technologies, fmt.Sprintf("Find-dwr：%s", req.RequestUrl))
		}
	case "/www.zip", "/bin.zip", "/www.rar", "/bin.rar", "/ROOT.war", "/ROOT.tar.gz", "/ROOT.zip", "/web.zip", "/web.rar", "/web.tar.gz", "/public.zip", "/public.rar":
		if (req.StatusCode == 200 || req.StatusCode == 206) && (strings.Contains(req.Header.Get("Content-Type"), "application/zip") || strings.Contains(req.Header.Get("Content-Type"), "application/octet-stream")) {
			technologies = append(technologies, fmt.Sprintf("Find-backup：%s", req.RequestUrl))
		}
	}

	return technologies
}
