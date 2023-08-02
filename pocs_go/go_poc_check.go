package pocs_go

import (
	"fmt"
	"github.com/veo/vscan/pocs_go/Metabase"
	"github.com/veo/vscan/pocs_go/chanjetTplus"
	"github.com/veo/vscan/pocs_go/dahua"
	"github.com/veo/vscan/pocs_go/nginx"
	"github.com/veo/vscan/pocs_go/other"
	"net/url"

	"github.com/veo/vscan/brute"
	"github.com/veo/vscan/pocs_go/HIKVISION"
	"github.com/veo/vscan/pocs_go/Springboot"
	"github.com/veo/vscan/pocs_go/ThinkPHP"
	"github.com/veo/vscan/pocs_go/apusic"
	"github.com/veo/vscan/pocs_go/confluence"
	"github.com/veo/vscan/pocs_go/f5"
	"github.com/veo/vscan/pocs_go/fastjson"
	"github.com/veo/vscan/pocs_go/fineReport"
	"github.com/veo/vscan/pocs_go/gitlab"
	"github.com/veo/vscan/pocs_go/haofeng"
	"github.com/veo/vscan/pocs_go/hongfanioffice"
	"github.com/veo/vscan/pocs_go/jboss"
	"github.com/veo/vscan/pocs_go/jenkins"
	"github.com/veo/vscan/pocs_go/jinheOA"
	"github.com/veo/vscan/pocs_go/landray"
	"github.com/veo/vscan/pocs_go/log4j"
	"github.com/veo/vscan/pocs_go/mcms"
	"github.com/veo/vscan/pocs_go/phpunit"
	"github.com/veo/vscan/pocs_go/seeyon"
	"github.com/veo/vscan/pocs_go/shiro"
	"github.com/veo/vscan/pocs_go/spark"
	"github.com/veo/vscan/pocs_go/sunlogin"
	"github.com/veo/vscan/pocs_go/tomcat"
	"github.com/veo/vscan/pocs_go/tongda"
	"github.com/veo/vscan/pocs_go/weaver"
	"github.com/veo/vscan/pocs_go/weblogic"
	"github.com/veo/vscan/pocs_go/yonyou"
	"github.com/veo/vscan/pocs_go/zabbix"
	"github.com/veo/vscan/pocs_go/zentao"
)

func POCcheck(wappalyzertechnologies []string, URL string, finalURL string, checklog4j bool) []string {
	var HOST string
	var technologies []string
	if host, err := url.Parse(URL); err == nil {
		HOST = host.Host
	}
	for tech := range wappalyzertechnologies {
		switch wappalyzertechnologies[tech] {
		case "Shiro":
			key := shiro.CVE_2016_4437(finalURL)
			if key != "" {
				technologies = append(technologies, fmt.Sprintf("GoPOC_Shiro|key:%s", key))
			}
		case "Apache Tomcat":
			username, password := brute.Tomcat_brute(URL)
			if username != "" {
				technologies = append(technologies, fmt.Sprintf("Brute_Tomcat|%s:%s", username, password))
			}
			if tomcat.CVE_2020_1938(HOST) {
				technologies = append(technologies, "GoPOC_Tomcat|CVE_2020_1938")
			}
			if tomcat.CVE_2017_12615(URL) {
				technologies = append(technologies, "GoPOC_Tomcat|CVE_2017_12615")
			}
		case "Basic":
			username, password := brute.Basic_brute(URL)
			if username != "" {
				technologies = append(technologies, fmt.Sprintf("Brute_basic|%s:%s", username, password))
			}
		case "Weblogic", "WebLogic":
			username, password := brute.Weblogic_brute(URL)
			if username != "" {
				if username == "login_page" {
					technologies = append(technologies, "Weblogic_login_page")
				} else {
					technologies = append(technologies, fmt.Sprintf("Brute_Weblogic|%s:%s", username, password))
				}
			}
			if weblogic.CVE_2014_4210(URL) {
				technologies = append(technologies, "GoPOC_Weblogic|CVE_2014_4210")
			}
			if weblogic.CVE_2017_3506(URL) {
				technologies = append(technologies, "GoPOC_Weblogic|CVE_2017_3506")
			}
			if weblogic.CVE_2017_10271(URL) {
				technologies = append(technologies, "GoPOC_Weblogic|CVE_2017_10271")
			}
			if weblogic.CVE_2018_2894(URL) {
				technologies = append(technologies, "GoPOC_Weblogic|CVE_2018_2894")
			}
			if weblogic.CVE_2019_2725(URL) {
				technologies = append(technologies, "GoPOC_Weblogic|CVE_2019_2725")
			}
			if weblogic.CVE_2019_2729(URL) {
				technologies = append(technologies, "GoPOC_Weblogic|CVE_2019_2729")
			}
			if weblogic.CVE_2020_2883(URL) {
				technologies = append(technologies, "GoPOC_Weblogic|CVE_2020_2883")
			}
			if weblogic.CVE_2020_14882(URL) {
				technologies = append(technologies, "GoPOC_Weblogic|CVE_2020_14882")
			}
			if weblogic.CVE_2020_14883(URL) {
				technologies = append(technologies, "GoPOC_Weblogic|CVE_2020_14883")
			}
			if weblogic.CVE_2021_2109(URL) {
				technologies = append(technologies, "GoPOC_Weblogic|CVE_2021_2109")
			}
		case "JBoss", "JBoss Application Server 7", "jboss", "jboss-as", "jboss-eap", "JBoss Web", "JBoss Application Server":
			if jboss.CVE_2017_12149(URL) {
				technologies = append(technologies, "GoPOC_jboss|CVE_2017_12149")
			}
			username, password := brute.Jboss_brute(URL)
			if username != "" {
				technologies = append(technologies, fmt.Sprintf("Brute_jboss|%s:%s", username, password))
			}
		case "JSON":
			fastjsonRceType := fastjson.Check(URL, finalURL)
			if fastjsonRceType != "" {
				technologies = append(technologies, fmt.Sprintf("GoPOC_FastJson|%s", fastjsonRceType))
			}
		case "Jenkins", "jenkins":
			if jenkins.Unauthorized(URL) {
				technologies = append(technologies, "GoPOC_jenkins|Unauthorized script")
			}
			if jenkins.CVE_2018_1000110(URL) {
				technologies = append(technologies, "GoPOC_jenkins|CVE_2018_1000110")
			}
			if jenkins.CVE_2018_1000861(URL) {
				technologies = append(technologies, "GoPOC_jenkins|CVE_2018_1000861")
			}
			if jenkins.CVE_2019_10003000(URL) {
				technologies = append(technologies, "GoPOC_jenkins|CVE_2019_10003000")
			}
		case "ThinkPHP", "thinkphp":
			if ThinkPHP.RCE(URL) {
				technologies = append(technologies, "GoPOC_ThinkPHP")
			}
		case "phpunit":
			if phpunit.CVE_2017_9841(URL) {
				technologies = append(technologies, "GoPOC_phpunit|CVE_2017_9841")
			}
		case "yonyou-seeyon-oa":
			if seeyon.SeeyonFastjson(URL) {
				technologies = append(technologies, "GoPOC_seeyon|SeeyonFastjson")
			}
			if seeyon.SessionUpload(URL) {
				technologies = append(technologies, "GoPOC_seeyon|SessionUpload")
			}
			if seeyon.CNVD_2019_19299(URL) {
				technologies = append(technologies, "GoPOC_seeyon|CNVD_2019_19299")
			}
			if seeyon.CNVD_2020_62422(URL) {
				technologies = append(technologies, "GoPOC_seeyon|CNVD_2020_62422")
			}
			if seeyon.CNVD_2021_01627(URL) {
				technologies = append(technologies, "GoPOC_seeyon|CNVD_2021_01627")
			}
			if seeyon.CreateMysql(URL) {
				technologies = append(technologies, "GoPOC_seeyon|CreateMysql")
			}
			if seeyon.DownExcelBeanServlet(URL) {
				technologies = append(technologies, "GoPOC_seeyon|DownExcelBeanServlet")
			}
			if seeyon.GetSessionList(URL) {
				technologies = append(technologies, "GoPOC_seeyon|GetSessionList")
			}
			if seeyon.InitDataAssess(URL) {
				technologies = append(technologies, "GoPOC_seeyon|InitDataAssess")
			}
			if seeyon.ManagementStatus(URL) {
				technologies = append(technologies, "GoPOC_seeyon|ManagementStatus")
			}
			if seeyon.BackdoorScan(URL) {
				technologies = append(technologies, "GoPOC_seeyon|Backdoor")
			}
			if seeyon.AuthorItyService(URL) {
				technologies = append(technologies, "GoPOC_seeyon|AuthorItyService")
			}
			if seeyon.GetAjaxDataServlet(URL) {
				technologies = append(technologies, "GoPOC_seeyon|GetAjaxDataServlet")
			}
			if seeyon.ConfigInfo(URL) {
				technologies = append(technologies, "GoPOC_seeyon|ConfigInof")
			}
			if seeyon.TestSql(URL) {
				technologies = append(technologies, "GoPOC_seeyon|TestSql")
			}
		case "登录页面":
			username, password, loginurl := brute.Admin_brute(finalURL)
			if loginurl != "" {
				technologies = append(technologies, fmt.Sprintf("Brute_admin|%s:%s", username, password))
			}
		case "Sunlogin":
			if sunlogin.SunloginRCE(URL) {
				technologies = append(technologies, "GoPOC_Sunlogin|RCE")
			}
		case "ZabbixSAML":
			if zabbix.CVE_2022_23131(URL) {
				technologies = append(technologies, "GoPOC_ZabbixSAML|bypass-login")
			}
		case "Spring", "Spring env", "spring-boot", "spring-framework", "spring-boot-admin":
			if Springboot.CVE_2022_22965(finalURL) {
				technologies = append(technologies, "GoPOC_Spring4Shell|CVE_2022_22965")
			}
		case "SpringGateway":
			if Springboot.CVE_2022_22947(URL) {
				technologies = append(technologies, "GoPOC_SpringGateway|CVE_2022_22947")
			}
		case "GitLab":
			if gitlab.CVE_2021_22205(URL) {
				technologies = append(technologies, "GoPOC_gitlab|CVE_2021_22205")
			}
		case "Confluence":
			if confluence.CVE_2021_26084(URL) {
				technologies = append(technologies, "GoPOC_confluence|CVE_2021_26084")
			}
			if confluence.CVE_2021_26085(URL) {
				technologies = append(technologies, "GoPOC_confluence|CVE_2021_26085")
			}
			if confluence.CVE_2022_26134(URL) {
				technologies = append(technologies, "GoPOC_confluence|CVE_2022_26134")
			}
			if confluence.CVE_2022_26138(URL) {
				technologies = append(technologies, "GoPOC_confluence|CVE_2022_26138")
			}
		case "f5 Big IP":
			if f5.CVE_2020_5902(URL) {
				technologies = append(technologies, "GoPOC_f5-Big-IP|CVE_2020_5902")
			}
			if f5.CVE_2021_22986(URL) {
				technologies = append(technologies, "GoPOC_f5-Big-IP|CVE_2021_22986")
			}
			if f5.CVE_2022_1388(URL) {
				technologies = append(technologies, "GoPOC_f5-Big-IP|CVE_2022_1388")
			}
		case "禅道":
			if zentao.CNVD_2022_42853(URL) {
				technologies = append(technologies, "GoPOC_zentao|CNVD_2022_42853")
			}
		case "spark-jobs":
			if spark.CVE_2022_33891(URL) {
				technologies = append(technologies, "GoPOC_spark|CVE_2022_33891")
			}
		case "蓝凌 OA":
			if landray.Landray_RCE(URL) {
				technologies = append(technologies, "GoPOC_Landray|Landray_RCE")
			}
		case "通达OA":
			if tongda.Get_user_session(URL) {
				technologies = append(technologies, "GoPOC_Tongda|Tongda_get_user_session")
			}
			if tongda.File_delete(URL) {
				technologies = append(technologies, "GoPOC_Tongda|Tongda_File_delete")
			}
			if tongda.File_upload(URL) {
				technologies = append(technologies, "GoPOC_Tongda|Tongda_File_upload")
			}
		case "铭飞MCms":
			if mcms.Front_Sql_inject(URL) {
				technologies = append(technologies, "GoPOC_Mcms|Mcms_Front_Sql_inject")
			}
		case "yonyou-fe":
			if yonyou.TemplateOfTaohong_manager(URL) {
				technologies = append(technologies, "GoPOC_yonyou|TemplateOfTaohong_manager")
			}
		case "yonyou-uclient":
			if yonyou.BshServlet(URL) {
				technologies = append(technologies, "GoPOC_yonyou|BshServlet")
			}
			if yonyou.Uapws(URL) {
				technologies = append(technologies, "GoPOC_yonyou|uapws")
			}
			if yonyou.NCFindWeb(URL) {
				technologies = append(technologies, "GoPOC_yonyou|NCFindWeb")
			}
			if yonyou.FileReceiveServlet(URL) {
				technologies = append(technologies, "GoPOC_yonyou|FileReceiveServlet")
			}
		case "YONYOU NC", "用友 NC Cloud", "Yonyou-NC":
			if yonyou.NCFindWeb(URL) {
				technologies = append(technologies, "GoPOC_yonyou|NCFindWeb")
			}
			if yonyou.FileReceiveServlet(URL) {
				technologies = append(technologies, "GoPOC_yonyou|FileReceiveServlet")
			}
			if yonyou.Nc_cloud_jsinvoke_upload_rce(URL) {
				technologies = append(technologies, "GoPOC_yonyou|Nc_cloud_jsinvoke_upload_rce")
			}
		case "yonyou-grp-u8":
			if yonyou.ProxySql(URL) {
				technologies = append(technologies, "GoPOC_yonyou|ProxySql")
			}
			if yonyou.Uapws(URL) {
				technologies = append(technologies, "GoPOC_yonyou|uapws")
			}
			if yonyou.UploadFileData(URL) {
				technologies = append(technologies, "GoPOC_yonyou|UploadFileData")
			}
			if yonyou.FileReceiveServlet(URL) {
				technologies = append(technologies, "GoPOC_yonyou|FileReceiveServlet")
			}
		case "ecology-oa", "ecology":
			if weaver.LnFileDownload(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA|LnFileDownload")
			}
			if weaver.GetSelectAllId(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA|GetSelectAllId")
			}
			if weaver.LoginSSOSql(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA|LoginSSOSql")
			}
			if weaver.GetSqlData(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA|GetSqlData")
			}
			if weaver.UsersData(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA|UsersData")
			}
			if weaver.QVD_2023_5012(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA SQL|QVD_2023_5012|复现参考链接：https://mp.weixin.qq.com/s/_NzNyWjMrx4DhMtrYGZlVQ")
			}
			if weaver.E_Cology_ChangeUserInfo(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA Found vuln E_Cology_信息泄露_爆破 loginId. 配合泛微E-Cology ofsLogin任意用户登录使用|复现参考链接：https://mp.weixin.qq.com/s/FtDYKhKlCC8pCshM6Q-1AA")
			}
			if weaver.E_Cology_ofsLogin_user_login(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA Found vuln E_Cology_ofsLogin.jsp任意用户登录漏洞|复现参考链接：https://mp.weixin.qq.com/s/FtDYKhKlCC8pCshM6Q-1AA")
			}
			if weaver.CheckServer_sql(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA Found vuln CheckServer-sql注入漏洞|复现参考链接：https://mp.weixin.qq.com/s/7Zvr0-9g-piLfH34V7swWA")
			}
			if weaver.HrmCareerApplyPerView_sql(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA Found vuln HrmCareerApplyPerView_sql注入漏洞")
			}
			if weaver.E_Cology_Database_Leak(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA Found 数据库信息泄露漏洞")
			}
			if weaver.E_Cology_filedownloadforoutdoc_sql(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA Found filedownloadforoutdoc_sql注入漏洞")
			}
			if weaver.E_Cology_byxml_xxe(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA Found E_Cology_byxml_xxe")
			}
			if weaver.E_Cology_syncuserinof_sql(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA Found E_Cology_syncuserinof_sql")
			}
			if weaver.E_Cology_bsh_servlet_rce(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA Found E_Cology_bsh_servlet")
			}
			if weaver.E_Cology_WorkflowServiceXml_rce(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA Found E_Cology_WorkflowServiceXml_rce|利用参考:https://github.com/zhiliao07/Apt_t00ls")
			}
			if weaver.E_Coloy_UserSelect_unauthorized(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA Found E_Coloy_UserSelect_unauthorized")
			}
			if weaver.E_Cology_OA_XmlRpcServlet_file_read(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA Found E_Cology_OA_XmlRpcServlet_file_read")
			}
		case "Resin":
			if weaver.E_Cology_Database_Leak(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA Found 数据库信息泄露漏洞")
			}
		case "ecology泛微e-office":
			if weaver.CVE_2023_2647(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA SQL|CVE_2023_2647|复现参考链接：https://mp.weixin.qq.com/s/4vJvjplAXE2TjOzJB0hMfQ")
			}
			if weaver.CVE_2023_2523(URL) {
				technologies = append(technologies, "GoPOC_泛微 OA SQL|CVE_2023_2523|复现参考链接：https://blog.csdn.net/qq_41904294/article/details/130832416")
			}
			if weaver.E_Office_do_excel_php_rce(URL) {
				technologies = append(technologies, "GoPOC_E_Office_do_excel_php_rce")
			}
			if weaver.E_Office_FlowCommon_uploald(URL) {
				technologies = append(technologies, "GoPOC_E_Office_FlowCommon_uploald")
			}
			if weaver.E_Cology_OA_XmlRpcServlet_file_read(URL) {
				technologies = append(technologies, "GoPOC_E_Cology_OA_XmlRpcServlet_file_read")
			}
			if weaver.E_Office_E_mobileAppinit_upload(URL) {
				technologies = append(technologies, "GoPOC_E_Office_E_mobileAppinit_upload")
			}
			if weaver.E_Office_SQLInjection_CNVD_2022_43246(URL) {
				technologies = append(technologies, "GoPOC_E_Office_SQLInjection_CNVD_2022_43246")
			}
		case "帆软数据决策系统":
			if fineReport.CNVD_2018_04757(URL) {
				technologies = append(technologies, "GoPOC_fineReport|CNVD-2018-04757")
			}
			if fineReport.Design_save_svg(URL) {
				technologies = append(technologies, "GoPOC_fineReport|Design_save_svg")
			}

		case "金蝶云星空":
			if apusic.Server_file(URL) {
				technologies = append(technologies, "GoPOC_apusic|Server_file")
			}
			if apusic.Win_server_file(URL) {
				technologies = append(technologies, "GoPOC_apusic|Win_server_file")
			}
			if apusic.Linux_server_file(URL) {
				technologies = append(technologies, "GoPOC_apusic|Linux_server_file")
			}
		case "红帆ioffice":
			if hongfanioffice.IoFileExport(URL) {
				technologies = append(technologies, "GoPOC_hongfan_ioffice|ioFileExport")
			}
		case "金和协同管理平台":
			if jinheOA.C6download(URL) {
				technologies = append(technologies, "GoPOC_jinheOA|C6download")
			}
		case "hikvision-ivms", "海康威视综合安防管理平台", "海康威视综合安防平台":
			if HIKVISION.CNVD_2021_14544(URL) {
				technologies = append(technologies, "GoPOC_HIKVISION|CNVD_2021_14544")
			}
			if HIKVISION.Downdb(URL) {
				technologies = append(technologies, "GoPOC_HIKVISION|Downdb")
			}
			if HIKVISION.Userxml(URL) {
				technologies = append(technologies, "GoPOC_HIKVISION|Userxml")
			}
			if HIKVISION.DATA(URL) {
				technologies = append(technologies, "GoPOC_HIKVISION|DATA")
			}
			if HIKVISION.Hikvision_api_files_rce(URL) {
				technologies = append(technologies, "GoPOC_api_file_uplaod_rce|海康威视综合安防管理平台文件上传漏洞|复现参考链接：https://mp.weixin.qq.com/s/4An-tUll11dBVozyYKxTfg")
			}
			if HIKVISION.Hikvision_iVMS_files_rce(URL) {
				technologies = append(technologies, "GoPOC_api_ivms_file_uplaod_rce|海康威视综合安防管理平台文件上传漏洞|复现参考链接：https://mp.weixin.qq.com/s/Wveo0X3857mBWFzNOcJHJw")
			}
			if HIKVISION.Hikvision_svm_api_files_rce(URL) {
				technologies = append(technologies, "GoPOC_svm_api_ivms_file_uplaod_rce|海康威视综合安防管理平台文件上传漏洞")

			}
			if HIKVISION.HIKVISION_ZHAFGL_Fastjson_RCE_nodns(URL) {
				technologies = append(technologies, "GoPOC_HIKVISION_ZHAFGL_Fastjson_RCE|海康威视综合安防管理平台fastjson漏洞")

			}
		case "皓峰通讯-智能防火墙":
			if haofeng.Setdomain(URL) {
				technologies = append(technologies, "GoPOC_haofeng|Setdomain")
			}
		case "chanjet-tplus":
			if chanjetTplus.QVD_2023_13612_SQL(URL) {
				technologies = append(technologies, "GoPOC_畅捷通T+|QVD_2023_13612_SQL")
			}
		case "nginxWebUI":
			if nginx.NginxWebUI_runCmd_rce(URL) {
				technologies = append(technologies, "GoPOC_NginxWebUI_runCmd_rce|参考链接：https://mp.weixin.qq.com/s/5N89pINE9SmpMFUoVJlgbA")
			}
		case "dahua-WP":
			if dahua.Dahua_devicePoint_addImgIco_upload_rce(URL) {
				technologies = append(technologies, "GoPOC_dahua_upload_rce|参考链接：https://github.com/thelostworldFree/dahua_upload_POC")
			}
			if dahua.Dahua_attachment_downloadByUrlAtt_file_read(URL) {
				technologies = append(technologies, "GoPOC_dahua_file_read|参考链接：https://mp.weixin.qq.com/s/x-yyaFrGc-cwS7Zm6rdwEg")
			}
		case "大华安防 DSS":
			if dahua.Dahua_attachment_downloadByUrlAtt_file_read(URL) {
				technologies = append(technologies, "GoPOC_dahua_file_read|参考链接：https://mp.weixin.qq.com/s/x-yyaFrGc-cwS7Zm6rdwEg")
			}
		case "Metabase":
			if Metabase.CVE_2023_38646(URL) {
				technologies = append(technologies, "GoPOC_CVE_2023_38646_RCE")
			}
		case "H3C/安博通/任子行/OEM系列安全产品":
			if other.Js_query_172_read_file(URL) {
				technologies = append(technologies, "GoPOC_js_query_172_read_file")
			}
		}
		if checklog4j {
			if log4j.Check(URL, finalURL) {
				technologies = append(technologies, "GoPOC_log4j|JNDI RCE")
			}
		}
	}

	return technologies
}
