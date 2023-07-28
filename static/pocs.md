# POC列表

```
pocs_go:

 +-------------------+------------------+-------------------------------------------------------------+
 | 系统               | 编号             | 描述                                                         |
 +-------------------+------------------+-------------------------------------------------------------+
 | F5 BIG-IP         | CVE-2022-1388    | F5 BIG-IP iControl REST - Remote Command Execution          |
 | F5 BIG-IP         | CVE-2021-22986   | F5 BIG-IP iControl REST - Remote Command Execution          |
 | F5 BIG-IP         | CVE-2020-5902    | F5 BIG-IP RCE                                               |
 | Confluence        | CVE-2022-26134   | RCE 1.3.0-7.4.17, 7.13.0-7.13.7, 7.14.0-7.14.3, 7.15.0      |
 |                   |                  | -7.15.2, 7.16.0-7.16.4, 7.17.0-7.17.4, 7.18.0-7.18.1        |
 | Confluence        | CVE_2021_26085   | Atlassian-Confluence-Server-7.5.1-Arbitrary-File-Read       |
 | Confluence        | CVE-2021-26084   | RCE < 6.13.23, 6.14.0-7.4.11, 7.5.0-7.11.6, 7.12.0-7.12.5   |
 | Gitlab            | CVE-2021-22205   | RCE on Gitlab version < 13.10.3                             |
 | Zabbix            | CVE-2022-23131   | Zabbix instances where SAML SSO authentication bypass       |
 | Sunlogin          | RCE              | Sunlogin RCE                                                |
 | Springboot        | CVE-2022-22965   | Spring Framework RCE via Data Binding on JDK 9+             |
 | Springboot        | CVE-2022-22947   | spring cloud gateway 3.1.1+ and 3.0.7+ remote code execution|
 | Apache Log4j      | CVE-2021-44228   | 2.0 <= Apache log4j2 <= 2.14.1, log4j remote code execution |
 | Apache Shiro      | CVE-2016-4437    | <= 1.2.4, shiro-550, rememberme deserialization rce         |
 | Apache Tomcat     | CVE-2017-12615   | 7.0.0 - 7.0.81, put method any files upload                 |
 | Apache Tomcat     | CVE-2020-1938    | 6, 7 < 7.0.100, 8 < 8.5.51, 9 < 9.0.31 arbitrary file read  |
 | Fsatjson          | VER-1262         | <= 1.2.62 fastjson autotype remote code execution           |
 | Jboss             | CVE_2017_12149   | Jboss AS 5.x/6.x rce                                        |
 | Jenkins           | CVE-2018-1000110 | user search                                                 |
 | Jenkins           | CVE-2018-1000861 | <= 2.153, LTS <= 2.138.3, remote code execution             |
 | Jenkins           | CVE-2018-1003000 | Groovy <= 2.61 Script Security <= 1.49 remote code execution|
 | Jenkins           | Unauthorized     | Unauthorized Groovy script remote code execution            |
 | Oracle Weblogic   | CVE-2014-4210    | 10.0.2 - 10.3.6, weblogic ssrf vulnerability                |
 | Oracle Weblogic   | CVE-2017-3506    | 10.3.6.0, 12.1.3.0, 12.2.1.0-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2017-10271   | 10.3.6.0, 12.1.3.0, 12.2.1.1-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2018-2894    | 12.1.3.0, 12.2.1.2-3, deserialization any file upload       |
 | Oracle Weblogic   | CVE-2019-2725    | 10.3.6.0, 12.1.3.0, weblogic wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2019-2729    | 10.3.6.0, 12.1.3.0, weblogic wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2020-2883    | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, iiop t3 deserialization rce |
 | Oracle Weblogic   | CVE-2020-14882   | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, 14.1.1.0, console rce       |
 | Oracle Weblogic   | CVE-2020-14883   | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, 14.1.1.0, console rce       |
 | Oracle Weblogic   | CVE-2021-2109    | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, 14.1.1.0, unauthorized jndi |
 | PHPUnit           | CVE_2017_9841    | 4.x < 4.8.28, 5.x < 5.6.3, remote code execution            |
 | Seeyon            | 10+ POC          | some poc                                                    |
 | ThinkPHP          | CVE-2019-9082    | < 3.2.4, thinkphp remote code execution                     |
 | ThinkPHP          | CVE-2018-20062   | <= 5.0.23, 5.1.31, thinkphp remote code execution           |
 +-------------------+------------------+-------------------------------------------------------------+
pocs_yml:

xrayV2 all 354 pocs

Nuclei 1700+ pocs


poc更新记录：

1.2023-06-30 QVD-2023-13612 用友畅捷通T SQL注入 [参考链接](https://github.com/Sweelg/QVD-2023-13612_TPlus-SQLvuln)
2.2023-07-01 海康威视isecure center 综合安防管理平台存在任意文件上传漏洞 [参考链接](https://mp.weixin.qq.com/s/4An-tUll11dBVozyYKxTfg)
3.2023-07-02 海康威视iVMS综合安防系统任意文件上传漏洞 [参考链接](https://mp.weixin.qq.com/s/Wveo0X3857mBWFzNOcJHJw)
4.2023-07-03 泛微OA QVD_2023_5012 SQL注入 [参考链接](https://mp.weixin.qq.com/s/_NzNyWjMrx4DhMtrYGZlVQ)
5.2023-07-03 泛微OA CVE_20223_2647 文件上传 [参考链接](https://mp.weixin.qq.com/s/4vJvjplAXE2TjOzJB0hMfQ)
6.2023-07-05 nginxWebUI runCmd命令执行漏洞 [参考链接](https://mp.weixin.qq.com/s/5N89pINE9SmpMFUoVJlgbA)
7.2023-07-06 合并工具Find-SomeThing未授权检测功能(待完成功能：https://github.com/Tsojan/TsojanScan 合并未授权检测) [参考链接](https://github.com/LittleBear4/Find-SomeThing)
8.2023-07-06 泛微OA CVE-2023-2523 文件上传 [参考链接](https://blog.csdn.net/qq_41904294/article/details/130832416)
9.2023-07-10 海康威视svm综合安防系统任意文件上传漏[暂无]
10.2023-07-11 E-Cology-CheckServer-sql [参考链接]（https://mp.weixin.qq.com/s/7Zvr0-9g-piLfH34V7swWA） 
11.2023-07-11 E-Cology-Database-Leak  [参考链接](https://www.lmlphp.com/user/17042/article/item/500812/) (2023-07-17已修复bug)
12.2023-07-11 E-Cology-HrmCareerApplyPerView-sql [参考链接](https://github.com/w-digital-scanner/w9scan/blob/aa725571897f095635c4b7660db5ce90c655946c/plugins/weaver_oa/1707.py#L13)
13.2023-07-11 E_Cology_filedownloadforoutdoc_sql (未测试)[参考链接](https://mp.weixin.qq.com/s/8ocAHc30OpEWha6nWI6UPA)
13.2023-07-13 dahua_upload_rce [参考链接](https://github.com/thelostworldFree/dahua_upload_POC)  
13.2023-07-13 E_Cology_byxml_xxe [参考链接](https://github.com/UltimateSec/ultimaste-nuclei-templates/blob/main/ecology-oa/ecology-oa-byxml-xxe.yaml)  
14.2023-07-17 Dahua_attachment_downloadByUrlAtt_file_read [参考链接](https://mp.weixin.qq.com/s/x-yyaFrGc-cwS7Zm6rdwEg) 
14.2023-07-24 Nc_cloud_jsinvoke_upload_rce [参考链接](https://mp.weixin.qq.com/s/axnVd0dH6HXJVHXWCAC7mg) 
14.2023-07-26 E_Cology_bsh_servlet_rce [参考链接](https://github.com/30579096/OA-EXPTOOL/blob/main/main/weaver/Bsh_RCE.py) 
14.2023-07-26 E_Cology_WorkflowServiceXml_rce [参考链接1](https://github.com/zhaoyumi/WeaverExploit_All/) [参考链接2](https://github.com/zhiliao07/Apt_t00ls) 
14.2023-07-27 CVE_2023_38646 [参考链接](https://github.com/UltimateSec/ultimaste-nuclei-templates/blob/main/metabase/CVE-2023-38646.yaml) 
14.2023-07-27 E_Coloy_UserSelect_unauthorized [参考链接](https://github.com/LittleBear4/OA-EXPTOOL/blob/main/book/weaver/ecologye-%E6%9C%AA%E6%8E%88%E6%9D%83%E8%AE%BF%E9%97%AE.yaml) 
14.2023-07-28 E_Cology_OA_XmlRpcServlet_file_read [参考链接](https://github.com/qingchenhh/qc_poc) 
14.2023-07-28 js_query_172_read_file [参考链接](https://mp.weixin.qq.com/s/mWoZ0MhrflFbok2ad_CI1A) 
14.2023-07-28 E_Office_FlowCommon_uploald [参考链接](https://github.com/LittleBear4/OA-EXPTOOL/blob/main/book/weaver/E-Office-FlowCommon-uploal.yaml) 
14.2023-07-28 E_Office_E_mobileAppinit_upload [参考链接](https://github.com/xinyisleep/pocscan/blob/ee0c74e68ec95b82a4e4ebcdb961d6ed18a44b77/%E6%B3%9B%E5%BE%AE/oa%E6%B3%9B%E5%BE%AEE-officeE-mobileAppinit.php%E5%AD%98%E5%9C%A8%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E.py) 

其他更新记录
1.2023-07-12 合并指纹1w+

```