# 1、yum源

```
一、站点版  
（一）、企业站  
1.搜狐：[http://mirrors.sohu.com/](http://mirrors.sohu.com/)  
2.网易：[http://mirrors.163.com/](http://mirrors.163.com/)  
3.阿里云：[http://mirrors.aliyun.com/](http://mirrors.aliyun.com/)  
4.腾讯：[http://android-mirror.bugly.qq.com:8080/](http://android-mirror.bugly.qq.com:8080/)（仅针对APP开发的软件，限流，不推荐）

（二）、教育站  
1.上海交通大学：[http://ftp.sjtu.edu.cn/html/resources.xml](http://ftp.sjtu.edu.cn/html/resources.xml)（部分移动运营商出口状况不佳，无法访问）  
2.华中科技大学：[http://mirror.hust.edu.cn/](http://mirror.hust.edu.cn/)（当前已用容量估计：4.83T）  
3.清华大学：[http://mirrors.tuna.tsinghua.edu.cn/](http://mirrors.tuna.tsinghua.edu.cn/)（当前已用容量估计：9.8T）  
4.北京理工大学：[http://mirror.bit.edu.cn/web/](http://mirror.bit.edu.cn/web/)  
5.兰州大学：[http://mirror.lzu.edu.cn/](http://mirror.lzu.edu.cn/)  
6.中国科技大学：[http://mirrors.ustc.edu.cn/](http://mirrors.ustc.edu.cn/)（当前已用容量估计：21.32T）  
7.大连东软信息学院：[http://mirrors.neusoft.edu.cn/](http://mirrors.neusoft.edu.cn/)（当前已用容量估计：2.5T）  
8.东北大学：[http://mirror.neu.edu.cn/](http://mirror.neu.edu.cn/)  
9.大连理工大学：[http://mirror.dlut.edu.cn/](http://mirror.dlut.edu.cn/)  
10.哈尔滨工业大学：[http://run.hit.edu.cn/html/](http://run.hit.edu.cn/html/)（部分联通运营商出口状况不佳，无法访问）  
11.北京交通大学：[http://mirror.bjtu.edu.cn/cn/](http://mirror.bjtu.edu.cn/cn/)  
12.天津大学：[http://mirror.tju.edu.cn](http://mirror.tju.edu.cn/)（无法访问，ping超时）  
13.中国地质大学：[http://mirrors.cug.edu.cn/](http://mirrors.cug.edu.cn/)（当前已用容量估计：2.3T）  
14.浙江大学：[http://mirrors.zju.edu.cn/](http://mirrors.zju.edu.cn/)  
15.厦门大学：[http://mirrors.xmu.edu.cn/](http://mirrors.xmu.edu.cn/)  
16.中山大学：[http://mirror.sysu.edu.cn/](http://mirror.sysu.edu.cn/)  
17.重庆大学：[http://mirrors.cqu.edu.cn/](http://mirrors.cqu.edu.cn/)（当前已用容量估计：3.93T）  
18.北京化工大学：[http://ubuntu.buct.edu.cn/](http://ubuntu.buct.edu.cn/)（Android SDK镜像仅供校内使用，当前已用容量估计：1.72T）  
19.南阳理工学院：[http://mirror.nyist.edu.cn/](http://mirror.nyist.edu.cn/)  
20.中国科学院：[http://www.opencas.org/mirrors/](http://www.opencas.org/mirrors/)  
21.电子科技大学：[http://ubuntu.uestc.edu.cn/](http://ubuntu.uestc.edu.cn/)（无法访问，ping超时）  
22.电子科技大学星辰工作室：[http://mirrors.stuhome.net/](http://mirrors.stuhome.net/)（当前已用容量估计：1.08T）  
23.西北农林科技大学：[http://mirrors.nwsuaf.edu.cn/](http://mirrors.nwsuaf.edu.cn/)（只做CentOS镜像，当前已用容量估计：140GB）

（三）、其他  
1.首都在线科技股份有限公司（英文名Capital Online Data Service）：[http://mirrors.yun-idc.com/](http://mirrors.yun-idc.com/)  
2.中国电信天翼云：[http://mirrors.ctyun.cn/](http://mirrors.ctyun.cn/)  
3.noc.im：[http://mirrors.noc.im/](http://mirrors.noc.im/)（当前已用容量估计：3.74T）  
4.常州贝特康姆软件技术有限公司：[http://centos.bitcomm.cn/](http://centos.bitcomm.cn/)（只做CentOS镜像，当前已用容量估计：140GB）  
5.公云PubYun（母公司为贝特康姆）：[http://mirrors.pubyun.com/](http://mirrors.pubyun.com/)  
6.Linux运维派：[http://mirrors.skyshe.cn/](http://mirrors.skyshe.cn/)（使用阿里云服务器，界面使用浙江大学的模板，首页维护，内容可访问）  
7.中国互联网络信息中心：[http://mirrors.cnnic.cn/](http://mirrors.cnnic.cn/)（只做Apache镜像，当前已用容量估计：120GB）  
8.Fayea工作室：[http://apache.fayea.com/](http://apache.fayea.com/)（只做Apache镜像，当前已用容量估计：120GB）

二、软件版

（一）、操作系统类  
1.Ubuntu  
阿里云：[http://mirrors.aliyun.com/ubuntu-releases/](http://mirrors.aliyun.com/ubuntu-releases/)  
网易：[http://mirrors.163.com/ubuntu-releases/](http://mirrors.163.com/ubuntu-releases/)  
搜狐：[http://mirrors.sohu.com/ubuntu-releases/](http://mirrors.sohu.com/ubuntu-releases/)（搜狐在12年之后似乎不同步了）  
首都在线科技股份有限公司：[http://mirrors.yun-idc.com/ubuntu-releases/](http://mirrors.yun-idc.com/ubuntu-releases/)

2.centos  
网易：[http://mirrors.163.com/centos/](http://mirrors.163.com/centos/)  
搜狐：[http://mirrors.sohu.com/centos/](http://mirrors.sohu.com/centos/)  
阿里云：[http://mirrors.aliyun.com/centos/](http://mirrors.aliyun.com/centos/)

（二）、服务器类  
1.tomcat、Apache  
中国互联网络信息中心：[http://mirrors.cnnic.cn/apache/](http://mirrors.cnnic.cn/apache/)  
华中科技大学：[http://mirrors.hust.edu.cn/apache/](http://mirrors.hust.edu.cn/apache/)  
北京理工大学：[http://mirror.bit.edu.cn/apache/](http://mirror.bit.edu.cn/apache/)

2.MySQL  
北京理工大学：[http://mirror.bit.edu.cn/mysql/Downloads/](http://mirror.bit.edu.cn/mysql/Downloads/)  
中国电信天翼云：[http://mirrors.ctyun.cn/Mysql/](http://mirrors.ctyun.cn/Mysql/)

3.PostgreSQL  
浙江大学：[http://mirrors.zju.edu.cn/postgresql/](http://mirrors.zju.edu.cn/postgresql/)

4.MariaDB  
中国电信天翼云：[http://mirrors.ctyun.cn/MariaDB/](http://mirrors.ctyun.cn/MariaDB/)

5.VideoLAN  
大连东软信息学院：[http://mirrors.neusoft.edu.cn/videolan/](http://mirrors.neusoft.edu.cn/videolan/)  
中国科技大学：[http://mirrors.ustc.edu.cn/videolan-ftp/](http://mirrors.ustc.edu.cn/videolan-ftp/)

（三）、开发工具类  
1.eclipse  
中国科技大学：[http://mirrors.ustc.edu.cn/eclipse/](http://mirrors.ustc.edu.cn/eclipse/)  
中国科学院：[http://mirrors.opencas.cn/eclipse/](http://mirrors.opencas.cn/eclipse/)  
东北大学：[http://ftp.neu.edu.cn/mirrors/eclipse/](http://ftp.neu.edu.cn/mirrors/eclipse/)，[http://mirror.neu.edu.cn/eclipse/](http://mirror.neu.edu.cn/eclipse/)

2.安卓SDK  
中国科学院：[http://mirrors.opencas.ac.cn/android/repository/](http://mirrors.opencas.ac.cn/android/repository/)  
南洋理工学院：[http://mirror.nyist.edu.cn/android/repository/](http://mirror.nyist.edu.cn/android/repository/)  
中国科学院：[http://mirrors.opencas.cn/android/repository/](http://mirrors.opencas.cn/android/repository/)  
腾讯：[http://android-mirror.bugly.qq.com:8080/android/repository/](http://android-mirror.bugly.qq.com:8080/android/repository/)（限流，不推荐）  
大连东软信息学院：[http://mirrors.neusoft.edu.cn/android/repository/](http://mirrors.neusoft.edu.cn/android/repository/)（同步效果不如中科院的镜像，不推荐）

3.Xcode  
腾讯：[http://android-mirror.bugly.qq.com:8080/Xcode/](http://android-mirror.bugly.qq.com:8080/Xcode/)（从7.2之后不再更新，建议直接从官网下载）

三、官方镜像列表状态地址  
CentOS：[http://mirror-status.centos.org/#cn](http://mirror-status.centos.org/#cn)  
Archlinux：[https://www.archlinux.org/mirrors/status/](https://www.archlinux.org/mirrors/status/)  
Ubuntu：[https://launchpad.net/ubuntu/+cdmirrors](https://launchpad.net/ubuntu/+cdmirrors)  
Debian：[http://mirror.debian.org/status.html](http://mirror.debian.org/status.html)  
Fedora Linux/Fedora EPEL：[https://admin.fedoraproject.org/mirrormanager/mirrors](https://admin.fedoraproject.org/mirrormanager/mirrors)  
Apache：[http://www.apache.org/mirrors/#cn](http://www.apache.org/mirrors/#cn)

Cygwin：[https://www.cygwin.com/mirrors.html](https://www.cygwin.com/mirrors.html)
```

## aliyun

CentOS 7
```
wget -O /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo

sed -i -e '/mirrors.cloud.aliyuncs.com/d' -e '/mirrors.aliyuncs.com/d' /etc/yum.repos.d/CentOS-Base.repo

```

