ngx_http_rc4_filter_module
==========================

RC4加密HTTP响应体


rc4_body
--------

**syntax:** *rc4_body &lt;on|off&gt;*

**context:** *http, server, location*

是否启用RC4加密


rc4_key
--------

**syntax:** *rc4_key &lt;$key of rc4&gt;*

**context:** *http, server, location*

RC4密码,可以使用变量


rc4_buff_size
-------------

**syntax:** *rc4_buff_size &lt;size&gt;*

**context:** *http, server, location*

用于加密过程的随时缓冲区大小, 默认512字节


配置示例
--------

    location /demo {
        set $key1 '123';
        set $key2 '456';
        content_by_lua ' ngx.say("Hello world.")';
        rc4_body on;
        rc4_key $key1$key2;
    }
