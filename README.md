Clone the code

```bash
[root@racknerd-b20bda0 ~]# git clone https://github.com/Microflow-IO/modsecurity-for-anylog
Cloning into 'modsecurity-for-anylog'...
remote: Enumerating objects: 66, done.
remote: Counting objects: 100% (66/66), done.
remote: Compressing objects: 100% (49/49), done.
remote: Total 66 (delta 15), reused 63 (delta 15), pack-reused 0 (from 0)
Unpacking objects: 100% (66/66), done.
```

Modify the LISTEN_PORT and OUTPUT environment variables according to your situation. Here, LISTEN_PORT is the JSON port for GELF format input, and OUTPUT is the JSON output port for alerts, both carried over UDP.

```bash
[root@racknerd-b20bda0 ~]# cd modsecurity-for-anylog/
[root@racknerd-b20bda0 modsecurity-for-anylog]# ls
docker-compose.yml  LICENSE  modsecurity
[root@racknerd-b20bda0 modsecurity-for-anylog]# cat docker-compose.yml | grep env -A 4
    environment:
      LISTEN_PORT: 15155
      OUTPUT: 127.0.0.1:12201
      RULEPATH: /usr/local/openresty/nginx/conf/modsecurity/modsecurity.conf
```

Use docker compose up -d to start the container

```bash
[root@racknerd-b20bda0 modsecurity-for-anylog]# docker compose up -d
[+] Running 2/2
 ✔ Network modsecurity-for-anylog_default  Created                                   0.3s 
 ✔ Container uniwaf                        Started                                   0.4s 
[root@racknerd-b20bda0 modsecurity-for-anylog]# docker ps | grep uniwaf
82a5bbb5f1ee   registry.jxit.net.cn:5000/uniserver/uniwaf:git-25     "sh -xc 'uniwaf -a -…"   12 seconds ago   Up 11 seconds                                               uniwaf
```

The local modsecurity directory stores the alert rule files and maps them to /usr/local/openresty/nginx/conf/modsecurity/ in the container.

```bash
[root@racknerd-b20bda0 modsecurity-for-anylog]# ls modsecurity/
crs-setup.conf  makefile.test  modsecurity.conf  rules  unicode.mapping  
[root@racknerd-b20bda0 modsecurity-for-anylog]# ls modsecurity/rules/
crawlers-user-agents.data                        REQUEST-931-APPLICATION-ATTACK-RFI.conf
iis-errors.data                                  REQUEST-932-APPLICATION-ATTACK-RCE.conf
```

Modify the rule files under modsecurity/rules as needed, and restart the container for the changes to take effect.

```bash
[root@racknerd-b20bda0 modsecurity-for-anylog]# docker compose restart
[+] Restarting 1/1
 ✔ Container uniwaf  Started                                               10.5s
```


