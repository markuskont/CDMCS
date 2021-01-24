* Write rules detecting default user-agents, but only if response code from server was 200 (OK);
  * Python;
  * Nikto;
  * Dirbuster;
  * Nmap;
  * Curl

```
alert http any any -> any any (sid: 106; msg: "Alert on default user-agent"; http.user_agent; content: "python"; nocase; flowbits: set,UA; flowbits: noalert;);
alert http any any -> any any (sid: 107; msg: "Alert on default user-agent"; http.user_agent; content: "nikto"; nocase; flowbits: set,UA; flowbits: noalert;);
alert http any any -> any any (sid: 108; msg: "Alert on default user-agent"; http.user_agent; content: "dirbuster"; nocase; flowbits: set,UA; flowbits: noalert;);
alert http any any -> any any (sid: 109; msg: "Alert on default user-agent"; http.user_agent; content: "nmap"; nocase; flowbits: set,UA; flowbits: noalert;);
alert http any any -> any any (sid: 110; msg: "Alert on default user-agent"; http.user_agent; content: "curl"; nocase; flowbits: set,UA; flowbits: noalert;);

alert http any any -> any any (msg: "CHECK - 0"; sid: 100; http.stat_code; content: "200"; flowbits: isset,UA;)
```

* Inspect MTA case `2020-03-12-infection-traffic.pcap`;
    * Generate eve.json and inspect events;
    * Find the malicious file download;

```
cat eve.json | jq 'select(.event_type!="flow") | select(.event_type!="stats")'
cat eve.json | jq 'select(.event_type=="http")'
```

* Write a rule that triggers when that file is downloaded;
    * mind flow direction;
    * set up prefilter;
    * match on malicious file name;
    * this is highest priority match;

```
alert http any any -> any any (sid:111; msg: "Malicious file seen"; flow:to_server,established; http.method; content: "GET"; http.user_agent; content: "WinHttp.WinHttpRequest"; http.uri; content: "system_x64.exe"; endswith; priority: 1;)
```

* Generalize the rule to match on .exe file seen in http;

ET Open solution
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Request for EXE via WinHTTP M1"; flow:established,to_server; content:"GET"; http_method; content:".exe"; isdataat:!1,relative; http_uri; content:"Mozilla/4.0 (compatible|3b 20|Win32|3b 20|WinHttp.WinHttpRequest.5)"; http_user_agent; depth:57; isdataat:!1,relative; fast_pattern; http_header_names; content:!"Referer"; classtype:bad-unknown; sid:2029840; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2020_04_09, deployment Perimeter, former_category HUNTING, signature_severity Informational, updated_at 2020_04_09;)
```

Minimal solutions

```
alert http any any -> any any (sid: 112; msg: "EXE seen in HTTP"; flow:established,to_server; http.method; content: "GET"; http.uri; content: ".exe"; endswith;)
```

Variation that only locks down on specific user-agent;

```
alert http any any -> any any (sid: 113; msg: "EXE seen in HTTP for WINHTTP user-agent"; flow:established,to_server; http.method; content: "GET"; endswith; http.user_agent; content: "WinHttp.WinHttpRequest"; http.uri; content: ".exe";)
```

* Enhance the rule to only trigger if response was HTTP 301 or 200;

```
alert http any any -> any any (sid:114; msg: "Malicious file seen"; flow:to_server,established; http.method; content: "GET"; http.user_agent; content: "WinHttp.WinHttpRequest"; http.uri; content: "system_x64.exe"; endswith; flowbits: set,malfile; flowbits: noalert;)

alert http any any -> any any (msg: "CHECK - malfile download OK"; sid: 115; http.stat_code; content: "301"; flowbits: isset,malfile;)
alert http any any -> any any (msg: "CHECK - malfile redirection"; sid: 116; http.stat_code; content: "200"; flowbits: isset,malfile;)
```

* Identify stage 2 download domain and write a IOC rule;
    * highest priority alert;
    * mark the IOC in alert metadata;

```
 cat logs/elastic/eve.json| jq 'select(.alert.signature_id==113) | .http.redirect'
```

```
"redirect": "https://secure.zenithglobalplc.com/assets/plugins/bootstrap-wizard/system_x64.exe"
```

```
alert tls any any -> any any (msg: "MALICIOUS TLS SNI seen!"; sid: 117; tls.sni; content: "secure.zenithglobalplc.com"; metadata:ioc sni ; priority: 1;)
```

* Where is the CnC server?

```
alert tls any any -> any any (msg: "C2 server seen!"; flow:established,to_server; sid: 118; tls.sni; content: "105711.com"; metadata:ioc sni ; priority: 1;)
alert tls any any -> any any (msg: "C2 server seen!"; flow:established,to_client; sid: 119; tls.subject; content: "domain.com"; metadata:ioc cert_subject ; priority: 1;)
```
