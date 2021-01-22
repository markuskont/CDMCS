# Solutions

* Facebook certificate and dns req

```
alert dns any any -> any any (sid: 100; msg: "Alert on facebook dns request"; dns.query; content: "facebook";);
alert tls any any -> any any (sid: 103; msg: "Alert on facebook cert"; tls.sni; content: "facebook";)
```

* DNS domain with .su suffix

```
alert dns any any -> any any (sid: 104; msg: "Alert on soviet union domain"; dns.query; content: ".su"; endswith;);
```

* DNS zone transfer (tricky, use wireshark for help)

```
alert dns any any -> any any (sid: 105; msg: "Alert on zone transfer"; content: "|00 fc|";);
```

* Detection of popular default user-agents:
  * Python;
  * Nikto;
  * Dirbuster;
  * Nmap;
  * Curl

```
alert http any any -> any any (sid: 106; msg: "Alert on default user-agent"; http.user_agent; content: "python"; nocase;);
alert http any any -> any any (sid: 107; msg: "Alert on default user-agent"; http.user_agent; content: "nikto"; nocase;);
alert http any any -> any any (sid: 108; msg: "Alert on default user-agent"; http.user_agent; content: "dirbuster"; nocase;);
alert http any any -> any any (sid: 109; msg: "Alert on default user-agent"; http.user_agent; content: "nmap"; nocase;);
alert http any any -> any any (sid: 110; msg: "Alert on default user-agent"; http.user_agent; content: "curl"; nocase;);
```
