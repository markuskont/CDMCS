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
