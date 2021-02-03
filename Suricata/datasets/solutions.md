* Write rules detecting default user-agents (exact matches on lowercase strings are fine);
    * Python;
    * Nikto;
    * Dirbuster;
    * Nmap;
    * Curl

```
alert http any any -> any any (msg:"Default user-agent seen"; http.user_agent; dataset:isset,task1, type string, state /tmp/task1.lst, memcap 10mb, hashsize 5; sid:2001; rev:1;)
```

```
./bin/suricatasc -c "dataset-add task1 string $(echo -n python | base64)"
./bin/suricatasc -c "dataset-add task1 string $(echo -n nikto | base64)"
./bin/suricatasc -c "dataset-add task1 string $(echo -n dirbuster | base64)"
./bin/suricatasc -c "dataset-add task1 string $(echo -n nmap | base64)"
./bin/suricatasc -c "dataset-add task1 string $(echo -n curl | base64)"
```

* Create a `string` list of all unique **dns queries**, **http user-agents**, **http.uri**, **ja3 fingerprints** and **TLS certificate issuers**;
  * lists should be generated **without getting any alerts**;
  * Verify each list element with `base64 -d`;

```
./bin/suricata -S ~/datasets.rules  --unix-socket -D
```

```
./bin/suricatasc -c "pcap-file /home/student/pcap/suricata-course/2021-01-12-Hancitor-infection-with-Cobalt-Strike.pcap /tmp"
./bin/suricatasc -c "dataset-dump"
```

```
alert dns any any -> any any (msg:"Track unique dns queries"; dns.query; dataset:set,task21, type string, state /tmp/task21.lst, memcap 10mb, hashsize 10000; sid:2002; rev:1; flowbits: noalert;)
alert http any any -> any any (msg:"Track unique user-agents"; http.user_agent; dataset:set,task22, type string, state /tmp/task22.lst, memcap 10mb, hashsize 5; sid:2003; rev:1; flowbits: noalert;)
alert http any any -> any any (msg:"Track unique URIs"; http.uri; dataset:set,task23, type string, state /tmp/task23.lst, memcap 10mb, hashsize 10000; sid:2004; rev:1; flowbits: noalert;)
alert tls any any -> any any (msg:"Track unique TLS ja3"; ja3.hash; dataset:set,task24, type string, state /tmp/task24.lst, memcap 10mb, hashsize 10000; sid:2005; rev:1; flowbits: noalert;)
alert tls any any -> any any (msg:"Track unique TLS SNI"; tls.sni; dataset:set,task25, type string, state /tmp/task25.lst, memcap 10mb, hashsize 10000; sid:2006; rev:1; flowbits: noalert;)
```

```
 cat /tmp/task21.lst  | while read line ; do echo $line | base64 -d ; printf "\n" ; done
```

* From those lists, select some interesting values and add them to new dataset;
  * Ensure that you get alerts when those elements are observed in PCAP or on wire;

```
alert http any any -> any any (msg:"Bad URI seen"; http.uri; dataset:isset,task3, type string, state /tmp/task3.lst, memcap 10mb, hashsize 10000; sid:2007; rev:1;)
```

```
dataset-add task3 $(echo -n "/2112.bin" | base64)
dataset-add task3 $(echo -n "/2112s.bin" | base64)
```


* Write a script that generates a dataset called `ad-domain-blacklist` from [this hosts file](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts);
  * Enhance the prior solution to also add reputation value for each entry;

```
alert dns any any -> any any (msg:"adware domain seen"; dns.query; dataset:isset,task4, type string, state /tmp/task4.lst, memcap 10mb, hashsize 10000; sid:2008; rev:1;)
```

```
for domain in $(curl -ss https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | grep 0.0.0.0 | grep -v "^#" | cut -d " " -f2 | grep -v 0.0.0.0); do
    /home/student/tools/suricata-7-datasets-ops-no-profiling/bin/suricatasc -c "dataset-add task4 string $(echo -n $domain | base64)"
done
```

Alert only if domain reputation is really bad

```
alert dns any any -> any any (msg:"adware domain seen"; dns.query; datarep:task4,>,200, type string, state /tmp/task4.rep; sid:2009; rev:1;)
```

```
printf "%s,100" $(echo -n "adware.domain" | base64) > /tmp/task4.rep
```
