# Solutions

* Select your own folder where the rules should be located. 

```
mkdir $DIR
suricata-update -D $DIR
```

* Following rulesets should be activated:
  * `et/open`
  * `oisf/trafficid`
  * `ptresearch/attackdetection`
  * `tgreen/hunting`

```
suricata-update -D $DIR enable-source et/open
suricata-update -D $DIR enable-source osif/trafficid
suricata-update -D $DIR enable-source ptresearch/attackdetection
suricata-update -D $DIR enable-source tgreen/hunting
```

```
suricata-update -D $DIR
```

* Generate a report of alerts per MTA PCAP;

```bash
#!/bin/bash

PCAP_FOLDER="/home/student/pcap/suricata-course"
RULE_FILE="/home/student/suricata-update-working-dir/rules/suricata.rules"
FILES=$(find $PCAP_FOLDER -type f -name '*.pcap')

function start_suricata {
  sudo suricata --unix-socket -S $RULE_FILE -D
  # Simple-stupid approach, here we should try to connect to unix-socket repeatedly until timing out
  echo "Waiting for Suricata daemon to properly start up"
  sleep 45
}

# start suricata in daemon mode, sudo is needed as we are using system-wide installation
# meaning default log directory and unix socket directory are located in folders that student lacks permissions
pgrep Suricata || start_suricata


# First pass to signal suricata to load all MTA PCAPs
for f in $FILES; do
  fname=$(echo $f | rev | cut -d "/" -f1 | rev)
  echo $PCAP_FOLDER/$fname
  logdir=/tmp/logs/$fname
  mkdir -p $logdir
  # send signal itself, sudo is used as we ran Suricata as superuser already
  sudo suricatasc -c "pcap-file $f $logdir"
done

# report in-progress PCAP files
# this can be parsed into bash variable to check how many PCAP-s are still TODO
sudo suricatasc -c "pcap-file-list"

# another simple-stupid hack, pcap-file simply adds PCAP to queue, but it might not be done yet
# again, we should actuall check for active queue repeadedly until timing out
# MTA set small, 30 seconds should be enough
echo "Waiting for 30 seconds to ensure all pcaps are done"
sleep 30

# Second pass after waiting on all PCAPs to finish
for f in $FILES; do
  fname=$(echo $f | rev | cut -d "/" -f1 | rev)
  # Here we could check if pcap is done and optionally sleep
  # Generate a new report file
  logdir=/tmp/logs/$fname
  echo "generating report into $logdir"
  echo $fname > $logdir/report.txt
  # Aggregate unique alerts with counts into that file
  cat $logdir/eve.json | jq 'select(.event_type=="alert") | .alert.signature' | sort -h | uniq -c | sort -h >> $logdir/report.txt
done

cat /tmp/logs/*/report.txt  | less
```

* Disable following rules:
  * Outbound Curl user-agent;
  * apt and yum package management;
  * Unix and BSD ping;
  * Suricata STREAM rules;

```
re:curl user-agent
re:(apt|yum).+package
re:PING (\*NIX|BSD)
re:SURICATA STREAM
```

* Write a crontab script that updates your ruleset and invokes suricata rule reload **without restarting it**;

```
suricata-update -D $DIR
suricatasc -c "reload-rules"
```
