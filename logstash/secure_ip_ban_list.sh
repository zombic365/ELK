#!/bin/bash

DATETT_FORMAT=`echo "$(date "+%b %d") [0-2][0-9]:[0-5][0-9]:[0-5][0-9]"`

if [ ! -f /var/log/secure_ip_list.log ]; then
    tocuh /var/log/secure_ip_list.log
fi

grep "${DATETT_FORMAT}.*Failed" /var/log/secure |awk '{print $(NF-3)}' |cut -d'.' -f-3 |sort -nr >/var/log/secure_ip_list.log
# Exmaple output
# 142.93.143
# 172.104.48
# 103.106.104
# 221.156.137
# 208.84.154
# 110.10.189
# ...

# grep "${DATETT_FORMAT}.*Failed" /var/log/secure |awk '{print $(NF-3)}' |cut -d'.' -f-3 |sort -n |uniq -c |sort -nr >/var/log/secure_ip_list.log

# Exmaple output
# 637 142.93.143
# 488 172.104.48
# 399 103.106.104
# 295 221.156.137
# 270 208.84.154
# 253 110.10.189
# ...