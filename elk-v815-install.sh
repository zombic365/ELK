# create by zombic365
#!/bin/bash

ELK_PATH="/DATA/ELK"
PKG_PATH="${ELK_PATH}/pkgs"

if [ -d ${ELK_PATH} ]; then
    if [ -d ${PKG_PATH} ]; then
        cd ${PKG_PATH}
        for _pkg in elasticsearch logstash kibana; do
            curl -O https://artifacts.elastic.co/downloads/${_pkg}/${_pkg}-8.15.2-linux-x86_64.tar.gz
            curl -O https://artifacts.elastic.co/downloads/${_pkg}/${_pkg}-8.15.2-linux-x86_64.tar.gz.sha512 |shasum -a 512 -c -
            if [ $? -eq 0 ]; then
                tar -zxf ./${_pkg}-8.15.2-linux-x86_64.tar.gz -C ${ELK_PATH}/.
                cd ${ELK_PATH}
                ln -s ${_pkg}-8.15.2 ${_pkg}
            fi
        done
    fi
fi