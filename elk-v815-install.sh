# create by zombic365
#!/bin/bash

ELK_PATH="/DATA/ELK"
PKG_PATH="${ELK_PATH}/pkgs"
SVC_NAME="elk"

if [ -d ${ELK_PATH} ]; then
    if [ -d ${PKG_PATH} ]; then
        for _pkg in elasticsearch logstash kibana; do
            cd ${PKG_PATH}
            if [ -f ${ELK_PATH}/${_pkg} ]; then
                echo "Install -> ${ELK_PATH}/${_pkg} skip."
                continue
            fi
            curl -O https://artifacts.elastic.co/downloads/${_pkg}/${_pkg}-8.15.2-linux-x86_64.tar.gz
            curl https://artifacts.elastic.co/downloads/${_pkg}/${_pkg}-8.15.2-linux-x86_64.tar.gz.sha512 |shasum -a 512 -c -
            if [ $? -eq 0 ]; then
                tar -zxf ./${_pkg}-8.15.2-linux-x86_64.tar.gz -C ${ELK_PATH}/.
                cd ${ELK_PATH}
                ln -s ${_pkg}-8.15.2 ${_pkg}
            fi
        done
    fi
fi

if [ ! -f ${PKG_PATH}/${SVC_NAME}-instances.yml ]; then
    cat <<EOF >${PKG_PATH}/${SVC_NAME}-instances.yml
instances:
- name: ${SVC_NAME}
    dns: [ '${SVC_NAME}' ]
    EOF
fi

${ELK_PATH}/elasticsearch/bin/elasticsearch-certutil \
cert \
--keep-ca-key \
--pem \
--in ${PKG_PATH}/${SVC_NAME}-instances.yml \
--out ${PKG_PATH}/${SVC_NAME}-certs.zip
