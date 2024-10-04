# create by zombic365
#!/bin/bash

# 참조 blog
# https://velog.io/@mnetna/X-PACK-%EC%8B%9C%ED%81%90%EB%A6%AC%ED%8B%B0-%EB%AC%B4%EB%A3%8C-%EA%B8%B0%EB%8A%A5-%EC%82%AC%EC%9A%A9
# https://blog.binarynum.com/62
# https://jjeong.tistory.com/1433
# https://github.com/elastic/elasticsearch/blob/main/distribution/packages/src/common/systemd/elasticsearch.service

ELK_PATH="/DATA/ELK"
ELK_USER="elk_user"
PKG_PATH="${ELK_PATH}/pkgs"
SVC_NAME="elk"
SVC_URL="https://${SVC_NAME}"

if [ -d ${ELK_PATH} ]; then
    if [ -d ${PKG_PATH} ]; then
        for _pkg in elasticsearch logstash kibana; do
            cd ${PKG_PATH}
            if [ -d ${ELK_PATH}/${_pkg} ]; then
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

if [ ! -d ${PKG_PATH}/${SVC_NAME}-certs-root ]; then
    ${ELK_PATH}/elasticsearch/bin/elasticsearch-certutil \
    ca --silent --pem --days 365 \
    --pass "" \
    --out ${PKG_PATH}/${SVC_NAME}-certs-root.zip

    if [ $? -eq 0 ]; then
        unzip -d ${PKG_PATH}/${SVC_NAME}-certs-root ${PKG_PATH}/${SVC_NAME}-certs-root.zip

        for _svc in elasticsearch logstash kibana; do
            mkdir ${ELK_PATH}/${_svc}/config/certs
            cp -rfp ${PKG_PATH}/${SVC_NAME}-certs-root/* ${ELK_PATH}/${_svc}/config/certs/.
        done
    fi
else
    echo "Create -> ${PKG_PATH}/${SVC_NAME}-certs-root skip."
fi


if [ -f ${PKG_PATH}/${SVC_NAME}-instances.yml ]; then
    echo "Create -> ${PKG_PATH}/${SVC_NAME}-instances.yml skip."
else
    cat <<EOF >${PKG_PATH}/${SVC_NAME}-instances.yml
instances:
    - name: 'instances'
      dns: [ '${SVC_NAME}', '${SVC_NAME}.local' ]
EOF
fi

# [pem 방식]
if [ ! -d ${PKG_PATH}/${SVC_NAME}-certs-instances ]; then
    ${ELK_PATH}/elasticsearch/bin/elasticsearch-certutil \
    cert --silent --pem \
    --ca-cert ${PKG_PATH}/${SVC_NAME}-certs-root/ca/ca.crt \
    --ca-key ${PKG_PATH}/${SVC_NAME}-certs-root/ca/ca.key \
    --in ${PKG_PATH}/${SVC_NAME}-instances.yml \
    --out ${PKG_PATH}/${SVC_NAME}-certs-instances.zip

    if [ $? -eq 0 ]; then
        unzip -d ${PKG_PATH}/${SVC_NAME}-certs-instances ${PKG_PATH}/${SVC_NAME}-certs-instances.zip
        for _svc in elasticsearch logstash kibana; do
            cp -rfp ${PKG_PATH}/${SVC_NAME}-certs-instances/* ${ELK_PATH}/${_svc}/config/certs/.
        done
        
    fi
else
    echo "Create -> ${PKG_PATH}/${SVC_NAME}-certs-instances skip."
fi

for _svc in elasticsearch logstash kibana; do
    if [ ! -f ${ELK_PATH}/${_svc}/config/${_svc}.yml.org ]; then
        mv ${ELK_PATH}/${_svc}/config/${_svc}.yml ${ELK_PATH}/${_svc}/config/${_svc}.yml.org 
    fi
done

if [ ! -f ${ELK_PATH}/elasticsearch/config/elasticsearch.yml ]; then
    cat <<EOF >${ELK_PATH}/elasticsearch/config/elasticsearch.yml
cluster.name: ${SVC_NAME}
node.name: ${SVC_NAME}
path.data: ${ELK_PATH}/elasticsearch/data
path.logs: ${ELK_PATH}/elasticsearch/logs
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node

xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.key: certs/instances/instances.key
xpack.security.transport.ssl.certificate: certs/instances/instances.crt
xpack.security.transport.ssl.certificate_authorities:  [ "certs/ca/ca.crt" ]

xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.key: certs/instances/instances.key
xpack.security.http.ssl.certificate: certs/instances/instances.crt
xpack.security.http.ssl.certificate_authorities:  [ "certs/ca/ca.crt" ]
EOF
else
    echo "Create -> ${ELK_PATH}/elasticsearch/config/elasticsearch.yml skip."
fi

if [ ! -f ${ELK_PATH}/kibana/config/kibana.yml ]; then
    cat <<EOF >${ELK_PATH}/kibana/config/kibana.yml
server.name: "${SVC_NAME}"
server.host: 0.0.0.0
server.port: 5601
server.publicBaseUrl: https://${SVC_URL}:5601

path.data: ${ELK_PATH}/kibana/data
pid.file: ${ELK_PATH}/kibana/run/kibana.pid

logging.root.level: info
logging.appenders.default:
    type: rolling-file
    fileName: ${ELK_PATH}/kibana/logs/kibana.log
    policy:
        type: size-limit
        size: 256mb
    strategy:
        type: numeric
        max: 10
    layout:
        type: json

server.ssl.enabled: true
server.ssl.certificate: ${ELK_PATH}/kibana/config/certs/instances/instances.crt
server.ssl.key: ${ELK_PATH}/kibana/config/certs/instances/instances.key

elasticsearch.hosts: [ "https://${SVC_NAME}:9200" ]
elasticsearch.username: "kibana_system"
#### elasticsearch.password는 elasticsearch-setup-passwords 통해서 설정된 패스워드를 설정한다.
elasticsearch.password: "[elasticsearch-setup-passwords kibana_system or kibana 패스워드]"

elasticsearch.ssl.certificateAuthorities: [ "${ELK_PATH}/kibana/config/certs/ca/ca.crt" ]
EOF
else
    echo "Create -> ${ELK_PATH}/kibana/config/kibana.yml skip."
fi

for _pkg in elasticsearch kibana; do

sed 