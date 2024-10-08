# create by zombic365
#!/bin/bash

# 참조 blog
# https://velog.io/@mnetna/X-PACK-%EC%8B%9C%ED%81%90%EB%A6%AC%ED%8B%B0-%EB%AC%B4%EB%A3%8C-%EA%B8%B0%EB%8A%A5-%EC%82%AC%EC%9A%A9
# https://blog.binarynum.com/62
# https://jjeong.tistory.com/1433
# https://github.com/elastic/elasticsearch/blob/main/distribution/packages/src/common/systemd/elasticsearch.service
# https://velog.io/@91savage/ELK-Stack-Elasticsearch-Logstash-Kibana-debian-%EC%84%A4%EC%B9%98
# https://ploz.tistory.com/entry/logstash-elasticsearch-cluster%EC%97%90-logstash-%EB%B6%99%EC%97%AC%EB%B3%B4%EA%B8%B0SSL-%ED%8F%AC%ED%95%A8

function run_cmd() {
    _CMD=$@
    log_msg "CMD" "$@"    
    eval "${_CMD}" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_msg "OK"
        return 0
    else
        log_msg "FAIL"
        return 1
    fi
}

function log_msg() {
    _CMD_LOG="tee -a ${SCRIPT_LOG}/script_${TODAY}.log"
    _RUN_TODAY=$(date "+%y%m%d")
    _RUN_TIME=$(date "+%H:%M:%S.%3N")
  
    _LOG_TIME="${_RUN_TODAY} ${_RUN_TIME}"
    _LOG_TYPE=$1
    _LOG_MSG=$2

    # printf "%-*s | %s\n" ${STR_LEGNTH} "Server Serial" "Unknown" |tee -a ${LOG_FILE} >/dev/null
    case ${_LOG_TYPE} in
        "CMD"   ) printf "%s | %-*s | %s\n" "${_LOG_TIME}" 7 "${_LOG_TYPE}" "${_LOG_MSG}"   ;;
        "OK"    ) printf "%s | %-*s | %s\n" "${_LOG_TIME}" 7 "${_LOG_TYPE}" "command ok."   ;;
        "FAIL"  ) printf "%s | %-*s | %s\n" "${_LOG_TIME}" 7 "${_LOG_TYPE}" "command fail." ;;
        "INFO"  ) printf "%s | %-*s | %s\n" "${_LOG_TIME}" 7 "${_LOG_TYPE}" "${_LOG_MSG}"   ;;
        "WARR"  ) printf "%s | %-*s | %s\n" "${_LOG_TIME}" 7 "${_LOG_TYPE}" "${_LOG_MSG}"   ;;
        "SKIP"  ) printf "%s | %-*s | %s\n" "${_LOG_TIME}" 7 "${_LOG_TYPE}" "${_LOG_MSG}"   ;;
        "ERROR" ) printf "%s | %-*s | %s\n" "${_LOG_TIME}" 7 "${_LOG_TYPE}" "${_LOG_MSG}"   ;;
        # "CMD"   ) printf "%s | %-*s | %s\n" "${_LOG_TIME}" 7 "${_LOG_TYPE}" "${_LOG_MSG}"   |tee -a ${LOG_FILE} >/dev/null ;;
        # "OK"    ) printf "%s | %-*s | %s\n" "${_LOG_TIME}" 7 "${_LOG_TYPE}" "command ok."   |tee -a ${LOG_FILE} >/dev/null ;;
        # "FAIL"  ) printf "%s | %-*s | %s\n" "${_LOG_TIME}" 7 "${_LOG_TYPE}" "command fail." |tee -a ${LOG_FILE} >/dev/null ;;
        # "INFO"  ) printf "%s | %-*s | %s\n" "${_LOG_TIME}" 7 "${_LOG_TYPE}" "${_LOG_MSG}"   |tee -a ${LOG_FILE} >/dev/null ;;
        # "WARR"  ) printf "%s | %-*s | %s\n" "${_LOG_TIME}" 7 "${_LOG_TYPE}" "${_LOG_MSG}"   |tee -a ${LOG_FILE} >/dev/null ;;
        # "ERROR" ) printf "%s | %-*s | %s\n" "${_LOG_TIME}" 7 "${_LOG_TYPE}" "${_LOG_MSG}"   |tee -a ${LOG_FILE} >/dev/null ;;
    esac
}

function help_usage() {
    cat <<EOF
Usage: $0 [Options]
Options:
-i, --install             : Install ELK
-r, --remove              : Remove  ELK
-u, --user [ STRING ]     : ELK User
-s, --svr  [ STRING ]     : ELK Service name
-p, --path [ STRING ]     : ELK Path
-v, --ver  [  INT   ]     : ELK Version
EOF
    exit 0
}

function set_opts() {
    arguments=$(getopt --options u:s:p:v:hir \
    --longoptions user:,svr:,path:,ver:,help,install,remove \
    --name $(basename $0) \
    -- "$@")

    eval set -- "${arguments}"
    while true; do
        case "$1" in
            -i | --install  ) MODE="install"; shift   ;;
            -r | --remove   ) MODE="remove" ; shift   ;;
            -u | --user     ) ELK_USER=$2   ; shift 2 ;;
            -s | --svr      ) ELK_SVR=$2    ; shift 2 ;;
            -p | --path     ) ELK_PATH=$2   ; shift 2 ;;
            -v | --ver      ) ELK_VER=$2    ; shift 2 ;;
            -h | --help     ) help_usage              ;;            
            --              ) shift         ; break   ;;
            ?               ) help_usage              ;;
        esac
    done
    ### 남아 있는 인자를 얻기 위해 shift 한다.
    shift $((OPTIND-1))
}

function setup_config() {
    if [ ! -d ${ELK_PATH}/tools/pkgs ]; then
        run_cmd "mkdir -p ${ELK_PATH}/tools/pkgs"
    fi
}

function download_pkgs() {
    for _SVC in elasticsearch logstash kibana; do
        run_cmd "curl -s https://artifacts.elastic.co/downloads/${_SVC}/${_SVC}-${ELK_VER}-linux-x86_64.tar.gz >${ELK_PATH}/tools/pkgs/${_SVC}-${ELK_VER}-linux-x86_64.tar.gz"
        run_cmd "curl -s https://artifacts.elastic.co/downloads/${_SVC}/${_SVC}-${ELK_VER}-linux-x86_64.tar.gz.sha512 >${ELK_PATH}/tools/pkgs/${_SVC}-${ELK_VER}-linux-x86_64.tar.gz.sha512"
        run_cmd "cd ${ELK_PATH}/tools/pkgs"
        run_cmd "shasum -a 512 -qc ${_SVC}-${ELK_VER}-linux-x86_64.tar.gz.sha512"
        if [ $? -eq 0 ]; then
            if [ ! -d ${ELK_PATH}/${_SVC}-${ELK_VER}-linux-x86_64 ]; then
                run_cmd "tar -zxf ${_SVC}-${ELK_VER}-linux-x86_64.tar.gz -C ${ELK_PATH}/."
                run_cmd "cd ${ELK_PATH}"
            else
                log_msg "SKIP" "Already install ${ELK_PATH}/${_SVC}-${ELK_VER}-linux-x86_64"
                continue
            fi

            if [ ! -f ${ELK_PATH}/${_SVC} ]; then
                run_cmd "ln -s ${ELK_PATH}/${_SVC} ${_SVC}"
            else
                log_msg "WARR" "Already ${ELK_PATH}/${_SVC}, so Change new [ ${_SVC}-${ELK_VER}-linux-x86_64 ]"
                run_cmd "ln -Tfs ${ELK_PATH}/${_SVC} ${_SVC}"
            fi

            log_msg "INFO" "Sucess Install ${_SVC}"
        else
            log_msg "ERROR" "Download error ${_SVC}-${ELK_VER}"
            exit 1
        fi
    done
}

function setup_ssl_els

main() {
    [ $# -eq 0 ] && help_usage
    set_opts "$@"

    if [ ! -d ${ELK_PATH} ]; then
        log_msg "ERROR" "Pleaase check path ${ELK_PATH}"
        exit 1
    else    
        setup_config
        case ${MODE} in
            "install" )
                download_pkgs
            ;;
            "remove"  ) echo "remote"  ; exit 0 ;;
            *         ) help_usage     ; exit 0 ;;
        esac
    fi
}
main $*


