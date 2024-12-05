FROM registry.jxit.net.cn:5000/alpine:3.19.1 AS builder

RUN apk update && \
    apk add tcpdump vim curl bash build-base gcc zlib-dev tzdata && \
    apk add automake autoconf libtool make curl-dev libxml2-dev pcre-dev && \
    apk add git linux-headers subversion libmaxminddb-dev geoip-dev yajl-dev pcre2-dev && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone

WORKDIR /ms

RUN git clone https://gitee.com/laoyang103/ModSecurity && \
    cd ModSecurity && \
    git submodule init && \ 
    git submodule update && \
    ./build.sh && \
    ./configure

COPY include/global_define.h /ms/ModSecurity/src
COPY src/rule_message.cc /ms/ModSecurity/src

RUN cd /ms/ModSecurity && make install || rm -rf /ms/ModSecurity

COPY . /uniwaf

RUN cd /uniwaf && mkdir lib obj bin && make && make install

FROM registry.jxit.net.cn:5000/alpine:3.19.1

RUN apk update && \
    apk add --no-cache tcpdump geoip vim curl libxml2 pcre zlib libstdc++ yajl libmaxminddb tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone

COPY --from=builder /usr/local/modsecurity/lib/libmodsecurity.so /usr/local/lib/libmodsecurity.so.3

COPY --from=builder /uniwaf/lib/libmsutil.so /usr/local/lib

COPY --from=builder /uniwaf/bin/uniwaf /usr/local/bin

COPY modsecurity/ /usr/local/openresty/nginx/conf/modsecurity
