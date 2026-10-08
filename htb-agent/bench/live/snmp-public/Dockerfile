# 라이브 벤치 타겟(docker): community 'public' SNMP 가 syslocation 으로 플래그 노출
FROM alpine:3.20
RUN apk add --no-cache net-snmp
COPY snmpd.conf /etc/snmp/snmpd.conf
EXPOSE 161/udp
CMD ["snmpd", "-f", "-Lo", "-c", "/etc/snmp/snmpd.conf"]
