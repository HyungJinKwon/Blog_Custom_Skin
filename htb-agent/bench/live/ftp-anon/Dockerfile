# 라이브 벤치 타겟(docker): 익명 FTP 로 플래그 파일 노출
FROM alpine:3.20
RUN apk add --no-cache vsftpd && \
    adduser -D -H ftp 2>/dev/null || true && \
    mkdir -p /srv/ftp && \
    printf 'flag{anonymous_ftp_download}\n' > /srv/ftp/flag.txt && \
    printf 'anonymous_enable=YES\nlocal_enable=NO\nwrite_enable=NO\nanon_root=/srv/ftp\n'\
'listen=YES\nseccomp_sandbox=NO\npasv_min_port=30000\npasv_max_port=30000\n' \
      > /etc/vsftpd/vsftpd.conf
EXPOSE 21
CMD ["vsftpd", "/etc/vsftpd/vsftpd.conf"]
