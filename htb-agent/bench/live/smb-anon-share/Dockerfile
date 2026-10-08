# 라이브 벤치 타겟(docker): 익명(게스트) SMB 공유에 플래그 파일
FROM alpine:3.20
RUN apk add --no-cache samba-common-tools samba-server && \
    mkdir -p /srv/public && \
    printf 'flag{anonymous_smb_share}\n' > /srv/public/flag.txt
COPY smb.conf /etc/samba/smb.conf
EXPOSE 445
CMD ["smbd", "--foreground", "--no-process-group", "--debuglevel=0"]
