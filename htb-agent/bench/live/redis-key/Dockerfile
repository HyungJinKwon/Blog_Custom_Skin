# 라이브 벤치 타겟(docker): 비인증 Redis 에 플래그가 든 키
FROM redis:7-alpine
RUN printf 'flag{unauth_redis_key}\n' > /flag.txt
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 6379
CMD ["/entrypoint.sh"]
