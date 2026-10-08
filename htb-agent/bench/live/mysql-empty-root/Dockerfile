# 라이브 벤치 타겟(docker): root 비밀번호 없는 MySQL(MariaDB), 테이블에 플래그
FROM mariadb:11
ENV MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1
ENV MARIADB_DATABASE=ctf
COPY init.sql /docker-entrypoint-initdb.d/init.sql
EXPOSE 3306
