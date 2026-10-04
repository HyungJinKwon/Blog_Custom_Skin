# 클라우드(AWS/S3) 열거 · 리버스쉘 (일반 지식)

> 권한이 확인된 대상에서만. 익스플로잇·셸은 '탐지 + 수동 제안'까지만 자동화.

## AWS / S3
`knowledge/rules/cloud-aws.json` + `cloud` 도구(awscli·s3scanner·cloud_enum).
- 자격증명 식별: `aws sts get-caller-identity`, `aws configure list`, 환경변수
- S3 비인증 열거: `aws s3 ls s3://<bucket> --no-sign-request`, `curl <bucket>.s3.amazonaws.com`
- 자동 탐색: `s3scanner`, `cloud_enum -k <keyword>`
- 쓰기가능 점검(CWE-732) → 웹셸 업로드 위험 / 오브젝트 수집
- 자격증명 확보 후 IAM 권한 열거(`aws iam ...`) → 과도권한=권한상승·횡적이동
출처: AWS CLI/S3/IAM 공식문서.

## 리버스쉘
`assassin --revshell IP:PORT` (또는 `PORT` + 공격자 IP 자동) → 표준 페이로드 생성(실행 안 함).
- 리스너: `nc -lvnp <port>` / `rlwrap nc` / `socat`(PTY) / `ncat --ssl`
- 페이로드: bash(tcp/udp)·sh mkfifo·nc·python3·php·perl·ruby·powershell·socat·awk
- 안정화: `python3 -c 'import pty;pty.spawn("/bin/bash")'` → `stty raw -echo; fg`
출처: 공개 표준 기법(PayloadsAllTheThings 류).
