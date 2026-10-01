/* ============================================================================
   원무수익마감점검 차액 원인 추적 — 최종 정리본 v3  (Oracle 19c, SELECT 전용, 바인드 입력형)
   작성: Elpam.k
   ----------------------------------------------------------------------------
   [흐름]  엑셀에서 차액 확인 → DB로 같은 숫자 재현 → 어느 쪽이 다른지 판정 → 시점·건 단위로 좁히기 → 원인 확정
     STEP 0  엑셀에서 차액 항목·구분 찾기 (수동) + 항목별 조사 경로
     STEP 1  DB로 화면 숫자 재현 + 엑셀 값 대조 (S1~S3)          ← DB가 마감/점검 중 어느 쪽과 맞는지 판정
     STEP 2  마감 시점 확인 (마감 후 변경·취소, 마감 테이블 찾기)
     STEP 3  건 단위로 좁히기 (항목 지정 건, 미수 구분, 정합성, 정산식, 원인 분류)
     STEP 4  계산·처방 단계 확인 (헤더 ↔ 계산 ↔ 처방)
     STEP 5  카드·현금 차액일 때 (VAN 승인 대조)
     STEP 6  건별 타임라인 / 보고 요약

   [입력 방법]  바인드 입력창에 아래 형식으로 입력 (날짜는 문자열 → 쿼리 안에서 TO_DATE 변환, 빈칸=NULL)
     :p_date      점검일자        예) 2026-10-01            (YYYY-MM-DD)  ← 항상 필수
     :p_op :p_er :p_ip   외래/응급/입원의 내원구분(CODV_CD) 코드값        ← S1 결과로 확정, S2에서 사용
     :p_cd        조회할 구분 코드 (보통 입원 코드, 공백=전체)           ← STEP 3~4 공통
     :p_item      S3 항목명 앞부분   예) 미수합계
     :p_xl_close  엑셀 마감 값(숫자만) 예) 22443990        :p_xl_chk  엑셀 점검 값(숫자만) 예) 22443900
     :p_ord       S2 순번 (3-1에서 항목 지정)  예) 9 (미수합계 A)
     :p_close_dt  마감 종료일시     예) 2026-10-01 18:30:00 (2-1 결과, YYYY-MM-DD HH24:MI:SS)
     :p_diff      찾는 차액 금액    예) 90 / 58900
     :p_mdrp      진료접수번호      예) 123456789           (6-1)
     :p_apv :p_cncl  카드 승인/취소 구분값 (5-1 결과로 확정, 5-2에서 사용)
     :p_owner     스키마명(대문자)  예) HOSPITAL             (2-4, 2-5)

   [S2 순번표]  1 총진료비 / 2 본인부담액 / 3 진료비감면 / 4 헌혈감면 / 5 중간금대체 / 6 기수납금 / 7 수납잔전액
               8 수납금 / 9 미수합계(A:UNCL_AMT) / 10 미수합계(B:UNCL_AMT-헌혈감면) / 11 카드수납 / 12 DDC수납
               13 현금등(수납-카드-DDC) / 14 항등식잔차(0이어야 정상)

   [안전] Test 환경에서 먼저 실행. 환자 식별정보(성명 등)는 조회하지 않는다. UPDATE/DELETE 없음.
   [추정] 컬럼 대응(예: 중간금대체=MIDL_AMT, 미수합계=UNCL_AMT)은 컬럼명과 엑셀 항목명의 유사성에 따른 〔추정〕이다.
          STEP 1의 대조 결과로 맞는지 확인한다.
   [성능] ACRCRCPCT는 I04(MCRC_YMD 선두), ACCLMCCLT·ACCLPAORT는 헤더 접수번호 세미조인(I03/I01), VAN은 WORK_YMD 선두.
          실제 인덱스 사용 여부는 실행계획으로 확인한다.
   ============================================================================ */


/* ############################################################################
   STEP 0. 엑셀에서 차액 항목 찾기 (수동)
   ----------------------------------------------------------------------------
   1) 원무수입마감점검 엑셀을 연다.  2) '상세구분' 열에서 "(차액)"이 들어간 행만 필터한다.
   3) 값이 0이 아닌 행의 [항목]과 [구분(외래/응급/입원)]을 적는다.
      예) 미수합계(차액) · 입원 · 90   (마감 22,443,990 / 점검 22,443,900)
   4) 같은 항목의 (마감)값, (점검)값을 숫자만 메모한다 → :p_xl_close, :p_xl_chk

   [차액 항목별 조사 경로]
     엑셀 항목          조사 쿼리                                   비고
     ---------------------------------------------------------------------------------------------
     미수합계           S3(9,10) → 3-2 → 3-1(:p_ord=9) → 3-5 → 3-6    구분별 미수 대조가 핵심
     본인부담액         S3 → 3-1(2) → 3-3 → 3-5 → 4-1
     진료비감면         S3 → 3-1(3) → 3-5 → 4-1                      헌혈감면은 4번
     중간금대체         S3 → 3-1(5) → 3-5
     수납금             S3 → 3-1(8) → 3-5 → STEP 5
     카드수입           5-1 → 5-2                                    VAN 카드 대조
     현금수입           5-3 → 5-4 → 5-5                              구분별 점검값이 0이면 리포트 집계 의심
     보증금/총수입      헤더 외 입금 데이터 필요(수납금+보증금)       보증금 테이블은 별도 확인 〔확인 필요〕
   ############################################################################ */


/* ############################################################################
   STEP 1. DB로 화면 숫자 재현 + 엑셀 대조
   ############################################################################ */

/* S1. 구분 코드 확정 — 엑셀의 구분별 총진료비/본인부담액/수납금과 같은 값을 가진 행의 CODV_CD가 그 구분의 코드
        예) 2026-10-01 엑셀: 총진료비 외래 468,811,554 / 응급 39,094,868 / 입원 938,996,260
                           수납금   외래 136,132,830 / 응급 12,059,860 / 입원 103,697,580
        ▶ 입력: p_date   ▶ 판정: 일치하는 행의 codv_cd를 :p_op / :p_er / :p_ip 로 사용 */
SELECT a.codv_cd AS 내원구분, a.adms_otdv_cd AS 입원외래구분, COUNT(*) AS 건수,
       SUM(a.tomc_amt) AS 총진료비, SUM(a.onbr_amt) AS 본인부담액, SUM(a.rcpc_amt) AS 수납금,
       SUM(a.uncl_amt) AS 미수금액합
  FROM acrcrcpct a
 WHERE a.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
   AND a.mcrc_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
   AND a.cncl_dt IS NULL
 GROUP BY a.codv_cd, a.adms_otdv_cd
 ORDER BY 1, 2;


/* S2. 화면 재현표 — 엑셀과 같은 항목 순서로 구분별 값을 출력 (엑셀 '마감' 열과 눈으로 대조)
        ▶ 입력: p_date, p_op, p_er, p_ip
        ▶ 항목 대응(〔추정〕): 진료비감면=RDEX_AMT, 중간금대체=MIDL_AMT, 기수납금=PRRC_AMT, 수납잔전액=BLAN_AMT,
                              수납금=RCPC_AMT, 미수합계=UNCL_AMT(A) 또는 UNCL_AMT-헌혈감면(B), 카드=CDRC_AMT */
WITH base AS (
    SELECT /*+ MATERIALIZE */
           a.codv_cd, a.tomc_amt, a.onbr_amt, a.rdex_amt, a.bldt_rdex_amt, a.midl_amt, a.prrc_amt,
           a.blan_amt, a.rcpc_amt, a.uncl_amt, a.cdrc_amt, a.ddc_rcpc_amt
      FROM acrcrcpct a
     WHERE a.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
       AND a.mcrc_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
       AND a.cncl_dt IS NULL
),
rpt AS (
    SELECT  1 AS ord, '총진료비'                    AS item, codv_cd, tomc_amt                                   AS amt FROM base
    UNION ALL SELECT  2, '본인부담액',                       codv_cd, onbr_amt                                   FROM base
    UNION ALL SELECT  3, '진료비감면',                       codv_cd, rdex_amt                                   FROM base
    UNION ALL SELECT  4, '헌혈감면',                         codv_cd, bldt_rdex_amt                              FROM base
    UNION ALL SELECT  5, '중간금대체',                       codv_cd, midl_amt                                   FROM base
    UNION ALL SELECT  6, '기수납금',                         codv_cd, prrc_amt                                   FROM base
    UNION ALL SELECT  7, '수납잔전액',                       codv_cd, blan_amt                                   FROM base
    UNION ALL SELECT  8, '수납금',                           codv_cd, rcpc_amt                                   FROM base
    UNION ALL SELECT  9, '미수합계(A:미수금액)',             codv_cd, uncl_amt                                   FROM base
    UNION ALL SELECT 10, '미수합계(B:미수금액-헌혈감면)',    codv_cd, uncl_amt - bldt_rdex_amt                   FROM base
    UNION ALL SELECT 11, '카드수납',                         codv_cd, cdrc_amt                                   FROM base
    UNION ALL SELECT 12, 'DDC수납',                          codv_cd, ddc_rcpc_amt                               FROM base
    UNION ALL SELECT 13, '현금등(수납-카드-DDC)',            codv_cd, rcpc_amt - cdrc_amt - ddc_rcpc_amt         FROM base
    UNION ALL SELECT 14, '항등식잔차(본인부담-감면-중간금-기수납-잔전-수납-미수) → 0이어야 정상',
                                                               codv_cd, onbr_amt - rdex_amt - midl_amt - prrc_amt
                                                                        - blan_amt - rcpc_amt - uncl_amt          FROM base
)
SELECT r.ord AS 순번, r.item AS 항목,
       SUM(CASE WHEN r.codv_cd = :p_op THEN r.amt ELSE 0 END) AS 외래,
       SUM(CASE WHEN r.codv_cd = :p_er THEN r.amt ELSE 0 END) AS 응급,
       SUM(CASE WHEN r.codv_cd = :p_ip THEN r.amt ELSE 0 END) AS 입원,
       SUM(r.amt)                                              AS 전체합계
  FROM rpt r
 GROUP BY r.ord, r.item
 ORDER BY r.ord;


/* S3. 엑셀 차액 항목 대조 — DB 값이 엑셀의 마감/점검 중 어느 쪽과 맞는가
        ▶ 입력: p_date, p_cd(구분 코드, 예: 입원 코드), p_item(예: 미수합계), p_xl_close, p_xl_chk
        ▶ 판정: 'DB=점검' → 마감 쪽이 DB와 다름(마감 후 변경·마감 집계 문제) → STEP 2부터
                'DB=마감' → 점검 쪽 집계가 DB와 다름(점검 로직·조회 기준 문제) → 점검 SQL 확인 필요
                '둘 다 다름' → 항목↔컬럼 대응(〔추정〕)이 틀렸을 수 있음 → S2의 다른 후보와 비교 */
WITH base AS (
    SELECT /*+ MATERIALIZE */
           a.codv_cd, a.rdex_amt, a.bldt_rdex_amt, a.midl_amt, a.prrc_amt, a.blan_amt, a.rcpc_amt,
           a.uncl_amt, a.onbr_amt, a.tomc_amt, a.cdrc_amt
      FROM acrcrcpct a
     WHERE a.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
       AND a.mcrc_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
       AND a.cncl_dt IS NULL
       AND (:p_cd IS NULL OR a.codv_cd = :p_cd)
),
rpt AS (
    SELECT '총진료비' AS item, tomc_amt AS amt FROM base
    UNION ALL SELECT '본인부담액', onbr_amt FROM base
    UNION ALL SELECT '진료비감면', rdex_amt FROM base
    UNION ALL SELECT '중간금대체', midl_amt FROM base
    UNION ALL SELECT '기수납금', prrc_amt FROM base
    UNION ALL SELECT '수납잔전액', blan_amt FROM base
    UNION ALL SELECT '수납금', rcpc_amt FROM base
    UNION ALL SELECT '미수합계(A:미수금액)', uncl_amt FROM base
    UNION ALL SELECT '미수합계(B:미수금액-헌혈감면)', uncl_amt - bldt_rdex_amt FROM base
    UNION ALL SELECT '카드수납', cdrc_amt FROM base
)
SELECT r.item AS 항목, SUM(r.amt) AS DB값, :p_xl_close AS 엑셀_마감, :p_xl_chk AS 엑셀_점검,
       SUM(r.amt) - :p_xl_close AS DB_마감_차이, SUM(r.amt) - :p_xl_chk AS DB_점검_차이,
       CASE WHEN SUM(r.amt) = :p_xl_close AND SUM(r.amt) = :p_xl_chk THEN '차액 없음'
            WHEN SUM(r.amt) = :p_xl_chk                              THEN 'DB=점검 (마감값이 DB와 다름)'
            WHEN SUM(r.amt) = :p_xl_close                            THEN 'DB=마감 (점검값이 DB와 다름)'
            ELSE                                                          '둘 다 다름 (항목 대응 재확인)' END AS 판정
  FROM rpt r
 WHERE r.item LIKE :p_item || '%'
 GROUP BY r.item
 ORDER BY r.item;


/* ############################################################################
   STEP 2. 마감 시점 확인 — 마감 이후에 데이터가 바뀌었는가
   ############################################################################ */

/* ▶ 판정: 종료일시를 :p_close_dt 로 사용. 같은 날 마감이 여러 행(재마감)이거나 에러메시지가 있으면 마감값이 부분 반영/재산출됐을 수 있음 */
/* 2-1. 마감 실행 로그: 점검일의 마감이 언제·몇 번·어떻게 돌았는가 (재마감·에러 확인) */
SELECT c.clsn_base_ymd   AS 마감기준일자,
       c.clsn_strt_dt    AS 시작일시,
       c.clsn_fnsh_dt    AS 종료일시,
       c.clsn_crtn_dvsn_cd AS 생성구분,
       c.clsn_crtn_resn_ctn AS 생성사유,
       c.clos_id         AS 마감자,
       c.err_mesg_ctn    AS 에러메시지,
       c.rmrk_ctn        AS 비고
  FROM acetclsgt c
 WHERE c.clsn_base_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
   AND c.clsn_base_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
 ORDER BY c.clsn_strt_dt;


/* ▶ 입력: p_date, p_cd, p_close_dt.  ▶ 판정: 행이 나오면 마감~점검 사이 변경/취소가 차액 원인 후보 → 해당 mdrp_no 로 6-1 */
/* 2-2. 마감 이후 변경·취소 건 (수납): 마감과 점검 사이의 시차 확인. :p_close_dt가 NULL이면 당일 수납분 조건은 빠진다 */
SELECT a.mdrp_no, a.mcrc_ymd, a.mcrc_sno, a.rcdv_cd, a.uncl_amt, a.uncl_deps_amt, a.rcpc_amt,
       a.cncl_dt, a.cncr_id, a.frst_rgst_dt, a.last_updt_dt, a.last_updr_id, a.last_updt_clnt_prgm_id
  FROM acrcrcpct a
 WHERE (:p_cd IS NULL OR a.codv_cd = :p_cd)
   AND (   (a.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') AND a.mcrc_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') + 1
            AND (a.last_updt_dt > TO_DATE(:p_close_dt, 'YYYY-MM-DD HH24:MI:SS') OR a.cncl_dt > TO_DATE(:p_close_dt, 'YYYY-MM-DD HH24:MI:SS')))      -- 당일 수납 건이 마감 후 변경/취소
        OR (a.mcrc_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') AND a.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') - 90      -- 과거 90일로 제한(Full Scan 방지)
            AND (   (a.cncl_dt >= TO_DATE(:p_date, 'YYYY-MM-DD') AND a.cncl_dt < TO_DATE(:p_date, 'YYYY-MM-DD') + 1)
                 OR (a.last_updt_dt >= TO_DATE(:p_date, 'YYYY-MM-DD') AND a.last_updt_dt < TO_DATE(:p_date, 'YYYY-MM-DD') + 1))))  -- 과거 수납 건이 당일 변경
 ORDER BY a.last_updt_dt;


/* ▶ 입력: p_date, p_cd, p_close_dt.  ▶ 판정: 마감 후 변경·취소·반납 요청된 처방이 있으면 계산·수납 재산출의 원인 후보 */
/* 2-3. 원무처방: 마감 후 변경·취소·반납 요청된 처방 (계산기준일 = PTAD_CLBA_YMD) */
SELECT p.mdrp_no, p.ptad_ordr_sno, p.ordr_ymd, p.ordr_sno, p.odki_cd, p.mdfe_cd,
       p.cqy, p.ntm, p.ddcn, p.rtrn_cqy, p.rtrn_ntm, p.rtrn_ddcn, p.rtrn_stts_cd, p.rtrn_rqst_dt, p.rtrn_rqpr_id,
       p.rcst_cd, p.cncl_dt, p.last_updt_dt, p.last_updr_id, p.last_updt_clnt_prgm_id
  FROM acclpaort p
 WHERE p.ptad_clba_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
   AND p.ptad_clba_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
   AND (:p_cd IS NULL OR COALESCE(p.ptad_codv_cd, p.codv_cd) = :p_cd)
   AND p.mdrp_no IN (SELECT x.mdrp_no FROM acrcrcpct x                         -- I01(MDRP_NO) 활용. MDRP_NO NULL 처방은 제외됨
                      WHERE x.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') AND x.mcrc_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') + 1)
   AND (p.last_updt_dt > TO_DATE(:p_close_dt, 'YYYY-MM-DD HH24:MI:SS') OR p.cncl_dt > TO_DATE(:p_close_dt, 'YYYY-MM-DD HH24:MI:SS') OR p.rtrn_rqst_dt > TO_DATE(:p_close_dt, 'YYYY-MM-DD HH24:MI:SS'))
 ORDER BY p.last_updt_dt;


/* ▶ 마감 금액 테이블(미수 구분별 마감값 저장 테이블)을 찾는 용도. 찾으면 그 테이블의 구분별 값을 엑셀 마감 값과 대조 */
/* 2-4. 마감 금액 테이블 후보 탐색 (미수 구분별 마감값이 저장된 테이블 찾기) */
SELECT tc.table_name, tc.comments
  FROM all_tab_comments tc
 WHERE tc.owner = :p_owner
   AND (tc.table_name LIKE 'ACETC%' OR tc.comments LIKE '%마감%' OR tc.comments LIKE '%수입%')
 ORDER BY tc.table_name;


/* ▶ 위와 같은 목적(컬럼명 기준) */
/* 2-5. 컬럼명으로 마감 금액 테이블 찾기 (미수 구분별 컬럼을 가진 테이블) */
SELECT col.table_name, col.column_name
  FROM all_tab_columns col
 WHERE col.owner = :p_owner
   AND (col.column_name LIKE '%UNCL%' OR col.column_name LIKE '%CLSN%' OR col.column_name LIKE '%CLOS%')
   AND col.table_name NOT IN ('ACRCRCPCT', 'ACCLMCCLT', 'ACCLPAORT', 'ACVNCDAPT', 'ACVNCSAPT')
 ORDER BY col.table_name, col.column_id;


/* ############################################################################
   STEP 3. 건 단위로 좁히기
   ############################################################################ */

/* 3-1. 항목 지정 건 목록 — S2 순번(:p_ord)의 금액이 0이 아닌 건 중, 금액이 :p_diff 와 같거나 마감 후 변경된 건
        ▶ 입력: p_date, p_cd, p_ord(예: 9=미수합계A), p_diff(예: 90), p_close_dt
        ▶ 판정: 금액일치=Y → 직접 후보 / 마감후변경=Y → 마감 시점 이후 변경이 원인 후보 → 해당 mdrp_no 로 6-1 */
SELECT x.mdrp_no AS 진료접수번호, x.mcrc_ymd AS 수납일자, x.mcrc_sno AS 일련번호, x.rcdv_cd AS 수납구분,
       x.amt AS 항목금액,
       CASE WHEN ABS(x.amt) = :p_diff THEN 'Y' END AS 금액일치,
       CASE WHEN x.last_updt_dt > TO_DATE(:p_close_dt, 'YYYY-MM-DD HH24:MI:SS') THEN 'Y' END AS 마감후변경,
       x.befr_mcrc_ymd AS 이전수납일자,
       x.last_updt_dt AS 최종수정일시, x.last_updr_id AS 최종수정자, x.last_updt_clnt_prgm_id AS 최종수정프로그램
  FROM (SELECT a.mdrp_no, a.mcrc_ymd, a.mcrc_sno, a.rcdv_cd, a.befr_mcrc_ymd,
               a.last_updt_dt, a.last_updr_id, a.last_updt_clnt_prgm_id,
               CASE :p_ord
                    WHEN  1 THEN a.tomc_amt
                    WHEN  2 THEN a.onbr_amt
                    WHEN  3 THEN a.rdex_amt
                    WHEN  4 THEN a.bldt_rdex_amt
                    WHEN  5 THEN a.midl_amt
                    WHEN  6 THEN a.prrc_amt
                    WHEN  7 THEN a.blan_amt
                    WHEN  8 THEN a.rcpc_amt
                    WHEN  9 THEN a.uncl_amt
                    WHEN 10 THEN a.uncl_amt - a.bldt_rdex_amt
                    WHEN 11 THEN a.cdrc_amt
                    WHEN 12 THEN a.ddc_rcpc_amt
                    WHEN 13 THEN a.rcpc_amt - a.cdrc_amt - a.ddc_rcpc_amt
                    WHEN 14 THEN a.onbr_amt - a.rdex_amt - a.midl_amt - a.prrc_amt - a.blan_amt - a.rcpc_amt - a.uncl_amt
               END AS amt
          FROM acrcrcpct a
         WHERE a.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
           AND a.mcrc_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
           AND (:p_cd IS NULL OR a.codv_cd = :p_cd)
           AND a.cncl_dt IS NULL) x
 WHERE x.amt <> 0
   AND (ABS(x.amt) = :p_diff OR x.last_updt_dt > TO_DATE(:p_close_dt, 'YYYY-MM-DD HH24:MI:SS'))
 ORDER BY ABS(x.amt) DESC, x.mdrp_no;


/* ▶ 항목을 모를 때: 입력 p_date, p_cd, p_diff.  ▶ 판정: 미수·미수입금·잔전·수납액 또는 항등식 잔차가 ±p_diff 인 건 = 직접 후보 */
/* 3-1b. :p_diff 원 후보 건 직접 탐색 (수납 헤더: 미수·미수입금·잔전·수납액·정산 잔차가 ±:p_diff) */
SELECT a.mdrp_no, a.mcrc_ymd, a.mcrc_sno, a.mcrc_rno, a.rcdv_cd, a.rcst_cd, a.isty_cd,
       a.onbr_amt, a.uncl_amt, a.uncl_deps_amt, a.blan_amt, a.rcpc_amt,
       a.onbr_amt - a.rdex_amt - a.midl_amt - a.prrc_amt - a.blan_amt - a.uncl_amt - a.rcpc_amt AS residual,
       a.cncl_dt, a.last_updt_dt, a.last_updr_id
  FROM acrcrcpct a
 WHERE a.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
   AND a.mcrc_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
   AND (:p_cd IS NULL OR a.codv_cd = :p_cd)
   AND (   ABS(a.uncl_amt) = :p_diff OR ABS(a.uncl_deps_amt) = :p_diff OR ABS(a.blan_amt) = :p_diff
        OR ABS(a.rcpc_amt) = :p_diff
        OR ABS(a.onbr_amt - a.rdex_amt - a.midl_amt - a.prrc_amt - a.blan_amt - a.uncl_amt - a.rcpc_amt) = :p_diff)
 ORDER BY a.mdrp_no, a.mcrc_sno;


/* ▶ 입력: p_date, p_cd.  ▶ 판정: 미수사유·보험유형별 미수합을 엑셀 마감의 구분별 미수(개인/보훈/보훈위탁 등)와 대조 → 차이 나는 구분 확정 〔대응 컬럼은 코드 테이블로 확인〕 */
/* 3-2. 미수 구분별 합계 대조 — 90원이 어느 미수 구분에서 어긋났는지 직접 확인
        엑셀 입원 마감값(개인 -2,782,300 / 보훈 8,636,960 / 보훈위탁 12,773,020 / 산전 941,000 /
        필수예방접종 27,310 / 외부지원 2,782,300 / 임상연구 65,700 / 헌혈 18,700)과 비교한다.
        어떤 컬럼(UNCL_RESN_CD, ISTY_CD, SCLW_QLDV_CD 등)이 리포트 구분과 대응하는지는 코드 테이블로 확인 〔확인 필요〕 */
SELECT a.uncl_resn_cd AS 미수사유, a.isty_cd AS 보험유형, a.isty_asst_cd AS 보험유형보조,
       COUNT(*) AS 건수, SUM(a.uncl_amt) AS 미수합, SUM(a.uncl_deps_amt) AS 미수입금합,
       SUM(a.bldt_rdex_amt) AS 헌혈감면합
  FROM acrcrcpct a
 WHERE a.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
   AND a.mcrc_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
   AND (:p_cd IS NULL OR a.codv_cd = :p_cd)
   AND a.cncl_dt IS NULL
   AND a.uncl_amt <> 0
 GROUP BY a.uncl_resn_cd, a.isty_cd, a.isty_asst_cd
 ORDER BY 1, 2, 3;


/* ▶ 입력: p_date, p_cd.  ▶ 판정: 카드+DDC>수납, 취소일시 있으나 금액 잔존, 미수입금>미수 등 구조적 불일치 건 */
/* 3-3. 정산식과 무관한 정합성 위반 (공식 확정 전에도 사용 가능) */
SELECT a.mdrp_no, a.mcrc_ymd, a.mcrc_sno, a.rcpc_amt, a.cdrc_amt, a.ddc_rcpc_amt,
       CASE
            WHEN a.cdrc_amt + a.ddc_rcpc_amt > a.rcpc_amt                THEN '카드+DDC가 수납액 초과'
            WHEN a.cncl_dt IS NOT NULL AND a.rcpc_amt <> 0               THEN '취소일시 있으나 수납액 잔존'
            WHEN a.card_apcn_dt IS NOT NULL AND a.cdrc_amt <> 0          THEN '카드취소일시 있으나 카드액 잔존'
            WHEN a.ddc_apcn_dt  IS NOT NULL AND a.ddc_rcpc_amt <> 0      THEN 'DDC취소일시 있으나 DDC액 잔존'
            WHEN a.capy_cncl_dt IS NOT NULL AND a.rcpc_amt - a.cdrc_amt - a.ddc_rcpc_amt <> 0 THEN '현금취소일시 있으나 현금액 잔존'
            WHEN a.uncl_deps_amt > a.uncl_amt                            THEN '미수입금이 미수금액 초과'
            WHEN a.uncl_amt > 0 AND a.uncl_resn_cd IS NULL               THEN '미수금 있으나 미수사유 없음'
            WHEN a.tomc_amt <> a.totl_inpy_amt + a.totl_nnpy_amt         THEN '총진료비 ≠ 급여+비급여'
            WHEN a.clam_amt <> a.totl_inpy_amt - a.inpy_onbr_amt         THEN '청구금액 ≠ 급여-급여본인부담'
       END AS 위반유형
  FROM acrcrcpct a
 WHERE a.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
   AND a.mcrc_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
   AND (:p_cd IS NULL OR a.codv_cd = :p_cd)
   AND (   a.cdrc_amt + a.ddc_rcpc_amt > a.rcpc_amt
        OR (a.cncl_dt IS NOT NULL AND a.rcpc_amt <> 0)
        OR (a.card_apcn_dt IS NOT NULL AND a.cdrc_amt <> 0)
        OR (a.ddc_apcn_dt  IS NOT NULL AND a.ddc_rcpc_amt <> 0)
        OR (a.capy_cncl_dt IS NOT NULL AND a.rcpc_amt - a.cdrc_amt - a.ddc_rcpc_amt <> 0)
        OR a.uncl_deps_amt > a.uncl_amt
        OR (a.uncl_amt > 0 AND a.uncl_resn_cd IS NULL)
        OR a.tomc_amt <> a.totl_inpy_amt + a.totl_nnpy_amt
        OR a.clam_amt <> a.totl_inpy_amt - a.inpy_onbr_amt)
 ORDER BY a.mdrp_no, a.mcrc_sno;


/* ▶ 입력: p_date, p_cd.  ▶ 판정: 불일치 건수가 가장 적은 식 = 정산식 후보. 다음 3-5의 exp_rcpc_amt 식을 그 식으로 교체 */
/* 3-4. 정산식 후보 검증: 불일치 건수가 가장 적은 식 = 실제 정산식일 가능성이 높다 (취소 제외)
        식R1·R2는 엑셀 항등식(본인부담 = 미수+감면+중간금+기수납+잔전+수납금)을 헤더 컬럼에 대응시킨 것 〔추정〕 */
SELECT COUNT(*) AS 대상건수,
       SUM(CASE WHEN a.rcpc_amt <> a.onbr_amt - a.rdex_amt - a.midl_amt - a.prrc_amt - a.blan_amt - a.uncl_amt
                THEN 1 ELSE 0 END)                                              AS 식R1,
       SUM(CASE WHEN a.rcpc_amt <> a.onbr_amt - a.rdex_amt - a.bldt_rdex_amt - a.midl_amt - a.prrc_amt
                                   - a.blan_amt - a.uncl_amt
                THEN 1 ELSE 0 END)                                              AS 식R2_헌혈감면포함,
       SUM(CASE WHEN a.rcpc_amt <> a.onbr_amt - a.rdex_amt - a.bldt_rdex_amt - a.midl_amt - a.prrc_amt
                                   - a.blan_amt - a.uncl_amt + a.uncl_deps_amt
                THEN 1 ELSE 0 END)                                              AS 식R3_미수입금반영,
       SUM(CASE WHEN a.rcpc_amt <> a.onbr_amt - a.rdex_amt - a.bldt_rdex_amt - a.cnpl_brdn_amt - a.midl_amt
                                   - a.prrc_amt - a.blan_amt - a.uncl_amt + a.uncl_deps_amt
                THEN 1 ELSE 0 END)                                              AS 식R4_계약처부담포함,
       SUM(CASE WHEN a.tomc_amt <> a.totl_inpy_amt + a.totl_nnpy_amt THEN 1 ELSE 0 END) AS 총진료비_항등식,
       SUM(CASE WHEN a.clam_amt <> a.totl_inpy_amt - a.inpy_onbr_amt THEN 1 ELSE 0 END) AS 청구금액_항등식,
       SUM(CASE WHEN a.cdrc_amt + a.ddc_rcpc_amt > a.rcpc_amt THEN 1 ELSE 0 END)        AS 카드DDC_초과
  FROM acrcrcpct a
 WHERE a.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
   AND a.mcrc_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
   AND (:p_cd IS NULL OR a.codv_cd = :p_cd)
   AND a.cncl_dt IS NULL;


/* ▶ 입력: p_date, p_cd, p_close_dt.  ▶ 판정: 추정원인(마감 후 변경/보험유형 변경/총진료비·감면·미수·결제수단 변동/단수) */
/* 3-5. 차액 건 원인 자동 분류: 마감 후 변경 → 이전 수납 건 대비 변동 항목 순으로 판정 */
WITH base AS (
    SELECT a.*,
           a.onbr_amt - a.rdex_amt - a.midl_amt - a.prrc_amt - a.blan_amt - a.uncl_amt AS exp_rcpc_amt  -- 〔추정〕 식R1 → 3-4 결과로 확정한 식으로 교체
      FROM acrcrcpct a
     WHERE a.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
       AND a.mcrc_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
       AND (:p_cd IS NULL OR a.codv_cd = :p_cd)
       AND a.cncl_dt IS NULL
),
diff AS (SELECT b.*, b.exp_rcpc_amt - b.rcpc_amt AS diff_amt FROM base b WHERE b.exp_rcpc_amt <> b.rcpc_amt)
SELECT d.mdrp_no AS 진료접수번호, d.mcrc_ymd AS 수납일자, d.mcrc_sno AS 일련번호, d.diff_amt AS 차액,
       CASE
            WHEN d.last_updt_dt > TO_DATE(:p_close_dt, 'YYYY-MM-DD HH24:MI:SS')                               THEN '0.마감 후 변경'
            WHEN p.mdrp_no IS NULL                                          THEN '0.이전건 없음(최초 수납)'
            WHEN NVL(d.isty_cd,'~') <> NVL(p.isty_cd,'~')                   THEN '1.보험유형 변경'
            WHEN d.tomc_amt <> p.tomc_amt                                   THEN '2.총진료비 변동'
            WHEN d.rdex_amt <> p.rdex_amt OR d.bldt_rdex_amt <> p.bldt_rdex_amt THEN '3.감면 변동'
            WHEN d.uncl_amt <> p.uncl_amt OR d.uncl_deps_amt <> p.uncl_deps_amt THEN '4.미수/미수입금 변동'
            WHEN d.cdrc_amt <> p.cdrc_amt OR d.ddc_rcpc_amt <> p.ddc_rcpc_amt   THEN '5.결제수단 변경'
            WHEN d.midl_amt <> p.midl_amt OR d.prrc_amt <> p.prrc_amt           THEN '6.중간/기수납 변동'
            WHEN ABS(d.diff_amt) < 100                                      THEN '7.단수 차이'
            ELSE                                                                 '9.기타(수동확인)'
       END AS 추정원인,
       d.tomc_amt - NVL(p.tomc_amt, 0) AS 총진료비_증감,
       d.uncl_amt - NVL(p.uncl_amt, 0) AS 미수_증감,
       d.rcpc_amt - NVL(p.rcpc_amt, 0) AS 수납액_증감,
       d.last_updr_id AS 최종수정자, d.last_updt_dt AS 최종수정일시, d.last_updt_clnt_prgm_id AS 최종수정프로그램
  FROM diff d
  LEFT JOIN acrcrcpct p
    ON p.mdrp_no = d.mdrp_no AND p.mcrc_ymd = d.befr_mcrc_ymd AND p.mcrc_sno = d.befr_mcrc_sno
 ORDER BY 추정원인, ABS(d.diff_amt) DESC;


/* ▶ 입력: p_date, p_cd.  ▶ 판정: 이전 수납 건 대비 미수가 달라진 건 (재수납·수정으로 미수가 바뀐 경우) */
/* 3-6. 이전 수납 건 대비 미수 증감 (재수납·수정 체인) */
SELECT a.mdrp_no, a.mcrc_ymd, a.mcrc_sno,
       a.uncl_amt AS 현_미수, p.uncl_amt AS 전_미수, a.uncl_amt - NVL(p.uncl_amt, 0) AS 미수_증감,
       a.uncl_deps_amt - NVL(p.uncl_deps_amt, 0) AS 미수입금_증감,
       a.isty_cd AS 현_보험유형, p.isty_cd AS 전_보험유형, a.last_updr_id, a.last_updt_clnt_prgm_id
  FROM acrcrcpct a
  LEFT JOIN acrcrcpct p
    ON p.mdrp_no = a.mdrp_no AND p.mcrc_ymd = a.befr_mcrc_ymd AND p.mcrc_sno = a.befr_mcrc_sno
 WHERE a.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
   AND a.mcrc_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
   AND (:p_cd IS NULL OR a.codv_cd = :p_cd)
   AND a.cncl_dt IS NULL
   AND a.befr_mcrc_ymd IS NOT NULL
   AND a.uncl_amt <> NVL(p.uncl_amt, 0)
 ORDER BY ABS(a.uncl_amt - NVL(p.uncl_amt, 0)), a.mdrp_no;


/* ############################################################################
   STEP 4. 계산·처방 단계 확인 — 수납 헤더 ↔ 진료비계산 ↔ 원무처방
   ############################################################################ */

/* ▶ 입력: p_date, p_cd.  ▶ 판정: 헤더와 계산 항목 합계가 다른 건 (건당 10원 단위 절사 누적차 후보) */
/* 4-1. 수납 헤더(ACRCRCPCT) vs 계산 항목 합계(ACCLMCCLT) 불일치 — 건당 10원 단위 절사 누적차 후보 〔추정〕 */
WITH det AS (
    SELECT c.mdrp_no, c.mcrc_ymd, c.mcrc_sno, COUNT(*) AS line_cnt,
           SUM(c.onbr_amt) AS onbr_amt, SUM(c.cnpl_brdn_amt) AS cnpl_brdn_amt, SUM(c.rdex_amt) AS rdex_amt,
           SUM(c.slmc_amt) AS slmc_amt, SUM(c.txtn_amt) AS txtn_amt, SUM(c.clam_amt) AS clam_amt
      FROM acclmcclt c
     WHERE c.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
       AND c.mcrc_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
       AND (:p_cd IS NULL OR c.ptad_codv_cd = :p_cd)
       AND c.cncl_dt IS NULL
       AND c.mdrp_no IN (SELECT x.mdrp_no FROM acrcrcpct x                      -- I03(MDRP_NO 선두) 활용
                          WHERE x.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') AND x.mcrc_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') + 1)
     GROUP BY c.mdrp_no, c.mcrc_ymd, c.mcrc_sno
)
SELECT h.mdrp_no, h.mcrc_ymd, h.mcrc_sno, d.line_cnt AS 항목수,
       h.onbr_amt      - NVL(d.onbr_amt, 0)      AS 본인부담_차이,
       h.cnpl_brdn_amt - NVL(d.cnpl_brdn_amt, 0) AS 계약처부담_차이,
       h.rdex_amt      - NVL(d.rdex_amt, 0)      AS 감면_차이,
       h.slmc_amt      - NVL(d.slmc_amt, 0)      AS 선택진료_차이,
       h.txtn_amt      - NVL(d.txtn_amt, 0)      AS 과세_차이,
       h.clam_amt      - NVL(d.clam_amt, 0)      AS 청구_차이,
       h.uncl_amt, h.blan_amt, h.rcpc_amt
  FROM acrcrcpct h
  LEFT JOIN det d
    ON d.mdrp_no = h.mdrp_no AND d.mcrc_ymd = h.mcrc_ymd AND d.mcrc_sno = h.mcrc_sno
 WHERE h.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
   AND h.mcrc_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
   AND (:p_cd IS NULL OR h.codv_cd = :p_cd)
   AND h.cncl_dt IS NULL
   AND (   d.mdrp_no IS NULL
        OR h.onbr_amt <> d.onbr_amt OR h.cnpl_brdn_amt <> d.cnpl_brdn_amt OR h.rdex_amt <> d.rdex_amt
        OR h.slmc_amt <> d.slmc_amt OR h.txtn_amt <> d.txtn_amt OR h.clam_amt <> d.clam_amt)
 ORDER BY h.mdrp_no, h.mcrc_sno;


/* ▶ 입력: p_date, p_cd, p_diff.  ▶ 판정: 계산 항목 중 이전값 대비 ±p_diff 변동 / 신포괄 금액 ±p_diff 건 */
/* 4-2. 계산 항목: 이전값(BEFR_*) 대비 ±:p_diff 변동 / 신포괄(NINL_*) ±:p_diff 건 */
SELECT c.mdrp_no, c.mccl_sno, c.mcrc_ymd, c.mcrc_sno, c.edi_cd,
       c.onbr_amt, c.befr_onbr_amt, c.onbr_amt - c.befr_onbr_amt AS 본인부담_증감,
       c.rcpc_amt, c.befr_rcpc_amt, c.rcpc_amt - c.befr_rcpc_amt AS 수납_증감,
       c.ninl_dvsn_cd, c.ninl_onbr_amt, c.ninl_rcpc_amt, c.ninl_clam_amt,
       c.chck_upre_cd, c.adjs_rmrk_ctn, c.rcst_cd, c.last_updt_dt, c.last_updr_id, c.last_updt_clnt_prgm_id
  FROM acclmcclt c
 WHERE c.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
   AND c.mcrc_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
   AND (:p_cd IS NULL OR c.ptad_codv_cd = :p_cd)
   AND c.cncl_dt IS NULL
   AND c.mdrp_no IN (SELECT x.mdrp_no FROM acrcrcpct x
                      WHERE x.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') AND x.mcrc_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') + 1)
   AND (   ABS(c.onbr_amt - c.befr_onbr_amt) = :p_diff OR ABS(c.rcpc_amt - c.befr_rcpc_amt) = :p_diff
        OR ABS(c.ninl_onbr_amt) = :p_diff OR ABS(c.ninl_rcpc_amt) = :p_diff)
 ORDER BY c.mdrp_no, c.mccl_sno;


/* ▶ 입력: p_date, p_cd.  ▶ 판정: 심사수정·조정비고(수동 조정) 건 분포 */
/* 4-3. 심사수정사유·조정비고·신포괄구분별 분포 (수동 조정 건은 자동 계산식과 어긋날 수 있음 〔추정〕) */
SELECT c.chck_upre_cd AS 심사수정사유,
       CASE WHEN c.adjs_rmrk_ctn IS NULL THEN 'N' ELSE 'Y' END AS 조정비고유무,
       c.ninl_dvsn_cd AS 신포괄구분,
       COUNT(*) AS 항목수, COUNT(DISTINCT c.mdrp_no) AS 접수수,
       SUM(c.onbr_amt - c.befr_onbr_amt) AS 본인부담_증감합,
       SUM(c.rcpc_amt - c.befr_rcpc_amt) AS 수납_증감합
  FROM acclmcclt c
 WHERE c.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
   AND c.mcrc_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
   AND (:p_cd IS NULL OR c.ptad_codv_cd = :p_cd)
   AND c.cncl_dt IS NULL
   AND c.mdrp_no IN (SELECT x.mdrp_no FROM acrcrcpct x
                      WHERE x.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') AND x.mcrc_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') + 1)
 GROUP BY c.chck_upre_cd, CASE WHEN c.adjs_rmrk_ctn IS NULL THEN 'N' ELSE 'Y' END, c.ninl_dvsn_cd
 ORDER BY 1, 2, 3;


/* ▶ 입력: p_date, p_cd.  ▶ 판정: 처방 수량·횟수·일수와 계산이 다른 건 */
/* 4-4. 원무처방 수량·횟수·일수 vs 계산 항목 합계 불일치 (계산이 처방과 1:N이면 노이즈 가능 〔추정〕) */
SELECT p.mdrp_no, p.ordr_ymd, p.ordr_sno, p.mdfe_cd,
       p.cqy AS 처방수량, c.cqy AS 계산수량, p.ntm AS 처방횟수, c.ntm AS 계산횟수,
       p.ddcn AS 처방일수, c.ddcn AS 계산일수, p.rtrn_cqy AS 반납수량, p.rtrn_stts_cd AS 반납상태,
       p.last_updt_dt AS 처방수정일시, c.last_updt_dt AS 계산수정일시
  FROM acclpaort p
  JOIN (SELECT m.mdrp_no, m.ordr_ymd, m.ordr_sno,
               SUM(m.cqy) AS cqy, MAX(m.ntm) AS ntm, MAX(m.ddcn) AS ddcn, MAX(m.last_updt_dt) AS last_updt_dt
          FROM acclmcclt m
         WHERE m.cncl_dt IS NULL
           AND m.mdrp_no IN (SELECT x.mdrp_no FROM acrcrcpct x
                              WHERE x.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') AND x.mcrc_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') + 1)
         GROUP BY m.mdrp_no, m.ordr_ymd, m.ordr_sno) c
    ON c.mdrp_no = p.mdrp_no AND c.ordr_ymd = p.ordr_ymd AND c.ordr_sno = p.ordr_sno
 WHERE p.cncl_dt IS NULL
   AND p.ptad_clba_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
   AND p.ptad_clba_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
   AND (:p_cd IS NULL OR COALESCE(p.ptad_codv_cd, p.codv_cd) = :p_cd)
   AND p.mdrp_no IN (SELECT x.mdrp_no FROM acrcrcpct x
                      WHERE x.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') AND x.mcrc_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') + 1)
   AND (p.cqy <> c.cqy OR p.ntm <> c.ntm OR p.ddcn <> c.ddcn)
 ORDER BY p.mdrp_no, p.ordr_sno;


/* ############################################################################
   STEP 5. 카드·현금 차액일 때 (현금수입(점검) 합계 58,900원 등) — VAN 승인 대조
   ############################################################################ */

/* ▶ 입력: p_date.  ▶ 판정: 승인/취소 구분값 확인 → :p_apv / :p_cncl 확정 */
/* 5-1. VAN 카드 승인 구분·입금구분 분포 (구분값·금액 부호 확인 → :p_apv / :p_cncl 확정) */
SELECT v.card_apcn_dvsn_cd AS 카드승인취소구분, v.deps_dvsn_cd AS 입금구분, v.codv_cd AS 내원구분,
       COUNT(*) AS 건수, SUM(v.pymn_amt) AS 결제금액합, MIN(v.pymn_amt) AS 최소금액
  FROM acvncdapt v
 WHERE v.work_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
   AND v.work_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
 GROUP BY v.card_apcn_dvsn_cd, v.deps_dvsn_cd, v.codv_cd
 ORDER BY 1, 2, 3;


/* ▶ 입력: p_date, p_apv, p_cncl.  ▶ 판정: 수납 헤더 카드수납과 VAN 승인-취소 순액이 다른 건 */
/* 5-2. 수납 헤더 카드수납(CDRC_AMT) vs VAN 승인-취소 순액 (접수·회차 단위 불일치) */
WITH van AS (
    SELECT v.mdrp_no, v.mcrc_ymd, v.mcrc_rno,
           SUM(CASE WHEN v.card_apcn_dvsn_cd = :p_apv  THEN v.pymn_amt ELSE 0 END) AS apv_amt,
           SUM(CASE WHEN v.card_apcn_dvsn_cd = :p_cncl THEN v.pymn_amt ELSE 0 END) AS cncl_amt
      FROM acvncdapt v
     WHERE v.work_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') AND v.work_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') + 1                  -- 인덱스 선두(WORK_YMD)
     GROUP BY v.mdrp_no, v.mcrc_ymd, v.mcrc_rno
),
hdr AS (
    SELECT h.mdrp_no, h.mcrc_ymd, h.mcrc_rno, SUM(h.cdrc_amt) AS cdrc_amt
      FROM acrcrcpct h
     WHERE h.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') AND h.mcrc_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') + 1 AND h.cncl_dt IS NULL
     GROUP BY h.mdrp_no, h.mcrc_ymd, h.mcrc_rno
)
SELECT NVL(h.mdrp_no, v.mdrp_no) AS 진료접수번호, NVL(h.mcrc_ymd, v.mcrc_ymd) AS 수납일자, NVL(h.mcrc_rno, v.mcrc_rno) AS 회차,
       NVL(h.cdrc_amt, 0) AS 헤더_카드수납, NVL(v.apv_amt, 0) AS VAN_승인, NVL(v.cncl_amt, 0) AS VAN_취소,
       NVL(h.cdrc_amt, 0) - (NVL(v.apv_amt, 0) - NVL(v.cncl_amt, 0)) AS 차이,    -- 〔추정〕 취소가 양수 저장일 때
       CASE WHEN h.mdrp_no IS NULL THEN 'VAN만 존재' WHEN v.mdrp_no IS NULL THEN '수납헤더만 존재' ELSE '양쪽 존재' END AS 존재구분
  FROM hdr h
  FULL OUTER JOIN van v ON v.mdrp_no = h.mdrp_no AND v.mcrc_ymd = h.mcrc_ymd AND v.mcrc_rno = h.mcrc_rno
 WHERE NVL(h.cdrc_amt, 0) <> NVL(v.apv_amt, 0) - NVL(v.cncl_amt, 0)
 ORDER BY ABS(NVL(h.cdrc_amt, 0) - (NVL(v.apv_amt, 0) - NVL(v.cncl_amt, 0))) DESC;


/* ▶ 입력: p_date.  ▶ 판정: 현금영수증 승인/취소/사용여부 분포 */
/* 5-3. VAN 현금(현금영수증) 승인 구분·사용여부 분포 */
SELECT s.apcn_dvsn_cd AS 승인취소구분, s.cash_apcn_dvsn_cd AS 현금승인취소구분, s.cash_apcn_resn_cd AS 취소사유,
       s.use_yn AS 사용여부, COUNT(*) AS 건수, SUM(s.pymn_amt) AS 결제금액합, MIN(s.pymn_amt) AS 최소금액
  FROM acvncsapt s
 WHERE s.work_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD')
   AND s.work_ymd <  TO_DATE(:p_date, 'YYYY-MM-DD') + 1
 GROUP BY s.apcn_dvsn_cd, s.cash_apcn_dvsn_cd, s.cash_apcn_resn_cd, s.use_yn
 ORDER BY 1, 2, 3, 4;


/* ▶ 입력: p_date.  ▶ 판정: 현금영수증 승인액이 현금 수납액을 초과하거나 헤더가 없는 건 */
/* 5-4. 현금영수증 승인액이 실제 현금 수납액(수납-카드-DDC)을 초과하거나 수납 헤더가 없는 건
        현금영수증은 현금 수납 중 발행 요청 건에만 존재하므로 현금수입 전체와는 일치하지 않는다 〔추정〕 */
WITH cash AS (
    SELECT s.mdrp_no, s.mcrc_ymd, s.mcrc_rno, SUM(s.pymn_amt) AS csap_amt
      FROM acvncsapt s
     WHERE s.work_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') AND s.work_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') + 1
       AND s.use_yn = 'Y'                                           -- 〔추정〕 5-3 결과로 확인
     GROUP BY s.mdrp_no, s.mcrc_ymd, s.mcrc_rno
),
hdr AS (
    SELECT h.mdrp_no, h.mcrc_ymd, h.mcrc_rno, SUM(h.rcpc_amt - h.cdrc_amt - h.ddc_rcpc_amt) AS cash_amt
      FROM acrcrcpct h
     WHERE h.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') AND h.mcrc_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') + 1 AND h.cncl_dt IS NULL
     GROUP BY h.mdrp_no, h.mcrc_ymd, h.mcrc_rno
)
SELECT NVL(h.mdrp_no, c.mdrp_no) AS 진료접수번호, NVL(h.mcrc_ymd, c.mcrc_ymd) AS 수납일자, NVL(h.mcrc_rno, c.mcrc_rno) AS 회차,
       NVL(h.cash_amt, 0) AS 헤더_현금등, NVL(c.csap_amt, 0) AS 현금영수증_승인액,
       NVL(c.csap_amt, 0) - NVL(h.cash_amt, 0) AS 초과분,
       CASE WHEN h.mdrp_no IS NULL THEN '현금영수증만 존재' ELSE '양쪽 존재' END AS 존재구분
  FROM cash c
  LEFT JOIN hdr h ON h.mdrp_no = c.mdrp_no AND h.mcrc_ymd = c.mcrc_ymd AND h.mcrc_rno = c.mcrc_rno
 WHERE h.mdrp_no IS NULL OR c.csap_amt > h.cash_amt
 ORDER BY 6 DESC;


/* ▶ 입력: p_date, p_diff(예: 58900).  ▶ 판정: 수납 헤더/카드승인/현금승인 중 해당 금액이 있는 건 */
/* 5-5. :p_diff 원 후보 (예: 58900) — 수납 헤더 / 카드승인 / 현금승인 에서 동시에 탐색 */
SELECT '수납헤더' AS 출처, h.mdrp_no, h.mcrc_ymd, h.mcrc_rno,
       h.rcpc_amt - h.cdrc_amt - h.ddc_rcpc_amt AS 금액, h.cncl_dt AS 취소일시
  FROM acrcrcpct h
 WHERE h.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') AND h.mcrc_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') + 1
   AND (ABS(h.rcpc_amt - h.cdrc_amt - h.ddc_rcpc_amt) = :p_diff OR ABS(h.cdrc_amt) = :p_diff)
UNION ALL
SELECT '카드승인', v.mdrp_no, v.mcrc_ymd, v.mcrc_rno, v.pymn_amt, v.card_apcn_ymd
  FROM acvncdapt v
 WHERE v.work_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') AND v.work_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') + 1 AND ABS(v.pymn_amt) = :p_diff
UNION ALL
SELECT '현금승인', s.mdrp_no, s.mcrc_ymd, s.mcrc_rno, s.pymn_amt, s.cash_apcn_ymd
  FROM acvncsapt s
 WHERE s.work_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') AND s.work_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') + 1 AND ABS(s.pymn_amt) = :p_diff;


/* ############################################################################
   STEP 6. 건별 추적 / 보고 요약
   ############################################################################ */

/* 6-1. 후보 접수번호의 수납 이력 타임라인 (직전 행 대비 증감 포함)
        ▶ 입력: p_mdrp.  ▶ 판정: 어느 회차에서 미수·수납·감면이 바뀌었고, 누가·어떤 프로그램이 바꿨는지 */
SELECT a.mcrc_ymd AS 수납일자, a.mcrc_sno AS 일련번호, a.mcrc_rno AS 회차, a.rcdv_cd AS 수납구분, a.rcst_cd AS 수납상태,
       a.isty_cd AS 보험유형, a.tomc_amt AS 총진료비, a.onbr_amt AS 본인부담, a.rdex_amt + a.bldt_rdex_amt AS 감면합,
       a.midl_amt AS 중간금, a.prrc_amt AS 기수납, a.blan_amt AS 잔전, a.uncl_amt AS 미수, a.uncl_deps_amt AS 미수입금,
       a.rcpc_amt AS 수납금액, a.cdrc_amt AS 카드, a.ddc_rcpc_amt AS DDC, a.rcpc_amt - a.cdrc_amt - a.ddc_rcpc_amt AS 현금등,
       a.rcpc_amt - LAG(a.rcpc_amt) OVER (ORDER BY a.mcrc_ymd, a.mcrc_sno) AS 수납액_증감,
       a.uncl_amt - LAG(a.uncl_amt) OVER (ORDER BY a.mcrc_ymd, a.mcrc_sno) AS 미수_증감,
       a.cncl_dt AS 취소일시, a.cncr_id AS 취소자, a.befr_mcrc_ymd AS 이전수납일자, a.befr_mcrc_sno AS 이전일련번호,
       a.frst_rgsr_id AS 최초등록자, a.frst_rgst_dt AS 최초등록일시,
       a.last_updr_id AS 최종수정자, a.last_updt_dt AS 최종수정일시, a.last_updt_clnt_prgm_id AS 최종수정프로그램
  FROM acrcrcpct a
 WHERE a.mdrp_no = :p_mdrp
 ORDER BY a.mcrc_ymd, a.mcrc_sno;


/* 6-2. 일자·내원구분별 차액 요약 (식R1 기준 〔추정〕; 3-4 결과로 식 확정 후 사용)
        ▶ 입력: p_date */
SELECT TO_CHAR(t.mcrc_ymd, 'YYYY-MM-DD') AS 수납일자, t.codv_cd AS 내원구분,
       COUNT(*) AS 전체건수, SUM(CASE WHEN t.diff_amt <> 0 THEN 1 ELSE 0 END) AS 차액건수, SUM(t.diff_amt) AS 차액합계
  FROM (SELECT a.mcrc_ymd, a.codv_cd,
               a.onbr_amt - a.rdex_amt - a.midl_amt - a.prrc_amt - a.blan_amt - a.uncl_amt - a.rcpc_amt AS diff_amt  -- 〔추정〕 식R1
          FROM acrcrcpct a
         WHERE a.mcrc_ymd >= TO_DATE(:p_date, 'YYYY-MM-DD') AND a.mcrc_ymd < TO_DATE(:p_date, 'YYYY-MM-DD') + 1 AND a.cncl_dt IS NULL) t
 GROUP BY ROLLUP (TO_CHAR(t.mcrc_ymd, 'YYYY-MM-DD'), t.codv_cd)
 ORDER BY 1, 2;
