/* ============================================================================
   원무수익마감점검 차액 확인·원인 파악 통합 쿼리 v2  (Oracle 19c, SELECT 전용)
   작성: Elpam.k
   ----------------------------------------------------------------------------
   [대상 테이블]  〔확인〕 제공된 정의서 기준
     ACRCRCPCT  진료비수납   PK(MDRP_NO, MCRC_YMD, MCRC_SNO)  I04 = MCRC_YMD 선두
     ACCLMCCLT  진료비계산   PK(MDRP_NO, MCCL_SNO)            I03 = MDRP_NO 선두
     ACCLPAORT  원무처방     PK(PTNO, INPT_YMD, PTAD_ORDR_SNO) I01 = MDRP_NO
     ACVNCDAPT  VAN카드승인  ACVNCSAPT VAN현금승인             연결: MDRP_NO + MCRC_YMD + MCRC_RNO
     ACETCLSGT  수익수입마감로그 (마감 실행 일시·생성구분·에러)
   [인덱스·성능]  〔확인〕 정의서 기준
     ACRCRCPCT : I04 = MCRC_YMD 선두 → 날짜 범위 조회 가능
     ACCLMCCLT : MCRC_YMD 선두 인덱스 없음(I03=MDRP_NO, I06=PTNO, I08=MCCL_YMD) → 헤더의 접수번호로 세미조인
     ACCLPAORT : PTAD_CLBA_YMD 선두 인덱스 없음(I01=MDRP_NO) → 헤더의 접수번호로 세미조인
     ACVNCDAPT/ACVNCSAPT : PK·I01 선두 = WORK_YMD(작업일자) → 날짜 필터는 WORK_YMD로 건다
     ※ 실제 인덱스 사용 여부는 실행계획으로 확인한다.
   [NULL 주의]  입원 구분은 NOT NULL 컬럼으로 판정한다.
     수납: CODV_CD(NOT NULL) / 계산: PTAD_CODV_CD(NOT NULL) / 처방: 둘 다 NULL 허용 → COALESCE
   [리포트 검산]  〔확인〕 2026-10-01 엑셀, 입원 컬럼
     미수합계(마감) 22,443,990 = 구분별 미수 합(헌혈미수 18,700 제외)
     본인부담액 286,516,072 = 미수합계 + 헌혈 + 감면 + 중간금대체 + 기수납 + 잔전 + 수납금
     미수합계(점검) 22,443,900 → 마감 대비 90원 적음 (외래·응급은 0)
   [추정]  정산식·코드값 의미는 정의서에 없다 → 0-4(K1)로 먼저 검증한 뒤 A1의 식을 확정한다.

   [바인드 변수]
     :p_date      점검일자 (DATE, 예: DATE '2026-10-01')
     :p_io        입원 구분값 (수납 CODV_CD 기준, NULL=전체) ← 0-3 결과로 확정
     :p_close_dt  마감 종료일시 (DATE) ← 0-1 결과
     :p_diff      찾는 차액 금액 (NUMBER, 예: 90 / 58900)
     :p_mdrp      진료접수번호 (T1)
     :p_apv, :p_cncl  카드/현금 승인·취소 구분값 ← 3-1, 3-3 결과
     :p_owner     스키마명 (0-2)

   [실행 순서]  0(준비) → 1(차액 확인) → 2(원인) → 3(카드/현금) → 4(건별 추적) → 5(보고)
   [안전]  Test 환경에서 먼저 실행. 환자 식별정보(성명 등)는 조회하지 않는다. UPDATE/DELETE 없음.
   ============================================================================ */


/* ############################################################################
   0. 준비 — 마감 시점, 구분값, 정산식 확정
   ############################################################################ */

/* 0-1. 마감 실행 로그: 점검일의 마감이 언제·몇 번·어떻게 돌았는가 (재마감·에러 확인) */
SELECT c.clsn_base_ymd   AS 마감기준일자,
       c.clsn_strt_dt    AS 시작일시,
       c.clsn_fnsh_dt    AS 종료일시,
       c.clsn_crtn_dvsn_cd AS 생성구분,
       c.clsn_crtn_resn_ctn AS 생성사유,
       c.clos_id         AS 마감자,
       c.err_mesg_ctn    AS 에러메시지,
       c.rmrk_ctn        AS 비고
  FROM acetclsgt c
 WHERE c.clsn_base_ymd >= :p_date
   AND c.clsn_base_ymd <  :p_date + 1
 ORDER BY c.clsn_strt_dt;


/* 0-2. 마감 금액 테이블 후보 탐색 (미수 구분별 마감값이 저장된 테이블 찾기) */
SELECT tc.table_name, tc.comments
  FROM all_tab_comments tc
 WHERE tc.owner = :p_owner
   AND (tc.table_name LIKE 'ACETC%' OR tc.comments LIKE '%마감%' OR tc.comments LIKE '%수입%')
 ORDER BY tc.table_name;


/* 0-2b. 컬럼명으로 마감 금액 테이블 찾기 (미수 구분별 컬럼을 가진 테이블) */
SELECT col.table_name, col.column_name
  FROM all_tab_columns col
 WHERE col.owner = :p_owner
   AND (col.column_name LIKE '%UNCL%' OR col.column_name LIKE '%CLSN%' OR col.column_name LIKE '%CLOS%')
   AND col.table_name NOT IN ('ACRCRCPCT', 'ACCLMCCLT', 'ACCLPAORT', 'ACVNCDAPT', 'ACVNCSAPT')
 ORDER BY col.table_name, col.column_id;


/* 0-3. 구분값 분포 + 미수 집계 후보 (입원 행의 값이 점검/마감 어느 쪽과 맞는지 확인)
        22,443,900=점검 / 22,443,990=마감.  헌혈감면합이 18,700이면 헌혈 컬럼 매핑 확정 〔추정〕 */
SELECT a.codv_cd                                                          AS 내원구분,
       a.adms_otdv_cd                                                     AS 입원외래구분,
       a.rcdv_cd                                                          AS 수납구분,
       CASE WHEN a.cncl_dt IS NULL THEN 'N' ELSE 'Y' END                  AS 취소여부,
       COUNT(*)                                                           AS 건수,
       SUM(a.uncl_amt)                                                    AS 미수합,
       SUM(a.uncl_amt - a.bldt_rdex_amt)                                  AS 미수_헌혈감면차감,
       SUM(a.uncl_amt - a.uncl_deps_amt)                                  AS 미수_입금차감,
       SUM(a.bldt_rdex_amt)                                               AS 헌혈감면합,
       SUM(a.blan_amt)                                                    AS 잔전합,
       SUM(a.rcpc_amt)                                                    AS 수납합,
       SUM(CASE WHEN a.rcpc_amt < 0 THEN 1 ELSE 0 END)                    AS 음수수납건수
  FROM acrcrcpct a
 WHERE a.mcrc_ymd >= :p_date
   AND a.mcrc_ymd <  :p_date + 1
 GROUP BY a.codv_cd, a.adms_otdv_cd, a.rcdv_cd,
          CASE WHEN a.cncl_dt IS NULL THEN 'N' ELSE 'Y' END
 ORDER BY 1, 2, 3, 4;


/* 0-4. K1 정산식 후보 검증: 불일치 건수가 가장 적은 식 = 실제 정산식일 가능성이 높다 (취소 제외)
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
 WHERE a.mcrc_ymd >= :p_date
   AND a.mcrc_ymd <  :p_date + 1
   AND (:p_io IS NULL OR a.codv_cd = :p_io)
   AND a.cncl_dt IS NULL;


/* 0-5. 미수 구분별 합계 대조 — 90원이 어느 미수 구분에서 어긋났는지 직접 확인
        엑셀 입원 마감값(개인 -2,782,300 / 보훈 8,636,960 / 보훈위탁 12,773,020 / 산전 941,000 /
        필수예방접종 27,310 / 외부지원 2,782,300 / 임상연구 65,700 / 헌혈 18,700)과 비교한다.
        어떤 컬럼(UNCL_RESN_CD, ISTY_CD, SCLW_QLDV_CD 등)이 리포트 구분과 대응하는지는 코드 테이블로 확인 〔확인 필요〕 */
SELECT a.uncl_resn_cd AS 미수사유, a.isty_cd AS 보험유형, a.isty_asst_cd AS 보험유형보조,
       COUNT(*) AS 건수, SUM(a.uncl_amt) AS 미수합, SUM(a.uncl_deps_amt) AS 미수입금합,
       SUM(a.bldt_rdex_amt) AS 헌혈감면합
  FROM acrcrcpct a
 WHERE a.mcrc_ymd >= :p_date
   AND a.mcrc_ymd <  :p_date + 1
   AND (:p_io IS NULL OR a.codv_cd = :p_io)
   AND a.cncl_dt IS NULL
   AND a.uncl_amt <> 0
 GROUP BY a.uncl_resn_cd, a.isty_cd, a.isty_asst_cd
 ORDER BY 1, 2, 3;


/* ############################################################################
   1. 차액 확인
   ############################################################################ */

/* 1-1. A1 수납 건 단위 차액 (기대 수납액 - 실수납액). 식은 CTE 한 곳에서만 정의 → 0-4 결과로 교체 */
WITH base AS (
    SELECT a.mdrp_no, a.mcrc_ymd, a.mcrc_sno, a.mcrc_rno, a.ptno, a.codv_cd, a.rcdv_cd,
           a.onbr_amt, a.rcpc_amt, a.uncl_amt, a.blan_amt,
           a.onbr_amt - a.rdex_amt - a.midl_amt - a.prrc_amt - a.blan_amt - a.uncl_amt AS exp_rcpc_amt  -- 〔추정〕 식R1
      FROM acrcrcpct a
     WHERE a.mcrc_ymd >= :p_date
       AND a.mcrc_ymd <  :p_date + 1
       AND (:p_io IS NULL OR a.codv_cd = :p_io)
       AND a.cncl_dt IS NULL
)
SELECT b.mdrp_no AS 진료접수번호, b.mcrc_ymd AS 수납일자, b.mcrc_sno AS 일련번호, b.rcdv_cd AS 수납구분,
       b.onbr_amt AS 본인부담금, b.exp_rcpc_amt AS 기대수납액, b.rcpc_amt AS 실수납액,
       b.exp_rcpc_amt - b.rcpc_amt AS 차액,
       CASE WHEN b.exp_rcpc_amt > b.rcpc_amt THEN '수납부족' ELSE '과수납' END AS 방향
  FROM base b
 WHERE b.exp_rcpc_amt <> b.rcpc_amt
 ORDER BY ABS(b.exp_rcpc_amt - b.rcpc_amt) DESC, b.mdrp_no;


/* 1-2. A2 정산식과 무관한 정합성 위반 (공식 확정 전에도 사용 가능) */
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
 WHERE a.mcrc_ymd >= :p_date
   AND a.mcrc_ymd <  :p_date + 1
   AND (:p_io IS NULL OR a.codv_cd = :p_io)
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


/* 1-3. A3 수납 헤더(ACRCRCPCT) vs 계산 항목 합계(ACCLMCCLT) 불일치 — 건당 10원 단위 절사 누적차 후보 〔추정〕 */
WITH det AS (
    SELECT c.mdrp_no, c.mcrc_ymd, c.mcrc_sno, COUNT(*) AS line_cnt,
           SUM(c.onbr_amt) AS onbr_amt, SUM(c.cnpl_brdn_amt) AS cnpl_brdn_amt, SUM(c.rdex_amt) AS rdex_amt,
           SUM(c.slmc_amt) AS slmc_amt, SUM(c.txtn_amt) AS txtn_amt, SUM(c.clam_amt) AS clam_amt
      FROM acclmcclt c
     WHERE c.mcrc_ymd >= :p_date
       AND c.mcrc_ymd <  :p_date + 1
       AND (:p_io IS NULL OR c.ptad_codv_cd = :p_io)
       AND c.cncl_dt IS NULL
       AND c.mdrp_no IN (SELECT x.mdrp_no FROM acrcrcpct x                      -- I03(MDRP_NO 선두) 활용
                          WHERE x.mcrc_ymd >= :p_date AND x.mcrc_ymd < :p_date + 1)
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
 WHERE h.mcrc_ymd >= :p_date
   AND h.mcrc_ymd <  :p_date + 1
   AND (:p_io IS NULL OR h.codv_cd = :p_io)
   AND h.cncl_dt IS NULL
   AND (   d.mdrp_no IS NULL
        OR h.onbr_amt <> d.onbr_amt OR h.cnpl_brdn_amt <> d.cnpl_brdn_amt OR h.rdex_amt <> d.rdex_amt
        OR h.slmc_amt <> d.slmc_amt OR h.txtn_amt <> d.txtn_amt OR h.clam_amt <> d.clam_amt)
 ORDER BY h.mdrp_no, h.mcrc_sno;


/* ############################################################################
   2. 원인 파악
   ############################################################################ */

/* 2-1. B1 차액 건 원인 자동 분류: 마감 후 변경 → 이전 수납 건 대비 변동 항목 순으로 판정 */
WITH base AS (
    SELECT a.*,
           a.onbr_amt - a.rdex_amt - a.midl_amt - a.prrc_amt - a.blan_amt - a.uncl_amt AS exp_rcpc_amt  -- 〔추정〕 1-1과 동일 식
      FROM acrcrcpct a
     WHERE a.mcrc_ymd >= :p_date
       AND a.mcrc_ymd <  :p_date + 1
       AND (:p_io IS NULL OR a.codv_cd = :p_io)
       AND a.cncl_dt IS NULL
),
diff AS (SELECT b.*, b.exp_rcpc_amt - b.rcpc_amt AS diff_amt FROM base b WHERE b.exp_rcpc_amt <> b.rcpc_amt)
SELECT d.mdrp_no AS 진료접수번호, d.mcrc_ymd AS 수납일자, d.mcrc_sno AS 일련번호, d.diff_amt AS 차액,
       CASE
            WHEN d.last_updt_dt > :p_close_dt                               THEN '0.마감 후 변경'
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


/* 2-2. B2 :p_diff 원 후보 건 직접 탐색 (수납 헤더: 미수·미수입금·잔전·수납액·정산 잔차가 ±:p_diff) */
SELECT a.mdrp_no, a.mcrc_ymd, a.mcrc_sno, a.mcrc_rno, a.rcdv_cd, a.rcst_cd, a.isty_cd,
       a.onbr_amt, a.uncl_amt, a.uncl_deps_amt, a.blan_amt, a.rcpc_amt,
       a.onbr_amt - a.rdex_amt - a.midl_amt - a.prrc_amt - a.blan_amt - a.uncl_amt - a.rcpc_amt AS residual,
       a.cncl_dt, a.last_updt_dt, a.last_updr_id
  FROM acrcrcpct a
 WHERE a.mcrc_ymd >= :p_date
   AND a.mcrc_ymd <  :p_date + 1
   AND (:p_io IS NULL OR a.codv_cd = :p_io)
   AND (   ABS(a.uncl_amt) = :p_diff OR ABS(a.uncl_deps_amt) = :p_diff OR ABS(a.blan_amt) = :p_diff
        OR ABS(a.rcpc_amt) = :p_diff
        OR ABS(a.onbr_amt - a.rdex_amt - a.midl_amt - a.prrc_amt - a.blan_amt - a.uncl_amt - a.rcpc_amt) = :p_diff)
 ORDER BY a.mdrp_no, a.mcrc_sno;


/* 2-3. B3 마감 이후 변경·취소 건 (수납): 마감과 점검 사이의 시차 확인. :p_close_dt가 NULL이면 당일 수납분 조건은 빠진다 */
SELECT a.mdrp_no, a.mcrc_ymd, a.mcrc_sno, a.rcdv_cd, a.uncl_amt, a.uncl_deps_amt, a.rcpc_amt,
       a.cncl_dt, a.cncr_id, a.frst_rgst_dt, a.last_updt_dt, a.last_updr_id, a.last_updt_clnt_prgm_id
  FROM acrcrcpct a
 WHERE (:p_io IS NULL OR a.codv_cd = :p_io)
   AND (   (a.mcrc_ymd >= :p_date AND a.mcrc_ymd < :p_date + 1
            AND (a.last_updt_dt > :p_close_dt OR a.cncl_dt > :p_close_dt))      -- 당일 수납 건이 마감 후 변경/취소
        OR (a.mcrc_ymd < :p_date AND a.mcrc_ymd >= :p_date - 90      -- 과거 90일로 제한(Full Scan 방지)
            AND (   (a.cncl_dt >= :p_date AND a.cncl_dt < :p_date + 1)
                 OR (a.last_updt_dt >= :p_date AND a.last_updt_dt < :p_date + 1))))  -- 과거 수납 건이 당일 변경
 ORDER BY a.last_updt_dt;


/* 2-4. B4 이전 수납 건 대비 미수 증감 (재수납·수정 체인) */
SELECT a.mdrp_no, a.mcrc_ymd, a.mcrc_sno,
       a.uncl_amt AS 현_미수, p.uncl_amt AS 전_미수, a.uncl_amt - NVL(p.uncl_amt, 0) AS 미수_증감,
       a.uncl_deps_amt - NVL(p.uncl_deps_amt, 0) AS 미수입금_증감,
       a.isty_cd AS 현_보험유형, p.isty_cd AS 전_보험유형, a.last_updr_id, a.last_updt_clnt_prgm_id
  FROM acrcrcpct a
  LEFT JOIN acrcrcpct p
    ON p.mdrp_no = a.mdrp_no AND p.mcrc_ymd = a.befr_mcrc_ymd AND p.mcrc_sno = a.befr_mcrc_sno
 WHERE a.mcrc_ymd >= :p_date
   AND a.mcrc_ymd <  :p_date + 1
   AND (:p_io IS NULL OR a.codv_cd = :p_io)
   AND a.cncl_dt IS NULL
   AND a.befr_mcrc_ymd IS NOT NULL
   AND a.uncl_amt <> NVL(p.uncl_amt, 0)
 ORDER BY ABS(a.uncl_amt - NVL(p.uncl_amt, 0)), a.mdrp_no;


/* 2-5. B5 계산 항목: 이전값(BEFR_*) 대비 ±:p_diff 변동 / 신포괄(NINL_*) ±:p_diff 건 */
SELECT c.mdrp_no, c.mccl_sno, c.mcrc_ymd, c.mcrc_sno, c.edi_cd,
       c.onbr_amt, c.befr_onbr_amt, c.onbr_amt - c.befr_onbr_amt AS 본인부담_증감,
       c.rcpc_amt, c.befr_rcpc_amt, c.rcpc_amt - c.befr_rcpc_amt AS 수납_증감,
       c.ninl_dvsn_cd, c.ninl_onbr_amt, c.ninl_rcpc_amt, c.ninl_clam_amt,
       c.chck_upre_cd, c.adjs_rmrk_ctn, c.rcst_cd, c.last_updt_dt, c.last_updr_id, c.last_updt_clnt_prgm_id
  FROM acclmcclt c
 WHERE c.mcrc_ymd >= :p_date
   AND c.mcrc_ymd <  :p_date + 1
   AND (:p_io IS NULL OR c.ptad_codv_cd = :p_io)
   AND c.cncl_dt IS NULL
   AND c.mdrp_no IN (SELECT x.mdrp_no FROM acrcrcpct x
                      WHERE x.mcrc_ymd >= :p_date AND x.mcrc_ymd < :p_date + 1)
   AND (   ABS(c.onbr_amt - c.befr_onbr_amt) = :p_diff OR ABS(c.rcpc_amt - c.befr_rcpc_amt) = :p_diff
        OR ABS(c.ninl_onbr_amt) = :p_diff OR ABS(c.ninl_rcpc_amt) = :p_diff)
 ORDER BY c.mdrp_no, c.mccl_sno;


/* 2-6. B6 심사수정사유·조정비고·신포괄구분별 분포 (수동 조정 건은 자동 계산식과 어긋날 수 있음 〔추정〕) */
SELECT c.chck_upre_cd AS 심사수정사유,
       CASE WHEN c.adjs_rmrk_ctn IS NULL THEN 'N' ELSE 'Y' END AS 조정비고유무,
       c.ninl_dvsn_cd AS 신포괄구분,
       COUNT(*) AS 항목수, COUNT(DISTINCT c.mdrp_no) AS 접수수,
       SUM(c.onbr_amt - c.befr_onbr_amt) AS 본인부담_증감합,
       SUM(c.rcpc_amt - c.befr_rcpc_amt) AS 수납_증감합
  FROM acclmcclt c
 WHERE c.mcrc_ymd >= :p_date
   AND c.mcrc_ymd <  :p_date + 1
   AND (:p_io IS NULL OR c.ptad_codv_cd = :p_io)
   AND c.cncl_dt IS NULL
   AND c.mdrp_no IN (SELECT x.mdrp_no FROM acrcrcpct x
                      WHERE x.mcrc_ymd >= :p_date AND x.mcrc_ymd < :p_date + 1)
 GROUP BY c.chck_upre_cd, CASE WHEN c.adjs_rmrk_ctn IS NULL THEN 'N' ELSE 'Y' END, c.ninl_dvsn_cd
 ORDER BY 1, 2, 3;


/* 2-7. B7 원무처방: 마감 후 변경·취소·반납 요청된 처방 (계산기준일 = PTAD_CLBA_YMD) */
SELECT p.mdrp_no, p.ptad_ordr_sno, p.ordr_ymd, p.ordr_sno, p.odki_cd, p.mdfe_cd,
       p.cqy, p.ntm, p.ddcn, p.rtrn_cqy, p.rtrn_ntm, p.rtrn_ddcn, p.rtrn_stts_cd, p.rtrn_rqst_dt, p.rtrn_rqpr_id,
       p.rcst_cd, p.cncl_dt, p.last_updt_dt, p.last_updr_id, p.last_updt_clnt_prgm_id
  FROM acclpaort p
 WHERE p.ptad_clba_ymd >= :p_date
   AND p.ptad_clba_ymd <  :p_date + 1
   AND (:p_io IS NULL OR COALESCE(p.ptad_codv_cd, p.codv_cd) = :p_io)
   AND p.mdrp_no IN (SELECT x.mdrp_no FROM acrcrcpct x                         -- I01(MDRP_NO) 활용. MDRP_NO NULL 처방은 제외됨
                      WHERE x.mcrc_ymd >= :p_date AND x.mcrc_ymd < :p_date + 1)
   AND (p.last_updt_dt > :p_close_dt OR p.cncl_dt > :p_close_dt OR p.rtrn_rqst_dt > :p_close_dt)
 ORDER BY p.last_updt_dt;


/* 2-8. B8 원무처방 수량·횟수·일수 vs 계산 항목 합계 불일치 (계산이 처방과 1:N이면 노이즈 가능 〔추정〕) */
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
                              WHERE x.mcrc_ymd >= :p_date AND x.mcrc_ymd < :p_date + 1)
         GROUP BY m.mdrp_no, m.ordr_ymd, m.ordr_sno) c
    ON c.mdrp_no = p.mdrp_no AND c.ordr_ymd = p.ordr_ymd AND c.ordr_sno = p.ordr_sno
 WHERE p.cncl_dt IS NULL
   AND p.ptad_clba_ymd >= :p_date
   AND p.ptad_clba_ymd <  :p_date + 1
   AND (:p_io IS NULL OR COALESCE(p.ptad_codv_cd, p.codv_cd) = :p_io)
   AND p.mdrp_no IN (SELECT x.mdrp_no FROM acrcrcpct x
                      WHERE x.mcrc_ymd >= :p_date AND x.mcrc_ymd < :p_date + 1)
   AND (p.cqy <> c.cqy OR p.ntm <> c.ntm OR p.ddcn <> c.ddcn)
 ORDER BY p.mdrp_no, p.ordr_sno;


/* ############################################################################
   3. 카드·현금 (VAN은 작업일자 WORK_YMD로 필터. 작업일과 수납일이 다른 건은 'VAN만 존재'/'수납헤더만 존재'로 보일 수 있음 〔추정〕)
      (현금수입 점검 차액: 2026-10-01 합계 58,900원 〔확인〕, 구분별 점검값 0 → 리포트 집계 방식 의심 〔추정〕)
   ############################################################################ */

/* 3-1. VAN 카드 승인 구분·입금구분 분포 (구분값·금액 부호 확인 → :p_apv / :p_cncl 확정) */
SELECT v.card_apcn_dvsn_cd AS 카드승인취소구분, v.deps_dvsn_cd AS 입금구분, v.codv_cd AS 내원구분,
       COUNT(*) AS 건수, SUM(v.pymn_amt) AS 결제금액합, MIN(v.pymn_amt) AS 최소금액
  FROM acvncdapt v
 WHERE v.work_ymd >= :p_date
   AND v.work_ymd <  :p_date + 1
 GROUP BY v.card_apcn_dvsn_cd, v.deps_dvsn_cd, v.codv_cd
 ORDER BY 1, 2, 3;


/* 3-2. 수납 헤더 카드수납(CDRC_AMT) vs VAN 승인-취소 순액 (접수·회차 단위 불일치) */
WITH van AS (
    SELECT v.mdrp_no, v.mcrc_ymd, v.mcrc_rno,
           SUM(CASE WHEN v.card_apcn_dvsn_cd = :p_apv  THEN v.pymn_amt ELSE 0 END) AS apv_amt,
           SUM(CASE WHEN v.card_apcn_dvsn_cd = :p_cncl THEN v.pymn_amt ELSE 0 END) AS cncl_amt
      FROM acvncdapt v
     WHERE v.work_ymd >= :p_date AND v.work_ymd < :p_date + 1                  -- 인덱스 선두(WORK_YMD)
     GROUP BY v.mdrp_no, v.mcrc_ymd, v.mcrc_rno
),
hdr AS (
    SELECT h.mdrp_no, h.mcrc_ymd, h.mcrc_rno, SUM(h.cdrc_amt) AS cdrc_amt
      FROM acrcrcpct h
     WHERE h.mcrc_ymd >= :p_date AND h.mcrc_ymd < :p_date + 1 AND h.cncl_dt IS NULL
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


/* 3-3. VAN 현금(현금영수증) 승인 구분·사용여부 분포 */
SELECT s.apcn_dvsn_cd AS 승인취소구분, s.cash_apcn_dvsn_cd AS 현금승인취소구분, s.cash_apcn_resn_cd AS 취소사유,
       s.use_yn AS 사용여부, COUNT(*) AS 건수, SUM(s.pymn_amt) AS 결제금액합, MIN(s.pymn_amt) AS 최소금액
  FROM acvncsapt s
 WHERE s.work_ymd >= :p_date
   AND s.work_ymd <  :p_date + 1
 GROUP BY s.apcn_dvsn_cd, s.cash_apcn_dvsn_cd, s.cash_apcn_resn_cd, s.use_yn
 ORDER BY 1, 2, 3, 4;


/* 3-4. 현금영수증 승인액이 실제 현금 수납액(수납-카드-DDC)을 초과하거나 수납 헤더가 없는 건
        현금영수증은 현금 수납 중 발행 요청 건에만 존재하므로 현금수입 전체와는 일치하지 않는다 〔추정〕 */
WITH cash AS (
    SELECT s.mdrp_no, s.mcrc_ymd, s.mcrc_rno, SUM(s.pymn_amt) AS csap_amt
      FROM acvncsapt s
     WHERE s.work_ymd >= :p_date AND s.work_ymd < :p_date + 1
       AND s.use_yn = 'Y'                                           -- 〔추정〕 3-3 결과로 확인
     GROUP BY s.mdrp_no, s.mcrc_ymd, s.mcrc_rno
),
hdr AS (
    SELECT h.mdrp_no, h.mcrc_ymd, h.mcrc_rno, SUM(h.rcpc_amt - h.cdrc_amt - h.ddc_rcpc_amt) AS cash_amt
      FROM acrcrcpct h
     WHERE h.mcrc_ymd >= :p_date AND h.mcrc_ymd < :p_date + 1 AND h.cncl_dt IS NULL
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


/* 3-5. :p_diff 원 후보 (예: 58900) — 수납 헤더 / 카드승인 / 현금승인 에서 동시에 탐색 */
SELECT '수납헤더' AS 출처, h.mdrp_no, h.mcrc_ymd, h.mcrc_rno,
       h.rcpc_amt - h.cdrc_amt - h.ddc_rcpc_amt AS 금액, h.cncl_dt AS 취소일시
  FROM acrcrcpct h
 WHERE h.mcrc_ymd >= :p_date AND h.mcrc_ymd < :p_date + 1
   AND (ABS(h.rcpc_amt - h.cdrc_amt - h.ddc_rcpc_amt) = :p_diff OR ABS(h.cdrc_amt) = :p_diff)
UNION ALL
SELECT '카드승인', v.mdrp_no, v.mcrc_ymd, v.mcrc_rno, v.pymn_amt, v.card_apcn_ymd
  FROM acvncdapt v
 WHERE v.work_ymd >= :p_date AND v.work_ymd < :p_date + 1 AND ABS(v.pymn_amt) = :p_diff
UNION ALL
SELECT '현금승인', s.mdrp_no, s.mcrc_ymd, s.mcrc_rno, s.pymn_amt, s.cash_apcn_ymd
  FROM acvncsapt s
 WHERE s.work_ymd >= :p_date AND s.work_ymd < :p_date + 1 AND ABS(s.pymn_amt) = :p_diff;


/* ############################################################################
   4. 건별 추적 — 후보 접수번호의 수납 이력 타임라인 (직전 행 대비 증감 포함)
   ############################################################################ */
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


/* ############################################################################
   5. 보고용 — 일자·진료구분별 차액 요약 (식은 1-1과 동일, ROLLUP)
   ############################################################################ */
SELECT TO_CHAR(t.mcrc_ymd, 'YYYY-MM-DD') AS 수납일자, t.codv_cd AS 내원구분,
       COUNT(*) AS 전체건수, SUM(CASE WHEN t.diff_amt <> 0 THEN 1 ELSE 0 END) AS 차액건수, SUM(t.diff_amt) AS 차액합계
  FROM (SELECT a.mcrc_ymd, a.codv_cd,
               a.onbr_amt - a.rdex_amt - a.midl_amt - a.prrc_amt - a.blan_amt - a.uncl_amt - a.rcpc_amt AS diff_amt  -- 〔추정〕 식R1
          FROM acrcrcpct a
         WHERE a.mcrc_ymd >= :p_date AND a.mcrc_ymd < :p_date + 1 AND a.cncl_dt IS NULL) t
 GROUP BY ROLLUP (TO_CHAR(t.mcrc_ymd, 'YYYY-MM-DD'), t.codv_cd)
 ORDER BY 1, 2;


/* ============================================================================
   점검 포인트
   ----------------------------------------------------------------------------
   1. 순서: 0-1(마감시각) → 0-3(입원 구분값) → 0-4(정산식) → 1-1/1-2/1-3(차액 확인) → 2-x(원인) → 4(건별)
   2. 0-3에서 입원 미수합이 22,443,900이면 점검 기준과 일치, 22,443,990이면 마감 기준과 일치한다.
      헌혈감면합이 18,700이면 BLDT_RDEX_AMT = 리포트 '헌혈미수' 로 매핑이 확정된다. 〔추정〕
   3. 취소 건은 CNCL_DT IS NULL 로 제외했다. 취소가 별도 행(음수)이면 0-3의 음수수납건수로 확인한다.
   4. 0-2/0-4로 마감 금액 테이블과 점검 SQL을 확보하면 90원이 어느 미수 구분(개인/보훈/보훈위탁 등)인지 확정할 수 있다.
   5. 날짜 조건은 컬럼에 함수를 씌우지 않는 범위 조건으로 작성했다. ACRCRCPCT는 I04, VAN은 WORK_YMD,
      계산·처방은 헤더 접수번호 세미조인으로 인덱스를 타도록 했다(실행계획으로 확인).
   5-1. 0-5의 구분별 미수합을 엑셀 마감 구분별 값과 대조하면 90원이 어느 구분인지 직접 확인할 수 있다.
   6. UPDATE 등 보정은 포함하지 않았다. 운영 DB 변경은 원무과 확인 후 별도 절차로 진행한다.
   ============================================================================ */
