/* ============================================================================
   원무수입마감점검 2026-10-01 입원 미수합계(차액) 90원 원인 추적 (ACRCRCPCT, SELECT 전용)
   ----------------------------------------------------------------------------
   [확인] 마감 22,443,990 / 점검 22,443,900 → 점검이 90원 적음 (입원 컬럼만 차이)
   [추정] 점검값은 ACRCRCPCT 원천 집계로 계산된다고 가정. 점검 프로그램의 SQL을 확인하면 확정 가능.
   [바인드]  :p_date 점검일자 (DATE '2026-10-01')
             :p_io   입원 구분값 (ADMS_OTDV_CD 기준 〔추정〕, D0 결과로 확인)
             :p_close_dt 마감 종료일시 (L1 결과, D2용)
             :p_mdrp 진료접수번호 (D1/D3에서 찾은 건)
   ※ Test 환경에서 먼저 실행. 환자 식별정보는 조회하지 않는다.
   ============================================================================ */


/* ----------------------------------------------------------------------------
   D0. 입원/외래/응급 구분값 확인 + 점검 기준 후보 집계
       → 입원 행의 값이 22,443,900(점검) 또는 22,443,990(마감) 중 어느 쪽과 맞는지 본다.
   ---------------------------------------------------------------------------- */
SELECT a.adms_otdv_cd                                                    AS 입원외래구분,
       a.codv_cd                                                         AS 내원구분,
       COUNT(*)                                                          AS 전체건수,
       SUM(CASE WHEN a.cncl_dt IS NULL THEN a.uncl_amt ELSE 0 END)       AS 미수_취소제외,
       SUM(a.uncl_amt)                                                   AS 미수_취소포함,
       SUM(CASE WHEN a.cncl_dt IS NULL THEN a.uncl_amt - a.uncl_deps_amt ELSE 0 END) AS 미수_입금차감,
       SUM(CASE WHEN a.cncl_dt IS NULL THEN a.blan_amt ELSE 0 END)       AS 잔전합
  FROM acrcrcpct a
 WHERE a.mcrc_ymd >= :p_date
   AND a.mcrc_ymd <  :p_date + 1
 GROUP BY a.adms_otdv_cd, a.codv_cd
 ORDER BY 1, 2;


/* ----------------------------------------------------------------------------
   D1. 90원 후보 건 탐색 (입원, 점검일 수납분)
       ① 미수/미수입금/잔전/수납액이 ±90인 건
       ② 항목 정산 잔차(residual)가 ±90인 건  〔추정〕 식: Q1과 동일
   ---------------------------------------------------------------------------- */
SELECT a.mdrp_no, a.mcrc_ymd, a.mcrc_sno, a.mcrc_rno, a.rcdv_cd, a.rcst_cd, a.isty_cd,
       a.onbr_amt, a.uncl_amt, a.uncl_deps_amt, a.blan_amt, a.rcpc_amt,
       a.onbr_amt - a.rdex_amt - a.bldt_rdex_amt - a.midl_amt - a.prrc_amt
         - a.uncl_amt + a.uncl_deps_amt - a.blan_amt - a.rcpc_amt        AS residual,
       a.cncl_dt, a.last_updt_dt, a.last_updr_id
  FROM acrcrcpct a
 WHERE a.mcrc_ymd >= :p_date
   AND a.mcrc_ymd <  :p_date + 1
   AND a.adms_otdv_cd = :p_io
   AND (   ABS(a.uncl_amt)      = 90
        OR ABS(a.uncl_deps_amt) = 90
        OR ABS(a.blan_amt)      = 90
        OR ABS(a.rcpc_amt)      = 90
        OR ABS(a.onbr_amt - a.rdex_amt - a.bldt_rdex_amt - a.midl_amt - a.prrc_amt
               - a.uncl_amt + a.uncl_deps_amt - a.blan_amt - a.rcpc_amt) = 90)
 ORDER BY a.mdrp_no, a.mcrc_sno;


/* ----------------------------------------------------------------------------
   L1. 마감 실행 로그 (ACETCLSGT 수익수입마감로그) — 점검일자의 마감이 언제, 몇 번, 어떻게 돌았는지
       → 마감 종료시각을 D2의 :p_close_dt 로 사용한다. 재마감(여러 행)·에러 여부도 확인한다.
       CLSN_CRTN_DVSN_CD(생성구분) 값 의미는 코드 테이블로 확인 〔확인 필요〕
   ---------------------------------------------------------------------------- */
SELECT c.clsn_base_ymd                    AS 마감기준일자,
       c.clsn_strt_dt                     AS 시작일시,
       c.clsn_fnsh_dt                     AS 종료일시,
       c.clsn_crtn_dvsn_cd                AS 생성구분,
       c.clsn_crtn_resn_ctn               AS 생성사유,
       c.clos_id                          AS 마감자,
       c.err_mesg_ctn                     AS 에러메시지,
       c.rmrk_ctn                         AS 비고,
       c.last_updt_dt                     AS 최종수정일시
  FROM acetclsgt c
 WHERE c.clsn_base_ymd >= :p_date
   AND c.clsn_base_ymd <  :p_date + 1
 ORDER BY c.clsn_strt_dt;


/* ----------------------------------------------------------------------------
   D2. 마감 이후 변경/취소 건 (마감 종료시각 :p_close_dt 이후의 데이터 변동)
       :p_close_dt = L1의 마지막 정상 마감 종료일시 (DATE)
       마감은 그 시점 값, 점검은 출력 시점(10/02 07:49) 원천 값이라 시차로 어긋날 수 있다.
   ---------------------------------------------------------------------------- */
SELECT a.mdrp_no, a.mcrc_ymd, a.mcrc_sno, a.rcdv_cd,
       a.uncl_amt, a.uncl_deps_amt, a.rcpc_amt,
       a.cncl_dt, a.cncr_id,
       a.frst_rgst_dt, a.last_updt_dt, a.last_updr_id, a.last_updt_clnt_prgm_id
  FROM acrcrcpct a
 WHERE a.adms_otdv_cd = :p_io
   AND (   (a.mcrc_ymd >= :p_date AND a.mcrc_ymd < :p_date + 1
            AND (a.last_updt_dt > :p_close_dt OR a.cncl_dt > :p_close_dt))   -- 당일 수납 건이 마감 후 변경/취소
        OR (a.mcrc_ymd < :p_date
            AND (   (a.cncl_dt >= :p_date AND a.cncl_dt < :p_date + 1)
                 OR (a.last_updt_dt >= :p_date AND a.last_updt_dt < :p_date + 1))))  -- 과거 수납 건이 당일 변경
 ORDER BY a.last_updt_dt;


/* ----------------------------------------------------------------------------
   D3. 이전 수납 건 대비 미수 증감 (재수납·수정 체인에서 미수가 달라진 건)
       미수 증감 합이 90인지, 90원 건이 있는지 확인한다.
   ---------------------------------------------------------------------------- */
SELECT a.mdrp_no, a.mcrc_ymd, a.mcrc_sno,
       a.uncl_amt                         AS 현_미수,
       p.uncl_amt                         AS 전_미수,
       a.uncl_amt - NVL(p.uncl_amt, 0)    AS 미수_증감,
       a.uncl_deps_amt - NVL(p.uncl_deps_amt, 0) AS 미수입금_증감,
       a.isty_cd                          AS 현_보험유형,
       p.isty_cd                          AS 전_보험유형,
       a.last_updr_id, a.last_updt_clnt_prgm_id
  FROM acrcrcpct a
  LEFT JOIN acrcrcpct p
    ON p.mdrp_no  = a.mdrp_no
   AND p.mcrc_ymd = a.befr_mcrc_ymd
   AND p.mcrc_sno = a.befr_mcrc_sno
 WHERE a.mcrc_ymd >= :p_date
   AND a.mcrc_ymd <  :p_date + 1
   AND a.adms_otdv_cd = :p_io
   AND a.cncl_dt IS NULL
   AND a.befr_mcrc_ymd IS NOT NULL
   AND a.uncl_amt <> NVL(p.uncl_amt, 0)
 ORDER BY ABS(a.uncl_amt - NVL(p.uncl_amt, 0)), a.mdrp_no;


/* ----------------------------------------------------------------------------
   D4. 건 확정 후: 해당 접수번호 이력은 sql/wonmu_diff_check.sql 의 Q4(타임라인)에
       :p_mdrp 를 넣어 확인한다.
   ============================================================================ */
