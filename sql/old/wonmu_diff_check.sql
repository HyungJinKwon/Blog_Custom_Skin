/* ============================================================================
   원무 차액 발생 확인 및 원인 파악 쿼리 (ACRCRCPCT 진료비수납 기준)
   DBMS : Oracle 19c  /  SELECT 전용(읽기 전용)  /  작성: Elpam.k
   ----------------------------------------------------------------------------
   [확인] 컬럼명·타입·NOT NULL·PK/인덱스는 제공된 테이블 정의서 기준
   [추정] "정산 공식"과 코드값 의미는 정의서에 없으므로 〔추정〕 → Q0으로 먼저 검증한다.
   ※ 반드시 Test 환경에서 먼저 실행한다. 환자 식별 정보(성명 등)는 조회하지 않는다.

   [키]    PK  = MDRP_NO(진료접수번호) + MCRC_YMD(진료비수납일자) + MCRC_SNO(일련번호)
           I01 = PTNO + MCRC_YMD + MCRC_RNO
   [이력]  BEFR_MCRC_YMD / BEFR_MCRC_SNO = 이전 수납 건 (수정·재수납 체인)
           INTG_MCRC_RNO(통합) / NEW_MCRC_RNO(신규) = 회차 통합·재생성

   [바인드]  :p_from  조회 시작일(DATE)      :p_to    조회 종료일(DATE, 포함)
             :p_mdrp  진료접수번호(Q5)       :p_ptno  환자번호(Q5, 선택)

   [성능]  ACRCRCPCT_I04 가 MCRC_YMD 선두(MCRC_YMD, RPNT_ID, ...)라 날짜 범위 조회에 인덱스를 쓸 수 있다.
           I02(CODV_CD, CNCL_DT, PTNO)는 내원구분·취소 조건과 함께일 때 후보. 실제 사용 여부는 실행계획으로 확인한다.
           ACCLMCCLT는 I03(MDRP_NO 선두)을 쓰므로 헤더에서 접수번호로 조인하는 경로가 유리하다.
   ============================================================================ */


/* ----------------------------------------------------------------------------
   Q0-1. 코드값 분포 프로파일 (수납구분 / 수납상태 / 취소 여부)
         → RCDV_CD, RCST_CD, 내원구분(CODV_CD) 의미를 코드 테이블과 대조해 확정한다.
   ---------------------------------------------------------------------------- */
SELECT a.codv_cd                                   AS 내원구분,
       a.rcdv_cd                                   AS 수납구분,
       a.rcst_cd                                   AS 수납상태,
       CASE WHEN a.cncl_dt IS NULL THEN 'N' ELSE 'Y' END AS 취소여부,
       COUNT(*)                                    AS 건수,
       SUM(a.rcpc_amt)                             AS 수납금액합,
       MIN(a.rcpc_amt)                             AS 최소수납액,
       SUM(CASE WHEN a.rcpc_amt < 0 THEN 1 ELSE 0 END) AS 음수건수
  FROM acrcrcpct a
 WHERE a.mcrc_ymd >= :p_from
   AND a.mcrc_ymd <  :p_to + 1
 GROUP BY a.codv_cd, a.rcdv_cd, a.rcst_cd,
          CASE WHEN a.cncl_dt IS NULL THEN 'N' ELSE 'Y' END
 ORDER BY 1, 2, 3, 4;


/* ----------------------------------------------------------------------------
   Q0-2. 정산식 후보 검증 (불일치 건수가 가장 적은 식 = 실제 정산식일 가능성이 높다)
         취소 건(CNCL_DT 존재)은 제외한다.
   ---------------------------------------------------------------------------- */
SELECT COUNT(*) AS 대상건수,
       /* 항등식 후보 (금액 항목 간 정합성) */
       SUM(CASE WHEN a.tomc_amt <> a.totl_inpy_amt + a.totl_nnpy_amt
                THEN 1 ELSE 0 END)                                     AS 총진료비_vs_급여plus비급여,
       SUM(CASE WHEN a.clam_amt <> a.totl_inpy_amt - a.inpy_onbr_amt
                THEN 1 ELSE 0 END)                                     AS 청구금액_vs_급여minus급여본인부담,
       SUM(CASE WHEN a.cdrc_amt + a.ddc_rcpc_amt > a.rcpc_amt
                THEN 1 ELSE 0 END)                                     AS 카드plusDDC_초과수납,
       /* 수납금액 정산식 후보 */
       SUM(CASE WHEN a.rcpc_amt <>
                a.onbr_amt - a.rdex_amt - a.bldt_rdex_amt - a.midl_amt - a.prrc_amt
                - a.uncl_amt + a.uncl_deps_amt - a.blan_amt
                THEN 1 ELSE 0 END)                                     AS 식F1,
       SUM(CASE WHEN a.rcpc_amt <>
                a.onbr_amt - a.rdex_amt - a.bldt_rdex_amt - a.midl_amt - a.prrc_amt
                - a.uncl_amt + a.uncl_deps_amt
                THEN 1 ELSE 0 END)                                     AS 식F2_잔전제외,
       SUM(CASE WHEN a.rcpc_amt <>
                a.onbr_amt - a.rdex_amt - a.bldt_rdex_amt - a.cnpl_brdn_amt - a.midl_amt
                - a.prrc_amt - a.uncl_amt + a.uncl_deps_amt - a.blan_amt
                THEN 1 ELSE 0 END)                                     AS 식F3_계약처부담포함,
       SUM(CASE WHEN a.rcpc_amt <>
                a.onbr_amt - a.rdex_amt - a.bldt_rdex_amt - a.midl_amt - a.prrc_amt
                - a.pyan_aplc_amt - a.supr_amt - a.uncl_amt + a.uncl_deps_amt - a.blan_amt
                THEN 1 ELSE 0 END)                                     AS 식F4_대불후원포함
  FROM acrcrcpct a
 WHERE a.mcrc_ymd >= :p_from
   AND a.mcrc_ymd <  :p_to + 1
   AND a.cncl_dt IS NULL;


/* ----------------------------------------------------------------------------
   Q1. 차액 발생 건 확인 (수납 건 단위)
       차액 = 정산식 기대 수납액 - 실제 수납액(RCPC_AMT)
       ※ exp_rcpc_amt 식은 이 CTE 한 곳에서만 정의한다. Q0-2 결과로 확정한 식으로 교체할 것.
   ---------------------------------------------------------------------------- */
WITH base AS (
    SELECT a.mdrp_no, a.mcrc_ymd, a.mcrc_sno, a.mcrc_rno, a.ptno,
           a.codv_cd, a.rcdv_cd, a.rcst_cd, a.isty_cd,
           a.tomc_amt, a.onbr_amt, a.rcpc_amt, a.cdrc_amt, a.ddc_rcpc_amt,
           a.rdex_amt, a.bldt_rdex_amt, a.midl_amt, a.prrc_amt,
           a.uncl_amt, a.uncl_deps_amt, a.blan_amt,
           /* 〔추정〕 식F1 — Q0-2에서 불일치가 가장 적은 식으로 교체 */
           a.onbr_amt - a.rdex_amt - a.bldt_rdex_amt - a.midl_amt - a.prrc_amt
             - a.uncl_amt + a.uncl_deps_amt - a.blan_amt            AS exp_rcpc_amt
      FROM acrcrcpct a
     WHERE a.mcrc_ymd >= :p_from
       AND a.mcrc_ymd <  :p_to + 1
       AND a.cncl_dt IS NULL
)
SELECT b.mdrp_no                         AS 진료접수번호,
       b.mcrc_ymd                        AS 수납일자,
       b.mcrc_sno                        AS 일련번호,
       b.ptno                            AS 환자번호,
       b.rcdv_cd                         AS 수납구분,
       b.tomc_amt                        AS 총진료비,
       b.onbr_amt                        AS 본인부담금,
       b.exp_rcpc_amt                    AS 기대수납액,
       b.rcpc_amt                        AS 실수납액,
       b.exp_rcpc_amt - b.rcpc_amt       AS 차액,
       CASE WHEN b.exp_rcpc_amt - b.rcpc_amt > 0 THEN '수납부족' ELSE '과수납' END AS 방향
  FROM base b
 WHERE b.exp_rcpc_amt <> b.rcpc_amt
 ORDER BY ABS(b.exp_rcpc_amt - b.rcpc_amt) DESC, b.mcrc_ymd, b.mdrp_no;


/* ----------------------------------------------------------------------------
   Q2. 정산식과 무관한 "항목 간 정합성" 위반 건 (공식 확정 전에도 즉시 사용 가능)
   ---------------------------------------------------------------------------- */
SELECT a.mdrp_no, a.mcrc_ymd, a.mcrc_sno, a.ptno,
       a.rcpc_amt, a.cdrc_amt, a.ddc_rcpc_amt,
       a.rcpc_amt - a.cdrc_amt - a.ddc_rcpc_amt          AS 현금등_잔여수납,
       a.tomc_amt - (a.totl_inpy_amt + a.totl_nnpy_amt)  AS 총진료비_차이,
       a.clam_amt - (a.totl_inpy_amt - a.inpy_onbr_amt)  AS 청구금액_차이,
       a.uncl_deps_amt - a.uncl_amt                      AS 미수입금_초과분,
       CASE
            WHEN a.cdrc_amt + a.ddc_rcpc_amt > a.rcpc_amt                 THEN '카드+DDC가 수납액 초과'
            WHEN a.cncl_dt IS NOT NULL AND a.rcpc_amt <> 0                THEN '취소일시 있으나 수납액 잔존'
            WHEN a.card_apcn_dt IS NOT NULL AND a.cdrc_amt <> 0           THEN '카드취소일시 있으나 카드액 잔존'
            WHEN a.ddc_apcn_dt  IS NOT NULL AND a.ddc_rcpc_amt <> 0       THEN 'DDC취소일시 있으나 DDC액 잔존'
            WHEN a.capy_cncl_dt IS NOT NULL AND a.rcpc_amt - a.cdrc_amt - a.ddc_rcpc_amt <> 0
                                                                          THEN '현금취소일시 있으나 현금액 잔존'
            WHEN a.uncl_deps_amt > a.uncl_amt                             THEN '미수입금이 미수금액 초과'
            WHEN a.uncl_amt > 0 AND a.uncl_resn_cd IS NULL                THEN '미수금 있으나 미수사유 없음'
            WHEN a.tomc_amt <> a.totl_inpy_amt + a.totl_nnpy_amt          THEN '총진료비 ≠ 급여+비급여'
            WHEN a.clam_amt <> a.totl_inpy_amt - a.inpy_onbr_amt          THEN '청구금액 ≠ 급여-급여본인부담'
       END                                               AS 위반유형
  FROM acrcrcpct a
 WHERE a.mcrc_ymd >= :p_from
   AND a.mcrc_ymd <  :p_to + 1
   AND (   a.cdrc_amt + a.ddc_rcpc_amt > a.rcpc_amt
        OR (a.cncl_dt IS NOT NULL AND a.rcpc_amt <> 0)
        OR (a.card_apcn_dt IS NOT NULL AND a.cdrc_amt <> 0)
        OR (a.ddc_apcn_dt  IS NOT NULL AND a.ddc_rcpc_amt <> 0)
        OR (a.capy_cncl_dt IS NOT NULL AND a.rcpc_amt - a.cdrc_amt - a.ddc_rcpc_amt <> 0)
        OR a.uncl_deps_amt > a.uncl_amt
        OR (a.uncl_amt > 0 AND a.uncl_resn_cd IS NULL)
        OR a.tomc_amt <> a.totl_inpy_amt + a.totl_nnpy_amt
        OR a.clam_amt <> a.totl_inpy_amt - a.inpy_onbr_amt)
 ORDER BY a.mcrc_ymd, a.mdrp_no, a.mcrc_sno;


/* ----------------------------------------------------------------------------
   Q3. 원인 파악: 이전 수납 건(BEFR_MCRC_YMD/SNO) 대비 어떤 항목이 변했는가
       차액이 있는 건을 "직전 상태"와 비교해 변동 항목으로 원인을 추정한다.
       처리자/프로그램 컬럼으로 책임 추적도 가능하다.
   ---------------------------------------------------------------------------- */
WITH base AS (
    SELECT a.*,
           a.onbr_amt - a.rdex_amt - a.bldt_rdex_amt - a.midl_amt - a.prrc_amt
             - a.uncl_amt + a.uncl_deps_amt - a.blan_amt AS exp_rcpc_amt   -- 〔추정〕 Q1과 동일 식 사용
      FROM acrcrcpct a
     WHERE a.mcrc_ymd >= :p_from
       AND a.mcrc_ymd <  :p_to + 1
       AND a.cncl_dt IS NULL
),
diff AS (
    SELECT b.*, b.exp_rcpc_amt - b.rcpc_amt AS diff_amt
      FROM base b
     WHERE b.exp_rcpc_amt <> b.rcpc_amt
)
SELECT d.mdrp_no                                       AS 진료접수번호,
       d.mcrc_ymd                                      AS 수납일자,
       d.mcrc_sno                                      AS 일련번호,
       d.diff_amt                                      AS 차액,
       CASE
            WHEN p.mdrp_no IS NULL                                   THEN '0.이전건 없음(최초 수납)'
            WHEN d.isty_cd <> p.isty_cd                              THEN '1.보험유형 변경'
            WHEN d.tomc_amt <> p.tomc_amt                            THEN '2.총진료비 변동'
            WHEN d.rdex_amt <> p.rdex_amt
              OR d.bldt_rdex_amt <> p.bldt_rdex_amt                  THEN '3.감면 변동'
            WHEN d.uncl_amt <> p.uncl_amt
              OR d.uncl_deps_amt <> p.uncl_deps_amt                  THEN '4.미수/미수입금 변동'
            WHEN d.cdrc_amt <> p.cdrc_amt
              OR d.ddc_rcpc_amt <> p.ddc_rcpc_amt                    THEN '5.결제수단 변경'
            WHEN d.midl_amt <> p.midl_amt
              OR d.prrc_amt <> p.prrc_amt                            THEN '6.중간/기수납 변동'
            WHEN ABS(d.diff_amt) < 100                               THEN '7.단수(잔전) 차이'
            ELSE                                                          '9.기타(수동확인)'
       END                                             AS 추정원인,
       d.tomc_amt - NVL(p.tomc_amt, 0)                 AS 총진료비_증감,
       d.onbr_amt - NVL(p.onbr_amt, 0)                 AS 본인부담_증감,
       d.rcpc_amt - NVL(p.rcpc_amt, 0)                 AS 수납액_증감,
       d.isty_cd                                       AS 현_보험유형,
       p.isty_cd                                       AS 전_보험유형,
       d.last_updr_id                                  AS 최종수정자,
       d.last_updt_dt                                  AS 최종수정일시,
       d.last_updt_clnt_prgm_id                        AS 최종수정프로그램
  FROM diff d
  LEFT JOIN acrcrcpct p
    ON p.mdrp_no  = d.mdrp_no
   AND p.mcrc_ymd = d.befr_mcrc_ymd
   AND p.mcrc_sno = d.befr_mcrc_sno
 ORDER BY 추정원인, ABS(d.diff_amt) DESC;


/* ----------------------------------------------------------------------------
   Q4. 특정 진료접수번호의 수납 이력 타임라인 (직전 행 대비 증감 포함)
   ---------------------------------------------------------------------------- */
SELECT a.mcrc_ymd                              AS 수납일자,
       a.mcrc_sno                              AS 일련번호,
       a.mcrc_rno                              AS 회차,
       a.rcdv_cd                               AS 수납구분,
       a.rcst_cd                               AS 수납상태,
       a.isty_cd                               AS 보험유형,
       a.tomc_amt                              AS 총진료비,
       a.onbr_amt                              AS 본인부담,
       a.rdex_amt + a.bldt_rdex_amt            AS 감면합,
       a.midl_amt                              AS 중간금액,
       a.prrc_amt                              AS 기수납,
       a.uncl_amt                              AS 미수,
       a.uncl_deps_amt                         AS 미수입금,
       a.rcpc_amt                              AS 수납금액,
       a.cdrc_amt                              AS 카드,
       a.ddc_rcpc_amt                          AS DDC,
       a.rcpc_amt - a.cdrc_amt - a.ddc_rcpc_amt AS 현금등,
       a.rcpc_amt - LAG(a.rcpc_amt) OVER (ORDER BY a.mcrc_ymd, a.mcrc_sno) AS 수납액_증감,
       a.tomc_amt - LAG(a.tomc_amt) OVER (ORDER BY a.mcrc_ymd, a.mcrc_sno) AS 총진료비_증감,
       a.cncl_dt                               AS 취소일시,
       a.cncr_id                               AS 취소자,
       a.befr_mcrc_ymd                         AS 이전수납일자,
       a.befr_mcrc_sno                         AS 이전일련번호,
       a.frst_rgsr_id                          AS 최초등록자,
       a.frst_rgst_dt                          AS 최초등록일시,
       a.last_updr_id                          AS 최종수정자,
       a.last_updt_dt                          AS 최종수정일시
  FROM acrcrcpct a
 WHERE a.mdrp_no = :p_mdrp
   AND (:p_ptno IS NULL OR a.ptno = :p_ptno)
 ORDER BY a.mcrc_ymd, a.mcrc_sno;


/* ----------------------------------------------------------------------------
   Q5. 진료접수번호 단위 합계 차액 (수납 건이 여러 개일 때 접수 기준으로 합산)
   ---------------------------------------------------------------------------- */
SELECT a.mdrp_no                                       AS 진료접수번호,
       MIN(a.ptno)                                     AS 환자번호,
       COUNT(*)                                        AS 수납건수,
       SUM(a.onbr_amt)                                 AS 본인부담합,
       SUM(a.rdex_amt + a.bldt_rdex_amt)               AS 감면합,
       SUM(a.rcpc_amt)                                 AS 수납합,
       SUM(a.uncl_amt - a.uncl_deps_amt)               AS 미수잔액합,
       SUM(a.onbr_amt - a.rdex_amt - a.bldt_rdex_amt
           - a.rcpc_amt - (a.uncl_amt - a.uncl_deps_amt)) AS 접수단위_차액   -- 〔추정〕
  FROM acrcrcpct a
 WHERE a.mdrp_no IN (SELECT x.mdrp_no
                       FROM acrcrcpct x
                      WHERE x.mcrc_ymd >= :p_from
                        AND x.mcrc_ymd <  :p_to + 1)
   AND a.cncl_dt IS NULL
 GROUP BY a.mdrp_no
HAVING SUM(a.onbr_amt - a.rdex_amt - a.bldt_rdex_amt
           - a.rcpc_amt - (a.uncl_amt - a.uncl_deps_amt)) <> 0
 ORDER BY ABS(SUM(a.onbr_amt - a.rdex_amt - a.bldt_rdex_amt
           - a.rcpc_amt - (a.uncl_amt - a.uncl_deps_amt))) DESC;


/* ----------------------------------------------------------------------------
   Q6. 일자·수납구분별 차액 요약 (보고용, ROLLUP)
   ---------------------------------------------------------------------------- */
SELECT TO_CHAR(t.mcrc_ymd, 'YYYY-MM-DD')               AS 수납일자,
       t.rcdv_cd                                       AS 수납구분,
       COUNT(*)                                        AS 전체건수,
       SUM(CASE WHEN t.diff_amt <> 0 THEN 1 ELSE 0 END) AS 차액건수,
       SUM(t.diff_amt)                                 AS 차액합계
  FROM (SELECT a.mcrc_ymd, a.rcdv_cd,
               a.onbr_amt - a.rdex_amt - a.bldt_rdex_amt - a.midl_amt - a.prrc_amt
                 - a.uncl_amt + a.uncl_deps_amt - a.blan_amt - a.rcpc_amt AS diff_amt  -- 〔추정〕 Q1과 동일 식
          FROM acrcrcpct a
         WHERE a.mcrc_ymd >= :p_from
           AND a.mcrc_ymd <  :p_to + 1
           AND a.cncl_dt IS NULL) t
 GROUP BY ROLLUP (TO_CHAR(t.mcrc_ymd, 'YYYY-MM-DD'), t.rcdv_cd)
 ORDER BY 1, 2;


/* ============================================================================
   점검 포인트
   ----------------------------------------------------------------------------
   1. 순서: Q0-1(코드 확인) → Q0-2(정산식 확정) → Q1(차액 확인) → Q2/Q3(원인) → Q4(건별 추적)
   2. Q0-2에서 어떤 식도 불일치율이 높지 않으면 수납 외 항목(대불 PYAN_APLC_AMT, 후원 SUPR_AMT,
      장애인기금 DBFU_AMT, 상한제초과 ULRG_EXCS_AMT 등)이 식에 포함될 가능성이 있다.
   3. 취소 건은 Q1/Q3/Q6에서 CNCL_DT IS NULL로 제외했다. 취소 원본·취소분이 별도 행(음수 포함)으로
      저장되는지는 Q0-1의 '음수건수'와 '취소여부' 분포로 확인한다. 〔확인 필요〕
   4. INTG_MCRC_RNO(통합), NEW_MCRC_RNO(신규 회차)가 있는 건은 회차가 합쳐지거나 재생성된 건이므로
      Q3에서 '이전건 없음/기타'로 분류되면 이 컬럼과 BEFR_MCRC_* 를 함께 확인한다.
   5. 보정이 필요한 경우 UPDATE는 본 파일에 포함하지 않았다. 운영 DB 변경은 원무과 확인 후 별도 절차로 진행한다.
   ============================================================================ */
