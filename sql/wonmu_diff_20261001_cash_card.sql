/* ============================================================================
   원무수익마감점검 2026-10-01 현금수입(점검) 합계 차액 58,900원 확인용 (SELECT 전용)
   ----------------------------------------------------------------------------
   [확인] 엑셀: 현금수입(마감) 합계 33,513,950 / 현금수입(점검) 합계 33,455,050 / 차액 58,900
          구분별(외래·응급·입원) 점검값은 모두 0 → 점검 리포트가 구분별 현금을 집계하지 않을 가능성 〔추정〕
   [추정] 현금수입 = 총수납금 - 카드수납 으로 산출된다고 가정 (총수입 - 카드 = 마감 현금과 일치함은 검산 완료)
   [대상] ACVNCDAPT(VAN카드승인) ↔ ACRCRCPCT(진료비수납, CDRC_AMT 카드수납금액)
   [연결] MDRP_NO + MCRC_YMD + MCRC_RNO (VAN에는 일련번호가 없고 회차만 있음)
   [바인드]  :p_date 점검일자(DATE)   :p_apv 카드승인 구분값   :p_cncl 카드취소 구분값
             (:p_apv/:p_cncl 은 C0 결과로 확인 〔확인 필요〕)
   ============================================================================ */


/* ----------------------------------------------------------------------------
   C0. VAN 카드 승인 구분·입금구분별 분포 (구분 코드값과 금액 부호 확인)
   ---------------------------------------------------------------------------- */
SELECT v.card_apcn_dvsn_cd                   AS 카드승인취소구분,
       v.deps_dvsn_cd                        AS 입금구분,
       v.codv_cd                             AS 내원구분,
       COUNT(*)                              AS 건수,
       SUM(v.pymn_amt)                       AS 결제금액합,
       MIN(v.pymn_amt)                       AS 최소금액,
       SUM(CASE WHEN v.card_apcn_ymd IS NOT NULL THEN 1 ELSE 0 END) AS 취소일자있음
  FROM acvncdapt v
 WHERE v.mcrc_ymd >= :p_date
   AND v.mcrc_ymd <  :p_date + 1
 GROUP BY v.card_apcn_dvsn_cd, v.deps_dvsn_cd, v.codv_cd
 ORDER BY 1, 2, 3;


/* ----------------------------------------------------------------------------
   C1. 수납 헤더 카드수납금액 vs VAN 승인-취소 순액 (접수·회차 단위 불일치 건)
       금액 부호 규칙이 C0에서 확인되면 net_van 계산식을 조정한다.
   ---------------------------------------------------------------------------- */
WITH van AS (
    SELECT v.mdrp_no, v.mcrc_ymd, v.mcrc_rno,
           SUM(CASE WHEN v.card_apcn_dvsn_cd = :p_apv  THEN v.pymn_amt ELSE 0 END) AS apv_amt,
           SUM(CASE WHEN v.card_apcn_dvsn_cd = :p_cncl THEN v.pymn_amt ELSE 0 END) AS cncl_amt,
           COUNT(*)                                                              AS van_cnt
      FROM acvncdapt v
     WHERE v.mcrc_ymd >= :p_date
       AND v.mcrc_ymd <  :p_date + 1
     GROUP BY v.mdrp_no, v.mcrc_ymd, v.mcrc_rno
),
hdr AS (
    SELECT h.mdrp_no, h.mcrc_ymd, h.mcrc_rno,
           SUM(h.cdrc_amt)  AS cdrc_amt,
           SUM(h.rcpc_amt)  AS rcpc_amt,
           COUNT(*)         AS hdr_cnt
      FROM acrcrcpct h
     WHERE h.mcrc_ymd >= :p_date
       AND h.mcrc_ymd <  :p_date + 1
       AND h.cncl_dt IS NULL
     GROUP BY h.mdrp_no, h.mcrc_ymd, h.mcrc_rno
)
SELECT NVL(h.mdrp_no,  v.mdrp_no)                     AS 진료접수번호,
       NVL(h.mcrc_ymd, v.mcrc_ymd)                    AS 수납일자,
       NVL(h.mcrc_rno, v.mcrc_rno)                    AS 회차,
       NVL(h.cdrc_amt, 0)                             AS 헤더_카드수납,
       NVL(v.apv_amt, 0)                              AS VAN_승인,
       NVL(v.cncl_amt, 0)                             AS VAN_취소,
       NVL(v.apv_amt, 0) - NVL(v.cncl_amt, 0)         AS VAN_순액,        -- 〔추정〕 취소가 양수 저장일 때
       NVL(h.cdrc_amt, 0) - (NVL(v.apv_amt, 0) - NVL(v.cncl_amt, 0)) AS 차이,
       CASE WHEN h.mdrp_no IS NULL THEN 'VAN만 존재'
            WHEN v.mdrp_no IS NULL THEN '수납헤더만 존재' ELSE '양쪽 존재' END AS 존재구분
  FROM hdr h
  FULL OUTER JOIN van v
    ON v.mdrp_no  = h.mdrp_no
   AND v.mcrc_ymd = h.mcrc_ymd
   AND v.mcrc_rno = h.mcrc_rno
 WHERE NVL(h.cdrc_amt, 0) <> NVL(v.apv_amt, 0) - NVL(v.cncl_amt, 0)
 ORDER BY ABS(NVL(h.cdrc_amt, 0) - (NVL(v.apv_amt, 0) - NVL(v.cncl_amt, 0))) DESC;


/* ----------------------------------------------------------------------------
   C2. 58,900원 후보 탐색: 현금 잔여(수납-카드-DDC)가 58,900인 건, 또는 58,900원 승인·취소 건
   ---------------------------------------------------------------------------- */
SELECT h.mdrp_no, h.mcrc_ymd, h.mcrc_sno, h.mcrc_rno, h.adms_otdv_cd, h.rcdv_cd,
       h.rcpc_amt, h.cdrc_amt, h.ddc_rcpc_amt,
       h.rcpc_amt - h.cdrc_amt - h.ddc_rcpc_amt AS 현금등,
       h.cncl_dt, h.card_apcn_dt, h.capy_cncl_dt, h.last_updt_dt
  FROM acrcrcpct h
 WHERE h.mcrc_ymd >= :p_date
   AND h.mcrc_ymd <  :p_date + 1
   AND (   ABS(h.rcpc_amt - h.cdrc_amt - h.ddc_rcpc_amt) = 58900
        OR ABS(h.cdrc_amt) = 58900
        OR ABS(h.rcpc_amt) = 58900)
UNION ALL
SELECT v.mdrp_no, v.mcrc_ymd, NULL, v.mcrc_rno, NULL, v.card_apcn_dvsn_cd,
       v.pymn_amt, NULL, NULL, NULL, NULL, v.card_apcn_ymd, NULL, v.last_updt_dt
  FROM acvncdapt v
 WHERE v.mcrc_ymd >= :p_date
   AND v.mcrc_ymd <  :p_date + 1
   AND ABS(v.pymn_amt) = 58900;


/* ============================================================================
   현금영수증(ACVNCSAPT VAN현금승인) 대조 — 현금수입 58,900원 후보 확인
   [연결] MDRP_NO + MCRC_YMD + MCRC_RNO / 금액: PYMN_AMT(결제금액), TOTL_PYMN_AMT(총결제금액)
   [구분] APCN_DVSN_CD(승인취소구분), CASH_APCN_DVSN_CD(현금승인취소구분), CASH_APCN_RESN_CD(사유),
          USE_YN(사용여부), ORGL_APRV_NO(원승인번호: 취소 건이 가리키는 원 승인)
   ※ 현금영수증은 현금 수납의 일부(발행 요청 건)에만 존재하므로 현금수입 전체와 일치하지 않는다. 〔추정〕
   ============================================================================ */

/* ----------------------------------------------------------------------------
   C3. 현금승인 구분·사용여부별 분포 (구분 코드값과 금액 부호 확인)
   ---------------------------------------------------------------------------- */
SELECT s.apcn_dvsn_cd                          AS 승인취소구분,
       s.cash_apcn_dvsn_cd                     AS 현금승인취소구분,
       s.cash_apcn_resn_cd                     AS 취소사유,
       s.use_yn                                AS 사용여부,
       COUNT(*)                                AS 건수,
       SUM(s.pymn_amt)                         AS 결제금액합,
       MIN(s.pymn_amt)                         AS 최소금액
  FROM acvncsapt s
 WHERE s.mcrc_ymd >= :p_date
   AND s.mcrc_ymd <  :p_date + 1
 GROUP BY s.apcn_dvsn_cd, s.cash_apcn_dvsn_cd, s.cash_apcn_resn_cd, s.use_yn
 ORDER BY 1, 2, 3, 4;


/* ----------------------------------------------------------------------------
   C4. 현금영수증 승인액이 실제 현금 수납액을 초과하거나, 취소만 있고 원승인이 없는 건
       현금등 = 수납금액 - 카드 - DDC 〔추정〕  (헤더 단위: 접수·회차)
   ---------------------------------------------------------------------------- */
WITH cash AS (
    SELECT s.mdrp_no, s.mcrc_ymd, s.mcrc_rno,
           SUM(s.pymn_amt)  AS csap_amt,
           COUNT(*)         AS csap_cnt
      FROM acvncsapt s
     WHERE s.mcrc_ymd >= :p_date
       AND s.mcrc_ymd <  :p_date + 1
       AND s.use_yn = 'Y'                          -- 〔추정〕 사용여부 Y=유효, C3에서 확인
     GROUP BY s.mdrp_no, s.mcrc_ymd, s.mcrc_rno
),
hdr AS (
    SELECT h.mdrp_no, h.mcrc_ymd, h.mcrc_rno,
           SUM(h.rcpc_amt - h.cdrc_amt - h.ddc_rcpc_amt) AS cash_amt
      FROM acrcrcpct h
     WHERE h.mcrc_ymd >= :p_date
       AND h.mcrc_ymd <  :p_date + 1
       AND h.cncl_dt IS NULL
     GROUP BY h.mdrp_no, h.mcrc_ymd, h.mcrc_rno
)
SELECT NVL(h.mdrp_no,  c.mdrp_no)       AS 진료접수번호,
       NVL(h.mcrc_ymd, c.mcrc_ymd)      AS 수납일자,
       NVL(h.mcrc_rno, c.mcrc_rno)      AS 회차,
       NVL(h.cash_amt, 0)               AS 헤더_현금등,
       NVL(c.csap_amt, 0)               AS 현금영수증_승인액,
       NVL(c.csap_amt, 0) - NVL(h.cash_amt, 0) AS 초과분,
       CASE WHEN h.mdrp_no IS NULL THEN '현금영수증만 존재' ELSE '양쪽 존재' END AS 존재구분
  FROM cash c
  LEFT JOIN hdr h
    ON h.mdrp_no  = c.mdrp_no
   AND h.mcrc_ymd = c.mcrc_ymd
   AND h.mcrc_rno = c.mcrc_rno
 WHERE h.mdrp_no IS NULL
    OR c.csap_amt > h.cash_amt
 ORDER BY 6 DESC;


/* ----------------------------------------------------------------------------
   C5. 58,900원 후보 (현금승인 테이블에서 ±58,900 건 + 취소·미사용 건)
   ---------------------------------------------------------------------------- */
SELECT s.work_ymd, s.work_sno, s.mdrp_no, s.mcrc_ymd, s.mcrc_rno,
       s.apcn_dvsn_cd, s.cash_apcn_dvsn_cd, s.cash_apcn_resn_cd,
       s.pymn_amt, s.totl_pymn_amt, s.csap_ymd, s.cash_apcn_ymd,
       s.orgl_aprv_no, s.use_yn, s.last_updt_dt
  FROM acvncsapt s
 WHERE s.mcrc_ymd >= :p_date
   AND s.mcrc_ymd <  :p_date + 1
   AND (ABS(s.pymn_amt) = 58900 OR ABS(s.totl_pymn_amt) = 58900)
 ORDER BY s.csap_ymd, s.work_sno;
