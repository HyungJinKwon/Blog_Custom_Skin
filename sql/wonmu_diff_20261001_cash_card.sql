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
