/* ============================================================================
   원무 차액 발생 확인 및 원인 파악 쿼리 모음 (Oracle 19c, SELECT 전용)
   작성: Elpam.k
   ----------------------------------------------------------------------------
   ※ 모든 테이블/컬럼명은 〔추정〕이다. 실제 스키마에 맞게 아래 매핑표대로 치환할 것.
   ※ 읽기 전용(SELECT)만 포함한다. 보정 UPDATE/DELETE는 포함하지 않는다.
   ※ 환자 식별 정보(성명 등)는 조회하지 않는다. 필요 시 접수번호로 별도 조회한다.

   [매핑표]  〔추정〕명            의미                              실제명
   ---------------------------------------------------------------------------
   BILL_MST      진료비 요약(접수 단위)   rcpt_no, pt_no, visit_dt, visit_type,
                                          tot_amt, ins_amt, pt_amt, nonins_amt, upd_dt
   BILL_DTL      진료비 상세(항목 단위)   rcpt_no, item_cd, tot_amt, ins_amt, pt_amt, nonins_amt
   BILL_CHG_HIST 진료비 변경 이력         rcpt_no, chg_dt, chg_user, chg_reason, before_amt, after_amt
   PAY_HIST      수납/환불 내역           rcpt_no, pay_no, pay_dt, pay_type('P'수납/'R'환불),
                                          pay_method, pay_amt(양수), pay_user
   DAY_CLOSE     일마감                   close_dt, visit_type, pay_sum, refund_sum

   [바인드 변수]
   :p_from  조회 시작일 (DATE, 예: DATE '2026-09-01')
   :p_to    조회 종료일 (DATE, 포함)
   :p_type  진료구분 ('O'외래/'I'입원/'E'응급, NULL=전체)
   :p_rcpt  접수번호 (Q5 상세 추적용)

   [차액 정의]  〔추정〕
   본인부담 차액 = 청구 본인부담금(BILL_MST.pt_amt) - 순수납액(수납 - 환불)
     > 0 : 미수 (덜 받음)      < 0 : 과수납 (더 받음)
   ============================================================================ */


/* ----------------------------------------------------------------------------
   Q1. 차액 발생 건 확인 (접수번호 단위: 청구 vs 수납)
   ---------------------------------------------------------------------------- */
WITH bill AS (
    SELECT m.rcpt_no, m.pt_no, m.visit_dt, m.visit_type, m.pt_amt AS bill_pt_amt
      FROM bill_mst m
     WHERE m.visit_dt >= :p_from
       AND m.visit_dt <  :p_to + 1
       AND (:p_type IS NULL OR m.visit_type = :p_type)
),
pay AS (
    SELECT p.rcpt_no,
           SUM(CASE WHEN p.pay_type = 'P' THEN p.pay_amt ELSE 0 END) AS paid_amt,
           SUM(CASE WHEN p.pay_type = 'R' THEN p.pay_amt ELSE 0 END) AS refund_amt,
           COUNT(*)                                                  AS pay_cnt,
           MAX(p.pay_dt)                                             AS last_pay_dt
      FROM pay_hist p
     GROUP BY p.rcpt_no
)
SELECT b.rcpt_no,
       b.visit_dt,
       b.visit_type,
       b.bill_pt_amt                                              AS 청구본인부담,
       NVL(p.paid_amt, 0)                                         AS 수납액,
       NVL(p.refund_amt, 0)                                       AS 환불액,
       NVL(p.paid_amt, 0) - NVL(p.refund_amt, 0)                  AS 순수납액,
       b.bill_pt_amt - (NVL(p.paid_amt, 0) - NVL(p.refund_amt, 0)) AS 차액,
       NVL(p.pay_cnt, 0)                                          AS 수납건수,
       p.last_pay_dt                                              AS 최종수납일시
  FROM bill b
  LEFT JOIN pay p ON p.rcpt_no = b.rcpt_no
 WHERE b.bill_pt_amt - (NVL(p.paid_amt, 0) - NVL(p.refund_amt, 0)) <> 0
 ORDER BY ABS(b.bill_pt_amt - (NVL(p.paid_amt, 0) - NVL(p.refund_amt, 0))) DESC,
          b.visit_dt;


/* ----------------------------------------------------------------------------
   Q2. 요약(BILL_MST) vs 상세(BILL_DTL) 합계 불일치 확인
       -> 원인이 "집계 오류"인지 "수납 누락"인지 분리하기 위한 1차 필터
   ---------------------------------------------------------------------------- */
SELECT m.rcpt_no,
       m.visit_dt,
       m.tot_amt                      AS 요약_총액,
       d.tot_amt                      AS 상세_총액,
       m.tot_amt - d.tot_amt          AS 총액차이,
       m.ins_amt - d.ins_amt          AS 공단부담차이,
       m.pt_amt  - d.pt_amt           AS 본인부담차이,
       m.nonins_amt - d.nonins_amt    AS 비급여차이
  FROM bill_mst m
  JOIN (SELECT rcpt_no,
               SUM(tot_amt)    AS tot_amt,
               SUM(ins_amt)    AS ins_amt,
               SUM(pt_amt)     AS pt_amt,
               SUM(nonins_amt) AS nonins_amt
          FROM bill_dtl
         GROUP BY rcpt_no) d
    ON d.rcpt_no = m.rcpt_no
 WHERE m.visit_dt >= :p_from
   AND m.visit_dt <  :p_to + 1
   AND (:p_type IS NULL OR m.visit_type = :p_type)
   AND (   m.tot_amt    <> d.tot_amt
        OR m.ins_amt    <> d.ins_amt
        OR m.pt_amt     <> d.pt_amt
        OR m.nonins_amt <> d.nonins_amt)
 ORDER BY ABS(m.tot_amt - d.tot_amt) DESC;


/* ----------------------------------------------------------------------------
   Q3. 일마감 vs 수납 상세 대조 (일자·진료구분별)
   ---------------------------------------------------------------------------- */
SELECT c.close_dt,
       c.visit_type,
       c.pay_sum                                   AS 마감_수납합계,
       NVL(s.pay_sum, 0)                           AS 상세_수납합계,
       c.pay_sum - NVL(s.pay_sum, 0)               AS 수납차액,
       c.refund_sum                                AS 마감_환불합계,
       NVL(s.refund_sum, 0)                        AS 상세_환불합계,
       c.refund_sum - NVL(s.refund_sum, 0)         AS 환불차액
  FROM day_close c
  LEFT JOIN (SELECT TRUNC(p.pay_dt)                                          AS pay_day,
                    m.visit_type,
                    SUM(CASE WHEN p.pay_type = 'P' THEN p.pay_amt ELSE 0 END) AS pay_sum,
                    SUM(CASE WHEN p.pay_type = 'R' THEN p.pay_amt ELSE 0 END) AS refund_sum
               FROM pay_hist p
               JOIN bill_mst m ON m.rcpt_no = p.rcpt_no
              GROUP BY TRUNC(p.pay_dt), m.visit_type) s
    ON s.pay_day = c.close_dt
   AND s.visit_type = c.visit_type
 WHERE c.close_dt >= :p_from
   AND c.close_dt <= :p_to
   AND (:p_type IS NULL OR c.visit_type = :p_type)
   AND (   c.pay_sum    <> NVL(s.pay_sum, 0)
        OR c.refund_sum <> NVL(s.refund_sum, 0))
 ORDER BY c.close_dt, c.visit_type;


/* ----------------------------------------------------------------------------
   Q4. 차액 원인 자동 분류 (Q1 결과 + 원인 플래그)
       원인 우선순위: 미수납 > 중복수납 > 수납후변경 > 환불불일치 > 단수차이 > 기타
   ---------------------------------------------------------------------------- */
WITH bill AS (
    SELECT m.rcpt_no, m.visit_dt, m.visit_type, m.pt_amt AS bill_pt_amt, m.upd_dt
      FROM bill_mst m
     WHERE m.visit_dt >= :p_from
       AND m.visit_dt <  :p_to + 1
       AND (:p_type IS NULL OR m.visit_type = :p_type)
),
pay AS (
    SELECT p.rcpt_no,
           SUM(CASE WHEN p.pay_type = 'P' THEN p.pay_amt ELSE 0 END) AS paid_amt,
           SUM(CASE WHEN p.pay_type = 'R' THEN p.pay_amt ELSE 0 END) AS refund_amt,
           COUNT(CASE WHEN p.pay_type = 'P' THEN 1 END)              AS paid_cnt,
           COUNT(CASE WHEN p.pay_type = 'R' THEN 1 END)              AS refund_cnt,
           MAX(p.pay_dt)                                             AS last_pay_dt
      FROM pay_hist p
     GROUP BY p.rcpt_no
),
dup AS (   -- 동일 접수·금액·수단이 1분 이내 중복된 수납
    SELECT DISTINCT rcpt_no
      FROM (SELECT p.rcpt_no,
                   COUNT(*) OVER (PARTITION BY p.rcpt_no, p.pay_type, p.pay_amt,
                                               p.pay_method, TRUNC(p.pay_dt, 'MI')) AS c
              FROM pay_hist p)
     WHERE c > 1
),
chg AS (   -- 진료비 변경 이력
    SELECT h.rcpt_no, MAX(h.chg_dt) AS last_chg_dt, COUNT(*) AS chg_cnt
      FROM bill_chg_hist h
     GROUP BY h.rcpt_no
),
diff AS (
    SELECT b.rcpt_no, b.visit_dt, b.visit_type, b.bill_pt_amt,
           NVL(p.paid_amt, 0)    AS paid_amt,
           NVL(p.refund_amt, 0)  AS refund_amt,
           NVL(p.paid_cnt, 0)    AS paid_cnt,
           NVL(p.refund_cnt, 0)  AS refund_cnt,
           p.last_pay_dt,
           c.last_chg_dt,
           NVL(c.chg_cnt, 0)     AS chg_cnt,
           CASE WHEN d.rcpt_no IS NOT NULL THEN 1 ELSE 0 END AS dup_flag,
           b.bill_pt_amt - (NVL(p.paid_amt, 0) - NVL(p.refund_amt, 0)) AS diff_amt
      FROM bill b
      LEFT JOIN pay  p ON p.rcpt_no = b.rcpt_no
      LEFT JOIN dup  d ON d.rcpt_no = b.rcpt_no
      LEFT JOIN chg  c ON c.rcpt_no = b.rcpt_no
)
SELECT f.rcpt_no,
       f.visit_dt,
       f.visit_type,
       f.bill_pt_amt  AS 청구본인부담,
       f.paid_amt     AS 수납액,
       f.refund_amt   AS 환불액,
       f.diff_amt     AS 차액,
       CASE
            WHEN f.paid_cnt = 0 AND f.diff_amt > 0                         THEN '1.미수납'
            WHEN f.dup_flag = 1 AND f.diff_amt < 0                         THEN '2.중복수납'
            WHEN f.last_chg_dt > f.last_pay_dt                             THEN '3.수납후 진료비변경'
            WHEN f.refund_cnt > 0 AND f.diff_amt <> 0                      THEN '4.환불 불일치'
            WHEN ABS(f.diff_amt) < 100                                     THEN '5.단수(절사)차이'
            ELSE                                                                '9.기타(수동확인)'
       END                AS 추정원인,
       f.chg_cnt      AS 변경이력건수,
       f.last_pay_dt  AS 최종수납일시,
       f.last_chg_dt  AS 최종변경일시
  FROM diff f
 WHERE f.diff_amt <> 0
 ORDER BY 추정원인, ABS(f.diff_amt) DESC;


/* ----------------------------------------------------------------------------
   Q5. 특정 접수번호 타임라인 (청구 변경 ↔ 수납/환불 시간순 추적)
   ---------------------------------------------------------------------------- */
SELECT ev_dt   AS 일시,
       ev_kind AS 구분,
       ev_desc AS 내용,
       amt     AS 금액,
       ev_user AS 처리자
  FROM (
        SELECT h.chg_dt                         AS ev_dt,
               '청구변경'                         AS ev_kind,
               h.chg_reason                     AS ev_desc,
               h.after_amt - h.before_amt       AS amt,
               h.chg_user                       AS ev_user
          FROM bill_chg_hist h
         WHERE h.rcpt_no = :p_rcpt
        UNION ALL
        SELECT p.pay_dt,
               CASE p.pay_type WHEN 'P' THEN '수납' ELSE '환불' END,
               p.pay_method,
               CASE p.pay_type WHEN 'P' THEN p.pay_amt ELSE -p.pay_amt END,
               p.pay_user
          FROM pay_hist p
         WHERE p.rcpt_no = :p_rcpt
       )
 ORDER BY ev_dt;


/* ----------------------------------------------------------------------------
   Q6. 항목(진료비 상세) 단위 비교: 변경 전후로 어떤 항목이 바뀌었는지는
       변경이력 테이블에 항목 코드가 있을 때만 가능 〔추정〕. 현재 상세 기준 분포 확인용.
   ---------------------------------------------------------------------------- */
SELECT d.item_cd,
       COUNT(*)         AS 건수,
       SUM(d.pt_amt)    AS 본인부담합계,
       SUM(d.nonins_amt) AS 비급여합계
  FROM bill_dtl d
 WHERE d.rcpt_no = :p_rcpt
 GROUP BY d.item_cd
 ORDER BY SUM(d.pt_amt) DESC;


/* ----------------------------------------------------------------------------
   Q7. 일자·원인별 차액 요약 (보고용)
       Q4를 뷰/인라인으로 재사용하려면 Q4의 SELECT를 WITH 절 하위로 감싼다.
   ---------------------------------------------------------------------------- */
SELECT NVL(TO_CHAR(visit_dt, 'YYYY-MM-DD'), '합계')   AS 진료일,
       NVL(추정원인, '소계')                              AS 추정원인,
       COUNT(*)                                          AS 건수,
       SUM(차액)                                         AS 차액합계
  FROM (
        /* ← Q4의 최종 SELECT 결과를 그대로 붙여 넣는다 (컬럼: visit_dt, 추정원인, 차액) */
        SELECT visit_dt, 추정원인, 차액 FROM dual WHERE 1 = 0
       )
 GROUP BY ROLLUP (TO_CHAR(visit_dt, 'YYYY-MM-DD'), 추정원인)
 ORDER BY 1, 2;


/* ============================================================================
   점검 포인트
   ----------------------------------------------------------------------------
   1. 날짜 조건은 컬럼에 함수를 씌우지 않는 범위 조건(>= / <)으로 작성했다. 인덱스 활용 목적.
   2. 인덱스 권장 〔추정〕: PAY_HIST(rcpt_no, pay_dt), BILL_MST(visit_dt, visit_type),
      BILL_CHG_HIST(rcpt_no, chg_dt)
   3. 환불 금액이 음수로 저장된 시스템이면 Q1/Q4/Q5의 'R' 처리부를 SUM(pay_amt) 단일 합으로 바꾼다.
   4. 수납취소(승인취소)가 별도 pay_type이면 CASE 분기에 추가해야 한다.
   5. Q4의 원인 분류는 휴리스틱이다. '9.기타'와 '3.수납후 진료비변경'은 Q5로 반드시 수동 확인한다.
   6. 운영 DB에서는 업무 시간대 대량 조회를 피하고 /*+ PARALLEL */ 힌트는 DBA 협의 후 사용한다.
   ============================================================================ */
