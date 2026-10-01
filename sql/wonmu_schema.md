# 원무 차액 점검 — 업로드된 테이블·컬럼 정리

> 출처: 업로드된 테이블 정의서 캡처(쿼리생성기 화면) 및 `원무수입마감점검` 엑셀
> 표기: `●` = NOT NULL, 타입의 숫자 = DATA_LENGTH, `NUMBER`/`DATE`는 길이 생략
> 〔확인〕 화면에 표시된 내용 / 〔한계〕 캡처에서 잘렸거나 보이지 않은 부분은 별도 표기

## 0. 테이블 한눈에 보기

| # | 테이블 | 테이블명 | 컬럼 수 | PK | 역할 |
|---|---|---|---|---|---|
| 1 | `ACRCRCPCT` | 진료비수납 | 104 | MDRP_NO, MCRC_YMD, MCRC_SNO | 수납 헤더 (금액 집계의 기준) |
| 2 | `ACCLMCCLT` | 진료비계산 | 179 | MDRP_NO, MCCL_SNO | 처방(항목) 단위 계산 내역 |
| 3 | `ACCLPAORT` | 원무처방 | 72 | PTNO, INPT_YMD, PTAD_ORDR_SNO | 계산 이전 단계의 원무 처방 |
| 4 | `ACVNCDAPT` | VAN카드승인 | 70 | WORK_YMD, WORK_SNO | 카드 승인·취소 원장 |
| 5 | `ACVNCSAPT` | VAN현금승인 | 66 | WORK_YMD, WORK_SNO | 현금영수증 승인·취소 원장 |
| 6 | `ACETCLSGT` | 수익수입마감로그 | 18 | 〔한계〕 PK 미확인 | 마감 실행 이력 |
| 7 | (엑셀) | 원무수입마감점검 | 6열 | - | 마감/점검/차액 리포트 |

**데이터 흐름**: 원무처방(`ACCLPAORT`) → 진료비계산(`ACCLMCCLT`) → 진료비수납(`ACRCRCPCT`) → VAN 승인(`ACVNCDAPT`, `ACVNCSAPT`) → 일마감(`ACETCLSGT`) → 엑셀 리포트

**연결키**
| 연결 | 키 |
|---|---|
| 수납 ↔ 계산 | `MDRP_NO + MCRC_YMD + MCRC_SNO` |
| 수납 ↔ VAN | `MDRP_NO + MCRC_YMD + MCRC_RNO` (VAN에는 `SNO` 없음) |
| 계산 ↔ 처방 | `MDRP_NO + ORDR_YMD + ORDR_SNO` 〔추정〕 |
| 수납 이전 건 | `BEFR_MCRC_YMD + BEFR_MCRC_SNO` |

### 공통 감사 컬럼 (업로드된 DB 테이블 6개 모두에 존재, 전부 NOT NULL)

| 컬럼 | 컬럼명 | 타입 |
|---|---|---|
| FRST_RGSR_ID | 최초등록자ID | VARCHAR2(10) |
| FRST_RGST_IP | 최초등록IP | VARCHAR2(39) |
| FRST_RGST_DT | 최초등록일시 | DATE |
| FRST_RGST_CLNT_PRGM_ID | 최초등록클라이언트프로그램ID | VARCHAR2(20) |
| FRST_RGST_SRVR_PRGM_ID | 최초등록서버프로그램ID | VARCHAR2(50) |
| LAST_UPDR_ID | 최종수정자ID | VARCHAR2(10) |
| LAST_UPDT_IP | 최종수정IP | VARCHAR2(39) |
| LAST_UPDT_DT | 최종수정일시 | DATE |
| LAST_UPDT_CLNT_PRGM_ID | 최종수정클라이언트프로그램ID | VARCHAR2(20) |
| LAST_UPDT_SRVR_PRGM_ID | 최종수정서버프로그램ID | VARCHAR2(50) |

아래 표에서는 이 10개 컬럼을 `(감사)`로 줄여 표기하고 위치(번호)만 적는다.

---

## 1. ACRCRCPCT 진료비수납 (104)

**인덱스**: PK(MDRP_NO, MCRC_YMD, MCRC_SNO) / I01(PTNO, MCRC_YMD, MCRC_RNO, MDDR_ID) / I02(CODV_CD, CNCL_DT, PTNO) / I04(MCRC_YMD, RPNT_ID, …) 〔한계〕 I04 이후 컬럼은 캡처에서 잘림

| No | 컬럼 | 컬럼명 | 타입 | NN |
|---|---|---|---|---|
| 1 | MDRP_NO | 진료접수번호 | NUMBER | ● |
| 2 | MCRC_YMD | 진료비수납일자 | DATE | ● |
| 3 | MCRC_SNO | 진료비수납일련번호 | NUMBER | ● |
| 4 | PTNO | 환자번호 | VARCHAR2(8) | ● |
| 5 | CODV_CD | 내원구분코드 | VARCHAR2(1) | ● |
| 6 | MDCR_YMD | 진료일자 | DATE | ● |
| 7 | MCDP_CD | 진료과코드 | VARCHAR2(6) | ● |
| 8 | MDDR_ID | 진료의사ID | VARCHAR2(10) | |
| 9 | ISTY_STRT_YMD | 보험유형시작일자 | DATE | ● |
| 10 | ISTY_FNSH_YMD | 보험유형종료일자 | DATE | ● |
| 11 | RCDV_CD | 수납구분코드 | VARCHAR2(1) | |
| 12 | MCRC_RNO | 진료비수납회차 | NUMBER | ● |
| 13 | ISTY_CD | 보험유형코드 | VARCHAR2(2) | |
| 14 | ISTY_ASST_CD | 보험유형보조코드 | VARCHAR2(2) | |
| 15 | RCST_CD | 수납상태코드 | VARCHAR2(1) | |
| 16 | FVDV_CD | 초재진구분코드 | VARCHAR2(1) | |
| 17 | UNCL_RESN_CD | 미수사유코드 | VARCHAR2(2) | |
| 18 | ADMS_OTDV_CD | 입원외래구분코드 | VARCHAR2(1) | |
| 19 | RCPT_NO | 영수증번호 | VARCHAR2(15) | |
| 20 | MDTN_NO | 투약번호 | NUMBER | |
| 21 | CLCL_WODV_CD | 계산작업구분코드 | VARCHAR2(1) | |
| 22 | CNVR_YN | 컨버전여부 | VARCHAR2(1) | |
| 23 | ONBR_DVSN_CD | 본인부담구분코드 | VARCHAR2(4) | |
| 24 | MCCR_NO | 진료확인번호 | VARCHAR2(23) | |
| 25 | ONBR_RT_BADV_CD | 본인부담율기준구분코드 | VARCHAR2(1) | |
| 26 | SCLW_QLDV_CD | 차상위자격구분코드 | VARCHAR2(1) | |
| 27 | RPNT_ID | 수납자ID | VARCHAR2(10) | |
| 28 | TAIN_PTNT_BRDN_RESN_CTN | 자보환자부담사유내용 | VARCHAR2(200) | |
| 29 | CDRC_AMT | 카드수납금액 | NUMBER | ● |
| 30 | CARD_APCN_DT | 카드승인취소일시 | DATE | |
| 31 | DDC_RCPC_AMT | DDC수납금액 | NUMBER | ● |
| 32 | DDC_APCN_DT | DDC승인취소일시 | DATE | |
| 33 | RCPC_AMT | 수납금액 | NUMBER | ● |
| 34 | CAPY_CNCL_DT | 현금결제취소일시 | DATE | |
| 35 | TOMC_AMT | 총진료비금액 | NUMBER | ● |
| 36 | FXAM_MDCR_DFRN_AMT | 정액진료차이금액 | NUMBER | ● |
| 37 | TOTL_NNPY_AMT | 총비급여금액 | NUMBER | ● |
| 38 | SLMC_AMT | 선택진료비금액 | NUMBER | ● |
| 39 | CNPL_BRDN_AMT | 계약처부담금액 | NUMBER | ● |
| 40 | ONBR_AMT | 본인부담금액 | NUMBER | ● |
| 41 | BLDT_RDEX_AMT | 헌혈감면금액 | NUMBER | ● |
| 42 | RDEX_AMT | 감면금액 | NUMBER | ● |
| 43 | MIDL_AMT | 중간금액 | NUMBER | ● |
| 44 | PRRC_AMT | 기수납금액 | NUMBER | ● |
| 45 | PYAN_APLC_AMT | 대불신청금액 | NUMBER | ● |
| 46 | BLAN_AMT | 잔전금액 | NUMBER | ● |
| 47 | UNCL_AMT | 미수금액 | NUMBER | ● |
| 48 | UNCL_DEPS_AMT | 미수입금금액 | NUMBER | ● |
| 49 | DBFU_AMT | 장애인기금금액 | NUMBER | ● |
| 50 | ULRG_EXCS_AMT | 상한제초과금액 | NUMBER | ● |
| 51 | INHS_DRUG_AMT | 원내약금액 | NUMBER | ● |
| 52 | HLTH_LIFE_KEEP_EXPN_AMT | 건강생활유지비용금액 | NUMBER | ● |
| 53 | CT_AMT | CT금액 | NUMBER | ● |
| 54 | SUPR_AMT | 후원금액 | NUMBER | ● |
| 55 | PRNL_MCCS_SBTR_AMT | 산전진료비차감금액 | NUMBER | ● |
| 56 | TXTN_AMT | 과세금액 | NUMBER | ● |
| 57 | INLA_DBPR_MDTE_MTCS_AMT | 장루탈루장애인치료재료대금액 | NUMBER | ● |
| 58 | RROB_DISS_SPRT_AMT | 희귀난치성질환지원금액 | NUMBER | ● |
| 59 | PVIC_AMT | 예방접종금액 | NUMBER | ● |
| 60 | TOTL_INPY_AMT | 총급여금액 | NUMBER | ● |
| 61 | INPY_ONBR_AMT | 급여본인부담금액 | NUMBER | ● |
| 62 | INPY_MRI_AMT | 급여MRI금액 | NUMBER | ● |
| 63 | INPY_BSIS_PYML_AMT | 급여기본식대금액 | NUMBER | ● |
| 64 | INPY_ADDI_AMT | 급여가산식금액 | NUMBER | ● |
| 65 | INPY_PET_AMT | 급여PET금액 | NUMBER | ● |
| 66 | CLRS_PRJC_CD | 임상연구과제코드 | VARCHAR2(10) | |
| 67 | TOTL_CLNC_NNPY_AMT | 총임상비급여금액 | NUMBER | ● |
| 68 | TOTL_CLNC_DSFE | 총임상지정료 | NUMBER | ● |
| 69 | TOTL_CLRS_AMT | 총임상연구금액 | NUMBER | ● |
| 70 | DDCT_AMT | Deductable금액 | NUMBER | ● |
| 71 | CPYM_AMT | Copayment금액 | NUMBER | ● |
| 72 | CINS_AMT | Coinsurance금액 | NUMBER | ● |
| 73 | CLPR_VL | 청구키값 | VARCHAR2(18) | |
| 74 | CLAM_YMD | 청구일자 | DATE | |
| 75 | CLAM_AMT | 청구금액 | NUMBER | ● |
| 76 | SPTN_CLAM_AMT | 분리청구금액 | NUMBER | ● |
| 77 | CNCL_DT | 취소일시 | DATE | |
| 78 | CNCR_ID | 취소자ID | VARCHAR2(10) | |
| 79 | TYPE_BRDN_RT_APST_YMD | 유형부담율적용시작일자 | DATE | |
| 80 | INTG_MCRC_RNO | 통합진료비수납회차 | NUMBER | |
| 81 | RCPC_LCTN_CD | 수납위치코드 | VARCHAR2(1) | |
| 82 | NEW_MCRC_RNO | 신규진료비수납회차 | NUMBER | |
| 83 | SPCC_NNPY_AMT | 특정비급여금액 | NUMBER | ● |
| 84 | SCIN_ISTY_CD | 상병보험유형코드 | VARCHAR2(3) | |
| 85 | ULRG_BASE_YMD | 상한제기준일자 | DATE | |
| 86 | MAIN_INSR_YN | 주보험여부 | VARCHAR2(1) | |
| 87 | DRG_NO | DRG번호 | VARCHAR2(6) | |
| 88~97 | (감사) | 최초등록·최종수정 10개 | - | ● |
| 98 | INPY_LMTT_TRGT_YN | 급여제한대상여부 | VARCHAR2(1) | |
| 99 | MCRC_DT | 진료비수납일시 | DATE | |
| 100 | UNMD_RCDV_CD | 무인수납구분코드 | VARCHAR2(1) | |
| 101 | ARTF_VOCR_AMT | 인공성대금액 | NUMBER | |
| 102 | BEFR_MCRC_YMD | 이전진료비수납일자 | DATE | |
| 103 | BEFR_MCRC_SNO | 이전진료비수납일련번호 | NUMBER | |
| 104 | DSCH_UNCL_LNKN_VL | 퇴원미수연결값 | VARCHAR2(6) | |

---

## 2. ACCLMCCLT 진료비계산 (179)

**인덱스**: PK(MDRP_NO, MCCL_SNO) / I03(MDRP_NO, MCRC_YMD, MCRC_SNO, MDAC_CLSF_CD, EDI_CD) / I05(CLPR_VL) / I06(PTNO, MCRC_YMD, MCRC_RNO, CODV_CD, ISTY_ASST_CD) / I08(MCCL_YMD, MDAC_CLSF_CD, …) 〔한계〕 I08 이후와 그 밖의 인덱스는 잘림

| No | 컬럼 | 컬럼명 | 타입 | NN |
|---|---|---|---|---|
| 1 | MDRP_NO | 진료접수번호 | NUMBER | ● |
| 2 | MCCL_SNO | 진료비계산일련번호 | NUMBER | ● |
| 3 | BEFR_MCCL_SNO | 이전진료비계산일련번호 | NUMBER | |
| 4 | PTNO | 환자번호 | VARCHAR2(8) | ● |
| 5 | PTAD_CODV_CD | 원무내원구분코드 | VARCHAR2(1) | ● |
| 6 | CODV_CD | 내원구분코드 | VARCHAR2(1) | |
| 7 | MDCR_YMD | 진료일자 | DATE | |
| 8 | MCDP_CD | 진료과코드 | VARCHAR2(6) | ● |
| 9 | MDDR_ID | 진료의사ID | VARCHAR2(10) | |
| 10 | MCRC_YMD | 진료비수납일자 | DATE | |
| 11 | MCRC_SNO | 진료비수납일련번호 | NUMBER | |
| 12 | ISTY_STRT_YMD | 보험유형시작일자 | DATE | |
| 13 | MCRC_RNO | 진료비수납회차 | NUMBER | |
| 14 | RCDV_CD | 수납구분코드 | VARCHAR2(1) | |
| 15 | ISTY_CD | 보험유형코드 | VARCHAR2(2) | |
| 16 | ISTY_ASST_CD | 보험유형보조코드 | VARCHAR2(2) | |
| 17 | RPNT_ID | 수납자ID | VARCHAR2(10) | |
| 18 | FRST_MCRC_YMD | 최초진료비수납일자 | DATE | |
| 19 | RCPC_AMT | 수납금액 | NUMBER | ● |
| 20 | NTM | 횟수 | NUMBER | ● |
| 21 | CQY | 수량 | NUMBER | ● |
| 22 | ADIT_CQY | 가산수량 | NUMBER | ● |
| 23 | DDCN | 일수 | NUMBER | ● |
| 24 | AGDV_CD | 연령구분코드 | VARCHAR2(1) | |
| 25 | DADV_CD | 주야구분코드 | VARCHAR2(1) | |
| 26 | FVDV_CD | 초재진구분코드 | VARCHAR2(1) | |
| 27 | CNPL_CD | 계약처코드 | VARCHAR2(10) | |
| 28 | RDEX_CD | 감면코드 | VARCHAR2(5) | |
| 29 | ADMS_OTDV_CD | 입원외래구분코드 | VARCHAR2(1) | |
| 30 | ONBR_RT | 본인부담율 | NUMBER | ● |
| 31 | IHOH_ORDV_CD | 원내원외처방구분코드 | VARCHAR2(1) | |
| 32 | ISNC_OHPR_HNDV_NO | 발급원외처방전교부번호 | VARCHAR2(13) | |
| 33 | SDPF_EXCP_CD | 의약분업예외코드 | VARCHAR2(2) | |
| 34 | CLCL_WODV_CD | 계산작업구분코드 | VARCHAR2(1) | |
| 35 | DRAP_DVSN_BLRE_DVSN_CD | 약품용구분혈액출고구분코드 | VARCHAR2(1) | |
| 36 | CLRS_PRJC_CD | 임상연구과제코드 | VARCHAR2(10) | |
| 37 | DSBL_ADDV_CD | 장애가산구분코드 | VARCHAR2(2) | |
| 38 | HSLC_DVSN_CD | 병원위치구분코드 | VARCHAR2(1) | |
| 39 | MCCN_CD | 진료센터코드 | VARCHAR2(6) | |
| 40 | MCCR_NO | 진료확인번호 | VARCHAR2(23) | |
| 41 | MDTN_LCDV_CD | 투약위치구분코드 | VARCHAR2(1) | |
| 42 | ONBR_RT_BADV_CD | 본인부담율기준구분코드 | VARCHAR2(1) | |
| 43 | SCLW_QLDV_CD | 차상위자격구분코드 | VARCHAR2(1) | |
| 44 | MCDP_ADDV_CD | 진료과가산구분코드 | VARCHAR2(2) | |
| 45 | ONBR_DVSN_CD | 본인부담구분코드 | VARCHAR2(4) | |
| 46 | CNCL_DT | 취소일시 | DATE | |
| 47 | TAIN_PTNT_BRDN_RESN_CTN | 자보환자부담사유내용 | VARCHAR2(200) | |
| 48 | PTPY_YN | 환자납부여부 | VARCHAR2(1) | |
| 49 | PTPY_INPT_YMD | 환자납부입력일자 | DATE | |
| 50 | SCRG_INPY_APDV_CD | 선별급여적용구분코드 | VARCHAR2(1) | |
| 51 | PRTB_YN | 포터블여부 | VARCHAR2(1) | |
| 52 | OSLF_TRNF_INJC_YN | 자가수혈주사여부 | VARCHAR2(1) | |
| 53 | AHIM_YN | 선실시여부 | VARCHAR2(1) | |
| 54 | CNVR_YN | 컨버전여부 | VARCHAR2(1) | |
| 55 | INHS_DRUG_YN | 원내약여부 | VARCHAR2(1) | |
| 56 | CHLD_PVIC_REGN_YN | 소아예방접종지역여부 | VARCHAR2(1) | |
| 57 | HSPT_ADIT_AMT | 병원가산금액 | NUMBER | ● |
| 58 | SLMC_AMT | 선택진료비금액 | NUMBER | ● |
| 59 | SMC_SHAR_AMT | EMR배분금액 | NUMBER | ● |
| 60 | TXTN_AMT | 과세금액 | NUMBER | ● |
| 61 | ONBR_AMT | 본인부담금액 | NUMBER | ● |
| 62 | CNPL_BRDN_AMT | 계약처부담금액 | NUMBER | ● |
| 63 | RDEX_AMT | 감면금액 | NUMBER | ● |
| 64 | SLM_APLY_UNPR_AMT | SLM적용단가금액 | NUMBER | ● |
| 65 | SLM_SHAR_AMT | SLM배분금액 | NUMBER | ● |
| 66 | ORTA_NM | 처방테이블명 | VARCHAR2(50) | |
| 67 | ORPR_VL | 처방키값 | VARCHAR2(100) | |
| 68 | ORDR_YMD | 처방일자 | DATE | |
| 69 | ORDR_SNO | 처방일련번호 | NUMBER | ● |
| 70 | ORDR_CD | 처방코드 | VARCHAR2(10) | |
| 71 | ODDR_ID | 처방의사ID | VARCHAR2(10) | |
| 72 | EXCF_CD | 검사분류코드 | VARCHAR2(10) | |
| 73 | ORGL_ORDR_CD | 원처방코드 | VARCHAR2(10) | |
| 74 | IMPL_DT | 실시일시 | DATE | |
| 75 | OROC_CD_OLD | 처방발생원코드 | VARCHAR2(2) | |
| 76 | SPCM_CD_CTN | 검체코드내용 | VARCHAR2(50) | |
| 77 | RDTN_PHSI_CD | 방사선촬영부위코드 | VARCHAR2(4) | |
| 78 | OPDV_CD | 수술구분코드 | VARCHAR2(1) | |
| 79 | ANST_MI | 마취시간분 | NUMBER | ● |
| 80 | HGRS_ANST_DVSN_CD | 고위험마취구분코드 | VARCHAR2(1) | |
| 81 | CLPR_VL | 청구키값 | VARCHAR2(18) | |
| 82 | CLOR_SNO | 청구처방일련번호 | NUMBER | |
| 83 | CLAM_YMD | 청구일자 | DATE | |
| 84 | CLDC_CRTN_DT | 청구서생성일시 | DATE | |
| 85 | CLAM_YN | 청구여부 | VARCHAR2(1) | |
| 86 | CLAM_AMT | 청구금액 | NUMBER | ● |
| 87 | MDFE_CD | 수가코드 | VARCHAR2(10) | |
| 88 | MDFE_APLY_YMD | 수가적용일자 | DATE | |
| 89 | IPDV_CD | 급여구분코드 | VARCHAR2(1) | |
| 90 | ORDR_IPDV_CD | 처방급여구분코드 | VARCHAR2(1) | |
| 91 | PTAD_IPDV_CD | 원무급여구분코드 | VARCHAR2(1) | |
| 92 | MTER_TCDV_CD | 재료기술구분코드 | VARCHAR2(1) | |
| 93 | MDFE_APDV_CD | 수가적용구분코드 | VARCHAR2(1) | |
| 94 | MFLC_CD | 수가대분류코드 | VARCHAR2(2) | |
| 95 | MDMD_CD | 수가중분류코드 | VARCHAR2(2) | |
| 96 | MFDV_CD | 수가구분코드 | VARCHAR2(1) | |
| 97 | MDGR_SNO | 수가그룹일련번호 | NUMBER | |
| 98 | STST_MDCF_CD | 통계수가분류코드 | VARCHAR2(4) | |
| 99 | MDAC_CLSF_CD | 수가누적분류코드 | VARCHAR2(4) | |
| 100 | UNPR_AMT | 단가금액 | NUMBER | ● |
| 101 | PRSC_UNPR_AMT | 점당단가금액 | NUMBER | ● |
| 102 | RLTV_SCR_APLY_YN | 상대점수적용여부 | VARCHAR2(1) | |
| 103 | RLTV_VLUE_SCR | 상대가치점수 | NUMBER | ● |
| 104 | LMRG_CD | 제한규정코드 | VARCHAR2(3) | |
| 105 | FXFX_DVSN_CD | 정률정액구분코드 | VARCHAR2(1) | |
| 106 | UPLT_RWTT_CTN | 상좌치열내용 | VARCHAR2(8) | |
| 107 | UPRG_RWTT_CTN | 상우치열내용 | VARCHAR2(8) | |
| 108 | LWLF_RWTT_CTN | 하좌치열내용 | VARCHAR2(50) | |
| 109 | LWRG_RWTT_CTN | 하우치열내용 | VARCHAR2(8) | |
| 110 | ABC_ENFR_YMD | ABC시행일자 | DATE | |
| 111 | ABC_MCDP_CD | ABC진료과코드 | VARCHAR2(6) | |
| 112 | ABC_EFDP_CD | ABC시행부서코드 | VARCHAR2(6) | |
| 113 | ABC_ODDR_ID | ABC처방의사ID | VARCHAR2(10) | |
| 114 | ABC_ENDR_ID | ABC시행의사ID | VARCHAR2(10) | |
| 115 | ABC_CECK_CD | ABC체크코드 | VARCHAR2(1) | |
| 116 | ABC_MCCN_CD | ABC진료센터코드 | VARCHAR2(6) | |
| 117 | CPDR_ID | 협진의사ID | VARCHAR2(10) | |
| 118 | CMTX_MCDP_CD | 협진진료과코드 | VARCHAR2(6) | |
| 119 | SMDR_ID | 선택의사ID | VARCHAR2(10) | |
| 120 | SMDV_CD | 선택진료구분코드 | VARCHAR2(2) | |
| 121 | SMCR_OPRT_ANST_CPDR_ID | 선택진료수술마취협진의사ID | VARCHAR2(10) | |
| 122 | SMDP_CLSF_CD | 선택진료지원과분류코드 | VARCHAR2(6) | |
| 123 | SMDP_CLSF_DETL_CD | 선택진료지원과분류상세코드 | VARCHAR2(6) | |
| 124 | TYPE_BRDN_RT_APST_YMD | 유형부담율적용시작일자 | DATE | |
| 125 | INTG_MCRC_RNO | 통합진료비수납회차 | NUMBER | |
| 126 | NEW_MCRC_RNO | 신규진료비수납회차 | NUMBER | |
| 127 | RCST_CD | 수납상태코드 | VARCHAR2(1) | |
| 128 | ENDR_ID | 시행의사ID | VARCHAR2(10) | |
| 129 | PRPD_ADMS_DT | 산모입원일시 | DATE | |
| 130 | MCCL_YMD | 진료비계산일자 | DATE | |
| 131 | PRPD_PTNO | 산모환자번호 | VARCHAR2(8) | |
| 132 | WARD_CD | 병동코드 | VARCHAR2(6) | |
| 133 | PTRM_NO | 병실번호 | VARCHAR2(4) | |
| 134 | CHCK_UPRE_CD | 심사수정사유코드 | VARCHAR2(2) | |
| 135 | ADJS_RMRK_CTN | 조정비고내용 | VARCHAR2(4000) | |
| 136 | MEMO_BRKD_CRTN_YN | 메모내역생성여부 | VARCHAR2(1) | ● |
| 137 | SCRG_CHTR_YN | 선별심사대상여부 | VARCHAR2(1) | |
| 138 | RDTN_RPTN_DT | 방사선접수일시 | DATE | |
| 139 | RDTN_FEEL_YN | 방사선체감여부 | VARCHAR2(1) | |
| 140 | OPRT_YMD | 수술일자 | DATE | |
| 141 | OPRT_SNO | 수술일련번호 | NUMBER | |
| 142 | CLAM_USGE_STRT_DT | 청구용도시작일시 | DATE | |
| 143 | CLAM_USGE_FNSH_DT | 청구용도종료일시 | DATE | |
| 144 | EDID_CD | EDI구분코드 | VARCHAR2(3) | |
| 145 | EDI_CD | EDI코드 | VARCHAR2(10) | |
| 146 | EDI_CD_RMRK_CTN | EDI코드비고내용 | VARCHAR2(1750) | |
| 147 | ASSN_CD1 | 산정코드1 | VARCHAR2(1) | |
| 148 | ASSN_CD2 | 산정코드2 | VARCHAR2(1) | |
| 149 | ASSN_CD3 | 산정코드3 | VARCHAR2(1) | |
| 150 | DRG_IPDV_CD | DRG급여구분코드 | VARCHAR2(1) | |
| 151 | DRG_NO | DRG번호 | VARCHAR2(6) | |
| 152 | PAST_MCCL_SNO | 과거진료비계산일련번호 | NUMBER | |
| 153 | BEFR_PAST_MCCL_SNO | 이전과거진료비계산일련번호 | NUMBER | |
| 154~163 | (감사) | 최초등록·최종수정 10개 | - | ● |
| 164 | DRG_INPY_ADTN_ASSN_CD | DRG급여추가산정코드 | VARCHAR2(2) | |
| 165 | OROC_DPRT_CD | 처방발생부서코드 | VARCHAR2(6) | |
| 166 | HGRS_PTRT_YN | 고위험분만여부 | VARCHAR2(1) | |
| 167 | BEFR_CQY | 이전수량 | NUMBER | ● |
| 168 | BEFR_ADIT_CQY | 이전가산수량 | NUMBER | ● |
| 169 | BEFR_HSPT_ADIT_AMT | 이전병원가산금액 | NUMBER | ● |
| 170 | BEFR_NTM | 이전횟수 | NUMBER | ● |
| 171 | BEFR_ONBR_AMT | 이전본인부담금액 | NUMBER | ● |
| 172 | BEFR_RCPC_AMT | 이전수납금액 | NUMBER | ● |
| 173 | NINL_DVSN_CD | 신포괄구분코드 | VARCHAR2(2) | |
| 174 | OTRS_HSPT_MDCR_SNO | 타병원진료일련번호 | NUMBER | |
| 175 | NINL_UNPR_AMT | 신포괄단가금액 | NUMBER | |
| 176 | NINL_RCPC_AMT | 신포괄수납금액 | NUMBER | |
| 177 | NINL_HSPT_ADIT_AMT | 신포괄병원가산금액 | NUMBER | |
| 178 | NINL_ONBR_AMT | 신포괄본인부담금액 | NUMBER | |
| 179 | NINL_CLAM_AMT | 신포괄청구금액 | NUMBER | |

---

## 3. ACCLPAORT 원무처방 (72)

**인덱스**: PK(PTNO, INPT_YMD, PTAD_ORDR_SNO) / I01(MDRP_NO) / I02(PTAD_MDRP_NO) / I03(ORDR_YMD, …) / 그 밖 1개(RCST_CD 계열로 보임) 〔한계〕 I03 이후는 잘림

| No | 컬럼 | 컬럼명 | 타입 | NN |
|---|---|---|---|---|
| 1 | PTNO | 환자번호 | VARCHAR2(8) | ● |
| 2 | INPT_YMD | 입력일자 | DATE | ● |
| 3 | PTAD_ORDR_SNO | 원무처방일련번호 | NUMBER | ● |
| 4 | MDRP_NO | 진료접수번호 | NUMBER | |
| 5 | PTAD_MDRP_NO | 원무진료접수번호 | NUMBER | |
| 6 | CODV_CD | 내원구분코드 | VARCHAR2(1) | |
| 7 | MDCR_YMD | 진료일자 | DATE | |
| 8 | PTAD_CODV_CD | 원무내원구분코드 | VARCHAR2(1) | |
| 9 | PTAD_CLBA_YMD | 원무계산기준일자 | DATE | ● |
| 10 | MCDP_CD | 진료과코드 | VARCHAR2(6) | |
| 11 | CHDR_ID | 지정의사ID | VARCHAR2(10) | |
| 12 | ORDR_YMD | 처방일자 | DATE | ● |
| 13 | IMPL_YMD | 실시일자 | DATE | |
| 14 | RCST_CD | 수납상태코드 | VARCHAR2(1) | |
| 15 | ISTY_CD | 보험유형코드 | VARCHAR2(2) | |
| 16 | ISTY_ASST_CD | 보험유형보조코드 | VARCHAR2(2) | |
| 17 | ORDR_SNO | 처방일련번호 | NUMBER | ● |
| 18 | ODKI_CD | 처방종류코드 | VARCHAR2(1) | |
| 19 | MDFE_CD | 수가코드 | VARCHAR2(10) | |
| 20 | IPDV_CD | 급여구분코드 | VARCHAR2(1) | |
| 21 | CQY | 수량 | NUMBER | ● |
| 22 | NTM | 횟수 | NUMBER | ● |
| 23 | DDCN | 일수 | NUMBER | ● |
| 24 | ISTP_ADMN_VLM | 동위원소투여용량 | NUMBER | ● |
| 25 | DADV_CD | 주야구분코드 | VARCHAR2(1) | |
| 26 | AIRC_YN | 선실시재계산여부 | VARCHAR2(1) | |
| 27 | PTPT_CD | 환자가야할장소코드 | VARCHAR2(6) | |
| 28 | EXMN_WNTD_DT | 검사희망일시 | DATE | |
| 29 | SPCM_CD | 검체코드 | VARCHAR2(3) | |
| 30 | ANST_MI | 마취시간분 | NUMBER | ● |
| 31 | OPRT_ADIT_RT | 수술가산율 | NUMBER | ● |
| 32 | ODDR_ID | 처방의사ID | VARCHAR2(10) | |
| 33 | ENDR_ID | 시행의사ID | VARCHAR2(10) | |
| 34 | SMCR_YN | 선택진료여부 | VARCHAR2(1) | |
| 35 | SMDR_ID | 선택의사ID | VARCHAR2(10) | |
| 36 | DRBN_NO | 약목음번호(화면 표기 그대로) | NUMBER | ● |
| 37 | MDTN_NO | 투약번호 | NUMBER | ● |
| 38 | IHOH_ORDV_CD | 원내원외처방구분코드 | VARCHAR2(1) | |
| 39 | RTRN_CQY | 반납수량 | NUMBER | ● |
| 40 | RTRN_NTM | 반납횟수 | NUMBER | ● |
| 41 | RTRN_DDCN | 반납일수 | NUMBER | ● |
| 42 | RTRN_STTS_CD | 반납상태코드 | VARCHAR2(1) | |
| 43 | RTRN_RQST_DT | 반납요청일시 | DATE | |
| 44 | RTRN_RQPR_ID | 반납요청자ID | VARCHAR2(10) | |
| 45 | OROC_CD_OLD | 처방발생원코드 | VARCHAR2(2) | |
| 46 | CNPL_CD | 계약처코드 | VARCHAR2(10) | |
| 47 | CLAM_YMD | 청구일자 | DATE | |
| 48 | VIA_ADMS_RCST_CD | 경유입원수납상태코드 | VARCHAR2(1) | |
| 49 | CLRS_PRJC_CD | 임상연구과제코드 | VARCHAR2(10) | |
| 50 | HSLC_DVSN_CD | 병원위치구분코드 | VARCHAR2(1) | ● |
| 51 | MCCN_CD | 진료센터코드 | VARCHAR2(6) | ● |
| 52 | ABC_ENFR_YMD | ABC시행일자 | DATE | |
| 53 | ABC_MCDP_CD | ABC진료과코드 | VARCHAR2(6) | |
| 54 | ABC_EFDP_CD | ABC시행부서코드 | VARCHAR2(6) | |
| 55 | ABC_ODDR_ID | ABC처방의사ID | VARCHAR2(10) | |
| 56 | ABC_ENDR_ID | ABC시행의사ID | VARCHAR2(10) | |
| 57 | ORPR_VL | 처방키값 | VARCHAR2(100) | |
| 58 | ORTA_NM | 처방테이블명 | VARCHAR2(50) | |
| 59 | CNCL_DT | 취소일시 | DATE | |
| 60~69 | (감사) | 최초등록·최종수정 10개 | - | ● |
| 70 | MDFE_APLY_YMD | 수가적용일자 | DATE | |
| 71 | RDEX_CD | 감면코드 | VARCHAR2(5) | |
| 72 | OROC_DPRT_CD | 처방발생부서코드 | VARCHAR2(6) | |

---

## 4. ACVNCDAPT VAN카드승인 (70)

**인덱스**: PK(WORK_YMD, WORK_SNO) / I01(WORK_YMD, …) 〔한계〕 I01 이후 컬럼은 잘림

| No | 컬럼 | 컬럼명 | 타입 | NN |
|---|---|---|---|---|
| 1 | WORK_YMD | 작업일자 | DATE | ● |
| 2 | WORK_SNO | 작업일련번호 | NUMBER | ● |
| 3 | APRV_YMD | 승인일자 | DATE | |
| 4 | APRV_HMS | 승인시분초 | VARCHAR2(6) | |
| 5 | MDRP_NO | 진료접수번호 | NUMBER | |
| 6 | MCRC_YMD | 진료비수납일자 | DATE | |
| 7 | MCRC_RNO | 진료비수납회차 | NUMBER | |
| 8 | UCOC_YMD | 미수발생일자 | DATE | |
| 9 | UCOC_SNO | 미수발생일련번호 | NUMBER | |
| 10 | UNCL_DEPS_SNO | 미수입금일련번호 | NUMBER | |
| 11 | PTNO | 환자번호 | VARCHAR2(8) | |
| 12 | CODV_CD | 내원구분코드 | VARCHAR2(1) | |
| 13 | MCDP_CD | 진료과코드 | VARCHAR2(6) | |
| 14 | MDCR_YMD | 진료일자 | DATE | |
| 15 | DEPS_DVSN_CD | 입금구분코드 | VARCHAR2(1) | |
| 16 | CARD_APCN_DVSN_CD | 카드승인취소구분코드 | VARCHAR2(2) | |
| 17 | APVR_ID | 승인자ID | VARCHAR2(10) | |
| 18 | CARD_RCGN_MTHD_CD | 카드인식방법코드 | VARCHAR2(1) | |
| 19 | CDAP_LNGT_VL | 카드승인길이값 | NUMBER | |
| 20 | CRCR_FLTX_CTN | 신용카드전문내용 | VARCHAR2(40) | |
| 21 | INTM_MNTS_CNT | 할부개월수 | NUMBER | |
| 22 | PYMN_AMT | 결제금액 | NUMBER | |
| 23 | TOTL_PYMN_AMT | 총결제금액 | NUMBER | |
| 24 | CDAP_YMD | 카드승인일자 | DATE | |
| 25 | CDAP_HMS | 카드승인시분초 | VARCHAR2(6) | |
| 26 | CDAP_NO | 카드승인번호 | VARCHAR2(16) | |
| 27 | BANK_ID | 은행ID | VARCHAR2(4) | |
| 28 | BANK_SNO | 은행일련번호 | NUMBER | |
| 29 | BANK_NM | 은행명 | VARCHAR2(50) | |
| 30 | CRCR_AFST_NO | 신용카드가맹점번호 | VARCHAR2(16) | |
| 31 | CCCM_NM | 신용카드사명 | VARCHAR2(50) | |
| 32 | CRCR_NM | 신용카드명 | VARCHAR2(50) | |
| 33 | BEAP_YMD | 이전승인일자 | DATE | |
| 34 | BEAP_HMS | 이전승인시분초 | VARCHAR2(6) | |
| 35 | BEAP_NO | 이전승인번호 | VARCHAR2(16) | |
| 36 | CRCR_CLAM_STTS_CD | 신용카드청구상태코드 | VARCHAR2(1) | ● |
| 37 | EDI_CLAM_YMD | EDI청구일자 | DATE | |
| 38 | PYMN_RSPN_CD | 결제응답코드 | VARCHAR2(4) | |
| 39 | CSTM_INFM_CTN | 고객정보내용 | VARCHAR2(150) | |
| 40 | CRCR_NO | 신용카드번호 | VARCHAR2(100) | |
| 41 | VANT_CMPN_DVSN_CD | VAN회사구분코드 | VARCHAR2(10) | |
| 42 | MAND_UNMD_RCDV_CD | 유인무인수납구분코드 | VARCHAR2(3) | |
| 43 | CRCR_VALD_YM | 신용카드유효년월 | VARCHAR2(6) | |
| 44 | CARD_INTR_CTN | 카드판독내용 | VARCHAR2(20) | |
| 45 | RCBR_MIDL_AMT_SBSN_YMD | 수납내역중간금액대체일자 | DATE | |
| 46 | CARD_APCN_YMD | 카드승인취소일자 | DATE | |
| 47 | ESIM_BD | 전자서명이미지자료 | BLOB | |
| 48 | ELSG_YN | 전자서명여부 | VARCHAR2(1) | |
| 49 | RPNT_ID | 수납자ID | VARCHAR2(10) | |
| 50 | CNFR_YN | 확인여부 | VARCHAR2(1) | |
| 51 | CNFR_RQPR_ID | 확인요청자ID | VARCHAR2(10) | |
| 52 | CNFR_DT | 확인일시 | DATE | |
| 53 | TREQ_NO | 단말기번호 | VARCHAR2(10) | |
| 54 | SGPD_DVSN_CD | 서명패드구분코드 | VARCHAR2(1) | |
| 55 | OPCA_YN | 오픈카드여부 | VARCHAR2(1) | |
| 56 | PUCH_CNCL_EXCL_YN | 매입취소제외여부 | VARCHAR2(1) | ● |
| 57~66 | (감사) | 최초등록·최종수정 10개 | - | ● |
| 67 | VANT_PBLC_INST_IDNT_CD | VAN발행기관식별코드 | VARCHAR2(3) | |
| 68 | VANT_CARD_TRACK_DATA_VL3 | VAN카드TRACK데이터값3 | VARCHAR2(40) | |
| 69 | VANT_CARD_LNKD_ECTN_INFM_CTN | VAN카드연계암호화정보내용 | VARCHAR2(132) | |
| 70 | VANT_MNGM_CRCR_TYPE_CD | VAN관리신용카드유형코드 | VARCHAR2(10) | |

> ※ 카드번호·고객정보 등 민감 컬럼(`CRCR_NO`, `CSTM_INFM_CTN`, `VANT_CARD_TRACK_DATA_VL3` 등)은 차액 점검 쿼리에서 조회하지 않는다.

---

## 5. ACVNCSAPT VAN현금승인 (66)

**인덱스**: PK(WORK_YMD, WORK_SNO) / I01(WORK_YMD, PTNO)

| No | 컬럼 | 컬럼명 | 타입 | NN |
|---|---|---|---|---|
| 1 | WORK_YMD | 작업일자 | DATE | ● |
| 2 | WORK_SNO | 작업일련번호 | NUMBER | ● |
| 3 | APRV_YMD | 승인일자 | DATE | |
| 4 | APRV_HMS | 승인시분초 | VARCHAR2(6) | |
| 5 | MDRP_NO | 진료접수번호 | NUMBER | |
| 6 | MCRC_YMD | 진료비수납일자 | DATE | |
| 7 | UCOC_YMD | 미수발생일자 | DATE | |
| 8 | UCOC_SNO | 미수발생일련번호 | NUMBER | |
| 9 | UNCL_DEPS_SNO | 미수입금일련번호 | NUMBER | |
| 10 | MCRC_RNO | 진료비수납회차 | NUMBER | |
| 11 | PTNO | 환자번호 | VARCHAR2(8) | |
| 12 | CODV_CD | 내원구분코드 | VARCHAR2(1) | |
| 13 | MCDP_CD | 진료과코드 | VARCHAR2(6) | |
| 14 | MDCR_YMD | 진료일자 | DATE | |
| 15 | DEPS_DVSN_CD | 입금구분코드 | VARCHAR2(1) | |
| 16 | APCN_DVSN_CD | 승인취소구분코드 | VARCHAR2(2) | |
| 17 | APVR_ID | 승인자ID | VARCHAR2(10) | |
| 18 | CARD_RCGN_MTHD_CD | 카드인식방법코드 | VARCHAR2(1) | |
| 19 | CSAP_FLTX_LNGT_VL | 현금승인전문길이값 | NUMBER | |
| 20 | CRCR_FLTX_CTN | 신용카드전문내용 | VARCHAR2(40) | |
| 21 | BSNM_INDV_DVSN_CD | 사업자개인구분코드 | VARCHAR2(1) | |
| 22 | PYMN_AMT | 결제금액 | NUMBER | |
| 23 | TOTL_PYMN_AMT | 총결제금액 | NUMBER | |
| 24 | CSAP_YMD | 현금승인일자 | DATE | |
| 25 | CSAP_HMS | 현금승인시분초 | VARCHAR2(6) | |
| 26 | CSAP_NO | 현금승인번호 | VARCHAR2(16) | |
| 27 | BANK_ID | 은행ID | VARCHAR2(4) | |
| 28 | BANK_SNO | 은행일련번호 | NUMBER | |
| 29 | BANK_NM | 은행명 | VARCHAR2(50) | |
| 30 | CRCR_AFST_NO | 신용카드가맹점번호 | VARCHAR2(16) | |
| 31 | CCCM_NM | 신용카드사명 | VARCHAR2(50) | |
| 32 | CASH_CARD_NM | 현금카드명 | VARCHAR2(32) | |
| 33 | BEAP_YMD | 이전승인일자 | DATE | |
| 34 | BEAP_HMS | 이전승인시분초 | VARCHAR2(6) | |
| 35 | BEAP_NO | 이전승인번호 | VARCHAR2(16) | |
| 36 | CRCR_CLAM_STTS_CD | 신용카드청구상태코드 | VARCHAR2(1) | |
| 37 | EDI_CLAM_YMD | EDI청구일자 | DATE | |
| 38 | PYMN_RSPN_CD | 결제응답코드 | VARCHAR2(4) | |
| 39 | CSTM_INFM_CTN | 고객정보내용 | VARCHAR2(150) | |
| 40 | CASH_CARD_NO | 현금카드번호 | VARCHAR2(100) | |
| 41 | VANT_CMPN_DVSN_CD | VAN회사구분코드 | VARCHAR2(10) | |
| 42 | SCTN_NO | 섹션번호 | VARCHAR2(3) | |
| 43 | CRCR_VALD_YM | 신용카드유효년월 | VARCHAR2(6) | |
| 44 | CARD_INTR_CTN | 카드판독내용 | VARCHAR2(20) | |
| 45 | CASH_APCN_YMD | 현금승인취소일자 | DATE | |
| 46 | RPNT_ID | 수납자ID | VARCHAR2(10) | |
| 47 | CAPY_NO_DVSN_CD | 현금결제번호구분코드 | VARCHAR2(1) | |
| 48 | CNFR_YN | 확인여부 | VARCHAR2(1) | |
| 49 | CNFR_RQPR_ID | 확인요청자ID | VARCHAR2(10) | |
| 50 | CNFR_DT | 확인일시 | DATE | |
| 51 | CASH_APCN_DVSN_CD | 현금승인취소구분코드 | VARCHAR2(1) | |
| 52 | ORGL_APRV_NO | 원승인번호 | VARCHAR2(16) | |
| 53 | CAPY_NO_ELPA_INPT_YN | 현금결제번호전자패드입력여부 | VARCHAR2(1) | |
| 54 | TREQ_NO | 단말기번호 | VARCHAR2(10) | |
| 55 | CASH_APCN_RESN_CD | 현금승인취소사유코드 | VARCHAR2(1) | |
| 56 | USE_YN | 사용여부 | VARCHAR2(1) | |
| 57~66 | (감사) | 최초등록·최종수정 10개 | - | ● |

---

## 6. ACETCLSGT 수익수입마감로그 (18)

**인덱스**: 〔한계〕 업로드된 캡처에 인덱스 영역이 포함되지 않아 PK·인덱스 구성은 확인되지 않음

| No | 컬럼 | 컬럼명 | 타입 | NN |
|---|---|---|---|---|
| 1 | CLSN_STRT_DT | 마감시작일시 | DATE | ● |
| 2 | CLSN_FNSH_DT | 마감종료일시 | DATE | |
| 3 | CLSN_BASE_YMD | 마감기준일자 | DATE | ● |
| 4 | CLSN_CRTN_DVSN_CD | 마감생성구분코드 | VARCHAR2(3) | ● |
| 5 | CLSN_CRTN_RESN_CTN | 마감생성사유내용 | VARCHAR2(1000) | |
| 6 | CLOS_ID | 마감자ID | VARCHAR2(10) | ● |
| 7 | ERR_MESG_CTN | 에러메시지내용 | VARCHAR2(1000) | |
| 8 | RMRK_CTN | 비고내용 | VARCHAR2(4000) | |
| 9~18 | (감사) | 최초등록·최종수정 10개 | - | ● |

---

## 7. 엑셀 `원무수입마감점검` (2026-10-01 출력, 시트명 20261002074911)

**열**: 구분 / 상세구분 / 외래수입마감 / 응급수입마감 / 입원수입마감 / 합계 (금액은 쉼표 포함 **텍스트**)

| 구분 | 상세구분(행) |
|---|---|
| 당일진료비수입발생 | 총진료비, 보험자부담액, 본인부담상한초과금, 지원금, 본인부담액, 개인미수, 보훈미수, 보훈위탁미수, 외부수탁검사, 건강생활유지비, 산전진료비, 필수예방접종비, 헌혈미수, 보건소, 공단, 기관미수, 외부지원, 기타계약처미수, 임상연구미수, 진료비감면, 중간금대체, 기수납금, 수납잔전액, 수납금 |
| 부가가치세 | 부가가치세 |
| 당일진료비수입입금 | 입원중간금, 가퇴원금, 입원중간금/가퇴원금제외 보증금, 가정간호선수금, 보증금환불, 미수입금, 임상미수입금, 미수감면 |
| 수입합계 | 총수납금, 현금수납, CARD수납 |
| 원무수익마감점검 | 항목별 (마감)/(점검)/(차액): 본인부담액, 미수합계, 진료비감면, 중간금대체, 수납금, 보증금, 총수입, 카드수입, 현금수입 |

**2026-10-01 점검 결과 (차액 ≠ 0)**
| 항목 | 구분 | 마감 | 점검 | 차액 |
|---|---|---|---|---|
| 미수합계 | 입원 | 22,443,990 | 22,443,900 | **90** |
| 현금수입 | 합계(구분별 점검값은 0) | 33,513,950 | 33,455,050 | **58,900** |

---

## 8. 정의서에서 확인되지 않은 것

- 코드 컬럼의 코드 그룹(COMMENT 열)은 캡처에서 `ACA…`, `ACB…`, `AC0…` 등으로 잘려 **전체 코드 그룹명과 코드값 의미는 확인되지 않음**
- 인덱스는 캡처 하단이 잘려 일부 테이블은 선두 몇 개만 확인됨
- 각 테이블의 건수·데이터 값·`ACETCLSGT`의 PK는 확인되지 않음
- **마감 금액(미수 구분별) 저장 테이블, 보증금·입금 테이블**은 업로드되지 않음
