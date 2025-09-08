import streamlit as st
import pandas as pd
import joblib
import numpy as np
import re
from urllib.parse import urlparse
import matplotlib.pyplot as plt
import seaborn as sns

# ---------------------------
# 모델 & 데이터 로드
# ---------------------------
model = joblib.load("phishing_model.joblib")   # 현재 환경에서 학습한 모델
known_urls = pd.read_csv("famous_url_with_alias.csv")  # 인증된 URL 목록
dataset = pd.read_csv("dataset_phishing.csv")  # 분석용 데이터셋
X = dataset.drop(columns=["url", "status"])
feature_columns = X.columns.tolist()  # feature 순서

# ---------------------------
# Feature Extraction Function
# ---------------------------
def extract_features(url: str):
    parsed = urlparse(url)
    hostname = parsed.netloc or ""
    path = parsed.path or ""

    values = {}

    # 주요 feature 계산
    values["length_url"] = len(url)
    values["length_hostname"] = len(hostname)
    values["ip"] = 1 if re.match(r"\d+\.\d+\.\d+\.\d+", hostname) else 0
    values["nb_dots"] = url.count(".")
    values["nb_hyphens"] = url.count("-")
    values["nb_at"] = url.count("@")
    values["nb_qm"] = url.count("?")
    values["nb_and"] = url.count("&")
    values["nb_or"] = url.count("|")
    values["nb_eq"] = url.count("=")
    values["nb_underscore"] = url.count("_")
    values["nb_tilde"] = url.count("~")
    values["nb_percent"] = url.count("%")
    values["nb_slash"] = url.count("/")
    values["nb_star"] = url.count("*")
    values["nb_colon"] = url.count(":")
    values["nb_comma"] = url.count(",")
    values["nb_semicolumn"] = url.count(";")
    values["nb_dollar"] = url.count("$")
    values["nb_space"] = url.count(" ")
    values["nb_www"] = url.count("www")
    values["nb_com"] = url.count(".com")
    values["nb_dslash"] = url.count("//")
    values["http_in_path"] = 1 if "http" in path else 0
    values["https_token"] = 1 if "https" in url else 0
    values["ratio_digits_url"] = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0
    values["ratio_digits_host"] = sum(c.isdigit() for c in hostname) / len(hostname) if len(hostname) > 0 else 0
    values["punycode"] = 1 if "xn--" in hostname else 0
    values["port"] = 0
    values["tld_in_path"] = 1 if re.search(r"\.[a-z]{2,}$", path) else 0
    values["tld_in_subdomain"] = 1 if re.search(r"\.[a-z]{2,}$", hostname.split(".")[0]) else 0
    values["abnormal_subdomain"] = 1 if hostname.count(".") > 3 else 0
    values["nb_subdomains"] = len(hostname.split(".")) - 2 if hostname else 0
    values["prefix_suffix"] = 1 if "-" in hostname else 0
    values["random_domain"] = 0

    # 나머지 feature는 기본값(0)
    for col in feature_columns:
        if col not in values:
            values[col] = 0

    features = [values[col] for col in feature_columns]
    return np.array(features, dtype=float)

# ---------------------------
# 한국어 친화형 Feature 이름 매핑
# ---------------------------
feature_names_kr = {
    # 길이 관련
    "length_url": "URL 전체 길이",
    "length_hostname": "도메인 길이",

    # 특수문자 개수
    "nb_dots": "점(.) 개수",
    "nb_hyphens": "하이픈(-) 개수",
    "nb_at": "@ 기호 개수",
    "nb_qm": "물음표(?) 개수",
    "nb_and": "& 기호 개수",
    "nb_or": "| 기호 개수",
    "nb_eq": "= 기호 개수",
    "nb_underscore": "밑줄(_) 개수",
    "nb_tilde": "물결(~) 개수",
    "nb_percent": "% 기호 개수",
    "nb_slash": "슬래시(/) 개수",
    "nb_star": "* 기호 개수",
    "nb_colon": "콜론(:) 개수",
    "nb_comma": "쉼표(,) 개수",
    "nb_semicolumn": "세미콜론(;) 개수",
    "nb_dollar": "$ 기호 개수",
    "nb_space": "공백( ) 개수",
    "nb_www": "www 문자열 개수",
    "nb_com": ".com 문자열 개수",
    "nb_dslash": "// 문자열 개수",

    # 보안 관련
    "https_token": "HTTPS 포함 여부",
    "http_in_path": "경로에 http 포함 여부",

    # 숫자 비율
    "ratio_digits_url": "숫자 비율(전체 URL)",
    "ratio_digits_host": "숫자 비율(도메인)",

    # 도메인 관련
    "punycode": "국제도메인(Punycode) 여부",
    "nb_subdomains": "서브도메인 개수",
    "prefix_suffix": "도메인에 하이픈(-) 포함 여부",
    "abnormal_subdomain": "비정상적 서브도메인 여부",
    "random_domain": "랜덤 도메인 여부(추정)",

    # 추가로 필요하면 계속 확장 가능
}

# ---------------------------
# Streamlit UI
# ---------------------------
st.title("🔐 피싱 URL 탐지기")

user_url = st.text_input("검사할 URL을 입력하세요:")

if user_url:
    # 1. 인증된 URL 체크
    if user_url in known_urls["url"].values:
        st.success("✅ 인증된 안전한 URL입니다.")
    else:
        # 2. 특징 추출 & 예측
        features = extract_features(user_url)
        if features.shape[0] != model.n_features_in_:
            st.error(f"❌ Feature 개수 불일치: {features.shape[0]}개 vs 모델 {model.n_features_in_}개")
        else:
            pred = model.predict([features])[0]

            if pred == "phishing":
                st.error("🚨 피싱 위험 URL로 분류되었습니다!")
            else:
                st.success("✅ 안전한 URL로 분류되었습니다.")

            # ---------------------------
            # 📊 분석 및 설명
            # ---------------------------
            st.subheader("📊 분석 근거")

            # (1) Feature 중요도 (전체 모델 기준)
            st.markdown("**모델이 학습한 주요 특징 중요도**")
            importances = model.feature_importances_
            indices = np.argsort(importances)[-15:]
            plt.figure(figsize=(6,5))
            sns.barplot(x=importances[indices], y=np.array(feature_columns)[indices])
            plt.title("주요 Feature 중요도")
            st.pyplot(plt)

            # (2) 입력 URL 값 비교
            st.markdown("**입력한 URL이 정상/피싱 평균과 비교했을 때 어떤 특성을 보이는지**")
            legit_mean = dataset[dataset["status"]=="legitimate"].drop(columns=["url","status"]).mean()
            phish_mean = dataset[dataset["status"]=="phishing"].drop(columns=["url","status"]).mean()

            explanation = []
            for i, col in enumerate(feature_columns[:30]):  # 처음 30개만 비교
                val = features[i]
                col_name = feature_names_kr.get(col, col)  # 한국어 이름 있으면 변환
                if abs(val - phish_mean[col]) < abs(val - legit_mean[col]):
                    explanation.append(f"🔴 {col_name} 값({val:.2f}) → 피싱 사이트 평균({phish_mean[col]:.2f})에 더 가까움 → 피싱 의심")
                else:
                    explanation.append(f"🟢 {col_name} 값({val:.2f}) → 정상 사이트 평균({legit_mean[col]:.2f})에 더 가까움 → 정상적 특성")

            for exp in explanation[:10]:  # 상위 10개만 출력
                st.write(exp)
