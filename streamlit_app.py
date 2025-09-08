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
model = joblib.load("phishing_model.joblib")   # ← joblib 버전으로 교체
known_urls = pd.read_csv("famous_url_with_alias.csv")  # 인증된 URL 목록
dataset = pd.read_csv("dataset_phishing.csv")  # 원본 데이터셋 (분석용)
X = dataset.drop(columns=["url", "status"])

# ---------------------------
# Feature Extraction Function
# ---------------------------
def extract_features(url: str):
    """dataset_phishing.csv 기반 feature 추출 (간소화 버전)"""
    parsed = urlparse(url)
    hostname = parsed.netloc or ""
    path = parsed.path or ""

    length_url = len(url)
    length_hostname = len(hostname)

    nb_dots = url.count(".")
    nb_hyphens = url.count("-")
    nb_at = url.count("@")
    nb_qm = url.count("?")
    nb_and = url.count("&")
    nb_or = url.count("|")
    nb_eq = url.count("=")
    nb_underscore = url.count("_")
    nb_tilde = url.count("~")
    nb_percent = url.count("%")
    nb_slash = url.count("/")
    nb_star = url.count("*")
    nb_colon = url.count(":")
    nb_comma = url.count(",")
    nb_semicolumn = url.count(";")
    nb_dollar = url.count("$")
    nb_space = url.count(" ")
    nb_www = url.count("www")
    nb_com = url.count(".com")
    nb_dslash = url.count("//")

    http_in_path = 1 if "http" in path else 0
    https_token = 1 if "https" in url else 0

    ratio_digits_url = sum(c.isdigit() for c in url) / length_url if length_url > 0 else 0
    ratio_digits_host = sum(c.isdigit() for c in hostname) / length_hostname if length_hostname > 0 else 0

    punycode = 1 if "xn--" in hostname else 0
    prefix_suffix = 1 if "-" in hostname else 0
    random_domain = 0
    tld_in_path = 1 if re.search(r"\.[a-z]{2,}$", path) else 0
    tld_in_subdomain = 1 if re.search(r"\.[a-z]{2,}$", hostname.split(".")[0]) else 0
    abnormal_subdomain = 1 if hostname.count(".") > 3 else 0
    nb_subdomains = len(hostname.split(".")) - 2 if hostname else 0

    # 나머지는 기본값 처리
    dummy = np.zeros(len(X.columns) - 25)  

    features = [
        length_url, length_hostname,
        0,  # ip
        nb_dots, nb_hyphens, nb_at, nb_qm, nb_and, nb_or, nb_eq,
        nb_underscore, nb_tilde, nb_percent, nb_slash, nb_star,
        nb_colon, nb_comma, nb_semicolumn, nb_dollar, nb_space,
        nb_www, nb_com, nb_dslash,
        http_in_path, https_token,
        ratio_digits_url, ratio_digits_host,
        punycode, 0,  # port
        tld_in_path, tld_in_subdomain, abnormal_subdomain,
        nb_subdomains, prefix_suffix, random_domain
    ] + dummy.tolist()

    return np.array(features, dtype=float)

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
        sns.barplot(x=importances[indices], y=np.array(X.columns)[indices])
        plt.title("주요 Feature 중요도")
        st.pyplot(plt)

        # (2) 입력 URL 값 비교
        st.markdown("**입력 URL의 특징 값이 정상 평균과 피싱 평균 중 어디에 가까운지**")
        legit_mean = dataset[dataset["status"]=="legitimate"].drop(columns=["url","status"]).mean()
        phish_mean = dataset[dataset["status"]=="phishing"].drop(columns=["url","status"]).mean()

        explanation = []
        for i, col in enumerate(X.columns[:30]):  # 처음 30개만 비교
            val = features[i]
            if abs(val - phish_mean[col]) < abs(val - legit_mean[col]):
                explanation.append(f"🔴 {col} 값({val:.2f}) → 피싱 평균({phish_mean[col]:.2f})에 더 가까움")
            else:
                explanation.append(f"🟢 {col} 값({val:.2f}) → 정상 평균({legit_mean[col]:.2f})에 더 가까움")

        for exp in explanation[:10]:  # 상위 10개만 출력
            st.write(exp)
