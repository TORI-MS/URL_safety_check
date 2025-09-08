import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

def main():
    # 1. 데이터 불러오기
    df = pd.read_csv("dataset_phishing.csv")
    X = df.drop(columns=["url", "status"])
    y = df["status"]

    # 2. 데이터 분할
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 3. 모델 학습
    model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    # 4. 모델 저장 (pkl + joblib 두 가지 버전)
    joblib.dump(model, "phishing_model.pkl")
    joblib.dump(model, "phishing_model.joblib")

    print("✅ 모델 학습 완료 및 저장됨 (phishing_model.pkl, phishing_model.joblib)")

if __name__ == "__main__":
    main()
