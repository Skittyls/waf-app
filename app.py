import streamlit as st
import joblib
import pandas as pd
import numpy as np
import math
from scipy.sparse import hstack

st.set_page_config(page_title="WAF Payload Inspector", page_icon="🛡️", layout="centered")

# Загрузка сохраненных файлов модели
@st.cache_resource
def load_resources():
    model = joblib.load('waf_model.pkl')
    tfidf = joblib.load('tfidf_vectorizer.pkl')
    return model, tfidf

model, tfidf = load_resources()

# Извлечение признаков для введенного текста
def extract_single_features(payload):
    length = len(payload)
    special_chars = ["'", '"', '<', '>', ';', '--', '/*', '*/', '=', '(', ')', '%', 'script', 'select', 'union']
    char_counts = [payload.lower().count(char) for char in special_chars]
    
    if not payload:
        entropy = 0
    else:
        entropy = -sum((payload.count(c)/len(payload)) * math.log2(payload.count(c)/len(payload)) for c in set(payload))
        
    features = [length] + char_counts + [entropy]
    return np.array(features).reshape(1, -1)

# Веб-интерфейс
st.title("🛡️ Web Application Firewall Inspector")
st.write("Интерактивный классификатор HTTP-запросов (SQLi / XSS / Clean)")

payload_input = st.text_area(
    "Введите HTTP Payload / Запрос для анализа:", 
    height=120,
    value="SELECT * FROM users WHERE username = 'admin' OR '1'='1';"
)

if st.button("🔍 Проверить запрос", use_container_width=True):
    if not payload_input.strip():
        st.warning("Пожалуйста, введите запрос.")
    else:
        tfidf_feat = tfidf.transform([payload_input])
        manual_feat = extract_single_features(payload_input)
        final_feat = hstack([tfidf_feat, manual_feat])
        
        prediction = model.predict(final_feat)[0]
        probabilities = model.predict_proba(final_feat)[0]
        classes = model.classes_

        st.divider()
        st.subheader("Результат анализа:")
        
        pred_str = str(prediction).lower()
        
        # Определение вердикта
        if pred_str in ['0', 'clean']:
            st.success("✅ **Статус: CLEAN** (Безопасный запрос)")
        elif pred_str in ['1', 'sqli']:
            st.error("🚨 **Статус: THREAT DETECTED — SQL Injection (SQLi)**")
        else:
            st.error("🚨 **Статус: THREAT DETECTED — Cross-Site Scripting (XSS)**")

        st.write("### Вероятности классов:")
        prob_df = pd.DataFrame({
            'Класс': [str(c) for c in classes],
            'Вероятность': probabilities
        })
        st.bar_chart(prob_df.set_index('Класс'))