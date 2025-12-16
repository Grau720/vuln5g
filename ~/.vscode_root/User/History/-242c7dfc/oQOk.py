import re
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from joblib import load, dump

"""
===========================================================
  FEATURIZER — Versión 1.1 (Corregido para MongoDB)
  Convierte una vulnerabilidad (CVE) en un vector numérico
  compatible con modelos tabulares (XGBoost, sklearn).
===========================================================
"""

class Featurizer:
    """
    Transformador responsable de convertir vulnerabilidades
    en vectores numéricos para entrenamiento e inferencia.
    """

    def __init__(self):
        self.vectorizer = None
        self.scaler = None
        self.encoder = None

        self.categorical_fields = [
            "attackVector", "attackComplexity", "privilegesRequired",
            "userInteraction", "scope", "cwe"
        ]

        self.numeric_fields = [
            "cvss_base_score",
            "confidentialityImpact",
            "integrityImpact",
            "availabilityImpact"
        ]

    def _parse_cvss_vector(self, vector_string):
        """
        Parse CVSS vector string como 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H'
        """
        result = {
            "attackVector": "UNKNOWN",
            "attackComplexity": "UNKNOWN",
            "privilegesRequired": "UNKNOWN",
            "userInteraction": "UNKNOWN",
            "scope": "UNKNOWN",
            "confidentialityImpact": 0.0,
            "integrityImpact": 0.0,
            "availabilityImpact": 0.0
        }
        
        if not vector_string:
            return result
            
        # Mapeo de valores a numéricos para impactos
        impact_map = {"N": 0.0, "L": 0.22, "H": 0.56}
        
        parts = vector_string.split('/')
        for part in parts:
            if ':' not in part:
                continue
            key, value = part.split(':', 1)
            
            if key == 'AV':
                av_map = {'N': 'NETWORK', 'A': 'ADJACENT', 'L': 'LOCAL', 'P': 'PHYSICAL'}
                result["attackVector"] = av_map.get(value, value)
            elif key == 'AC':
                ac_map = {'L': 'LOW', 'H': 'HIGH'}
                result["attackComplexity"] = ac_map.get(value, value)
            elif key == 'PR':
                pr_map = {'N': 'NONE', 'L': 'LOW', 'H': 'HIGH'}
                result["privilegesRequired"] = pr_map.get(value, value)
            elif key == 'UI':
                ui_map = {'N': 'NONE', 'R': 'REQUIRED'}
                result["userInteraction"] = ui_map.get(value, value)
            elif key == 'S':
                s_map = {'U': 'UNCHANGED', 'C': 'CHANGED'}
                result["scope"] = s_map.get(value, value)
            elif key == 'C':
                result["confidentialityImpact"] = impact_map.get(value, 0.0)
            elif key == 'I':
                result["integrityImpact"] = impact_map.get(value, 0.0)
            elif key == 'A':
                result["availabilityImpact"] = impact_map.get(value, 0.0)
        
        return result

    def extract_raw_features(self, cve: dict):
        """
        Extrae features crudas adaptado a la estructura real de MongoDB.
        """
        # Obtener datos CVSS (nota: en tu BD es 'cvssv3', no 'cvss_v3')
        cvss = cve.get("cvssv3", {})
        
        raw = {
            "cvss_base_score": cvss.get("score", 0.0),
        }
        
        # Parse CVSS vector para obtener métricas detalladas
        vector_data = self._parse_cvss_vector(cvss.get("vector", ""))
        raw.update(vector_data)

        # Extraer CWE del campo 'tipo' o generar uno por defecto
        tipo = cve.get("tipo", "")
        if tipo:
            # Normalizar tipos a CWE-like
            tipo_to_cwe = {
                "Denegación de servicio": "CWE-400",
                "Ejecución de código": "CWE-94",
                "Inyección SQL": "CWE-89",
                "XSS": "CWE-79",
                "Desbordamiento de búfer": "CWE-119"
            }
            raw["cwe"] = tipo_to_cwe.get(tipo, f"CWE-{tipo.replace(' ', '-')}")
        else:
            raw["cwe"] = "CWE-UNKNOWN"

        # Combinar descripciones técnicas y generales
        desc_tecnica = cve.get("descripcion_tecnica", "")
        desc_general = cve.get("descripcion_general", "")
        raw["text"] = f"{desc_tecnica} {desc_general}".strip()

        return raw

    def fit(self, raw_feature_list: list):
        """
        Ajusta el featurizer con datos de entrenamiento.
        """
        df = pd.DataFrame(raw_feature_list)

        # FIT TF-IDF
        self.vectorizer = TfidfVectorizer(
            max_features=500, 
            stop_words="english",
            ngram_range=(1,2),
            min_df=2  # Ignorar términos muy raros
        )
        self.vectorizer.fit(df["text"])

        # FIT OneHotEncoder
        self.encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
        self.encoder.fit(df[self.categorical_fields])

        # FIT Scaler
        self.scaler = StandardScaler()
        self.scaler.fit(df[self.numeric_fields])

        return self

    def transform(self, raw_feature_list: list):
        """
        Transforma features crudas en matriz numérica.
        """
        df = pd.DataFrame(raw_feature_list)

        # TF-IDF
        tfidf_matrix = self.vectorizer.transform(df["text"]).toarray()

        # Categóricos
        cat = self.encoder.transform(df[self.categorical_fields])

        # Numéricos
        num = self.scaler.transform(df[self.numeric_fields])

        # Concatenar
        X = np.hstack([num, cat, tfidf_matrix])

        return X

    def save(self, path: str):
        """Guarda el featurizer entrenado."""
        dump({
            "vectorizer": self.vectorizer,
            "encoder": self.encoder,
            "scaler": self.scaler
        }, path)

    @staticmethod
    def load(path: str):
        """Carga un featurizer previamente entrenado."""
        data = load(path)
        f = Featurizer()
        f.vectorizer = data["vectorizer"]
        f.encoder = data["encoder"]
        f.scaler = data["scaler"]
        return f