# 🧠 Smart Labeling System - Documentación

Sistema inteligente de etiquetado y entrenamiento de modelos de predicción de explotabilidad para vulnerabilidades 5G.

---

## 📋 Tabla de Contenidos

1. [Introducción](#introducción)
2. [Instalación](#instalación)
3. [Arquitectura](#arquitectura)
4. [Uso Rápido](#uso-rápido)
5. [Scripts Disponibles](#scripts-disponibles)
6. [Workflow Completo](#workflow-completo)
7. [Interpretación de Resultados](#interpretación-de-resultados)
8. [FAQ](#faq)

---

## 🎯 Introducción

### Problema Original

El sistema de etiquetado heurístico simple tenía varios problemas:

- **Sesgo hacia DoS**: 29% de CVEs eran DoS, tratados igual que RCE
- **Sin clasificar**: 15% de CVEs sin tipo, ignorados por el modelo
- **Falsos positivos**: DoS con CVSS 7.5 marcados como "críticos"
- **Sin contexto 5G**: No consideraba infraestructura afectada

### Solución: Smart Labeling

Sistema de scoring multifactorial que considera:

✅ **Pesos por tipo** - RCE (1.0) > DoS (0.45)  
✅ **Infraestructura 5G** - AMF/SMF críticos (+60%)  
✅ **Keywords peligrosas** - "unauthenticated", "pre-auth" (+40%)  
✅ **Edad del CVE** - Más recientes = más peligrosos  
✅ **Thresholds dinámicos** - DoS necesita >0.70, RCE >0.50  

---

## 🔧 Instalación

### Dependencias

Añade a `requirements.txt`:

```txt
python-dateutil>=2.8.2
```

Instala:

```bash
pip install -r requirements.txt
```

### Archivos Nuevos

Copia estos archivos a `services/ia/`:

1. `smart_labeling.py` - Sistema de scoring
2. `label_validator.py` - Comparación de métodos
3. `retrain_with_smart_labels.py` - Re-entrenamiento
4. `run_predict.py` - Endpoint de predicción

---

## 🏗️ Arquitectura

```
services/ia/
├── smart_labeling.py          # 🧠 Cerebro del sistema
│   ├── calculate_exploit_score()  # Score 0-1
│   ├── smart_label()              # Etiquetado individual
│   ├── smart_label_batch()        # Procesamiento masivo
│   └── explain_label()            # Explicaciones
│
├── label_validator.py         # 📊 Análisis comparativo
│   ├── compare_methods()          # Old vs New
│   ├── analyze_comparison()       # Estadísticas
│   └── generate_report()          # Reportes CSV
│
├── retrain_with_smart_labels.py  # 🚀 Re-entrenamiento
│   └── Entrena modelo V2 con smart labels
│
├── run_predict.py            # 🎯 Predicciones
│   ├── predict_single_cve()      # Un CVE
│   ├── predict_top_risks()       # Top N
│   └── predict_batch()           # Todos
│
└── train_exploit_model.py    # 🔄 Actualizado
    └── Soporta --smart-labels flag
```

---

## ⚡ Uso Rápido

### 1. Comparar Métodos de Etiquetado

```bash
python services/ia/label_validator.py
```

**Output:**
```
📈 ETIQUETAS POSITIVAS (explotables):
   Método original: 192 (58.0%)
   Smart labeling:  145 (43.8%)
   Diferencia: -47 (-14.2%)

🔍 ANÁLISIS ESPECÍFICO: Denegación de Servicio
   Reducción: 42 CVEs (43.8%)
```

### 2. Re-entrenar con Smart Labels

```bash
python services/ia/retrain_with_smart_labels.py
```

**Output:**
```
🏷️ SMART LABELING - RESUMEN
✅ Explotables: 145 (43.8%)
❌ No explotables: 186 (56.2%)

📊 RESULTADOS V2 (Test Set):
              precision    recall  f1-score
Explotable       0.89      0.92      0.91
```

### 3. Calibrar Modelo V2

```bash
python services/ia/calibrate_exploit_model.py --version v2
```

### 4. Hacer Predicciones

```bash
# Un CVE específico con explicación
python services/ia/run_predict.py --cve CVE-2023-41627 --explain

# Top 20 más peligrosos
python services/ia/run_predict.py --top 20 --min-cvss 7.0

# Batch completo
python services/ia/run_predict.py --batch --output predictions.json
```

---

## 📚 Scripts Disponibles

### `smart_labeling.py`

**Función principal:** `calculate_exploit_score(cve) -> (score, metadata)`

**Ejemplo:**
```python
from smart_labeling import calculate_exploit_score, smart_label

# Scoring detallado
score, metadata = calculate_exploit_score(cve)
print(f"Score: {score:.3f}")
print(f"Tipo weight: {metadata['tipo_weight']}")
print(f"Adjustments: {metadata['final_adjustments']}")

# Etiquetado simple
label = smart_label(cve)  # 0 o 1
```

**Pesos configurables:**

Edita `TIPO_WEIGHTS` y `INFRA_MULTIPLIERS` en el archivo para ajustar:

```python
TIPO_WEIGHTS = {
    "Ejecución remota": 1.0,      # Máximo
    "Denegación de servicio": 0.45,  # Reducido
    "Sin clasificar": 0.15,        # Penalizado
}

TIPO_THRESHOLDS = {
    "Ejecución remota": 0.50,      # Más permisivo
    "Denegación de servicio": 0.70,  # Más restrictivo
}
```

---

### `label_validator.py`

**Uso:**
```bash
# Análisis completo
python label_validator.py

# Modo interactivo
python label_validator.py --interactive
```

**Reportes generados:**

```
reports/
├── label_comparison_full.csv     # Todos los CVEs
├── label_discrepancias.csv       # Solo diferencias
├── label_summary_by_type.csv     # Resumen por tipo
└── cases_for_review.csv          # Alta severidad
```

---

### `retrain_with_smart_labels.py`

**Proceso:**

1. Carga CVEs desde MongoDB
2. Genera labels con Smart Labeling
3. Entrena modelo V2
4. Compara con V1 (si existe)
5. Guarda modelo V2

**Archivos generados:**

```
models/
├── exploit_model_v2.joblib       # Modelo re-entrenado
└── featurizer_v2.joblib          # Featurizer actualizado
```

---

### `run_predict.py`

**Modos de uso:**

```bash
# 1. Predicción individual
python run_predict.py --cve CVE-2024-1234

# 2. Con explicación detallada
python run_predict.py --cve CVE-2024-1234 --explain

# 3. Top N más peligrosos
python run_predict.py --top 20 --min-cvss 7.0 --output top20.json

# 4. Procesamiento batch
python run_predict.py --batch --output all_predictions.json

# 5. Especificar versión del modelo
python run_predict.py --cve CVE-2024-1234 --model v2
```

**Output ejemplo:**

```json
{
  "cve_id": "CVE-2023-41627",
  "exploit_probability": 0.9992,
  "risk_level": "CRITICAL",
  "cvss_score": 7.5,
  "tipo": "Ejecución remota",
  "componente": "Open5GS"
}
```

---

## 🔄 Workflow Completo

### Escenario 1: Primera Vez

```bash
# 1. Ingestar datos con telemetría
python ingest_main.py

# 2. Entrenar modelo con smart labels
python services/ia/retrain_with_smart_labels.py

# 3. Calibrar modelo
python services/ia/calibrate_exploit_model.py --version v2

# 4. Hacer predicciones
python services/ia/run_predict.py --top 10
```

### Escenario 2: Mejorar Modelo Existente

```bash
# 1. Comparar métodos de etiquetado
python services/ia/label_validator.py

# 2. Revisar reportes
cat reports/label_summary_by_type.csv

# 3. Ajustar thresholds en smart_labeling.py si necesario

# 4. Re-entrenar
python services/ia/retrain_with_smart_labels.py

# 5. Comparar V1 vs V2
# (automático en el script anterior)
```

### Escenario 3: Análisis de Vulnerabilidades Nuevas

```bash
# 1. Ingestar nuevos CVEs
python ingest_main.py

# 2. Predecir riesgos
python services/ia/run_predict.py --batch --output latest.json

# 3. Filtrar críticos
jq '.[] | select(.risk_level == "CRITICAL")' latest.json
```

---

## 📊 Interpretación de Resultados

### Quality Score (Auditoría)

Generado por telemetría en ingesta:

- **80-100**: Excelente - Datos completos
- **60-80**: Bueno - Algunos campos vacíos
- **40-60**: Regular - Revisar manualmente
- **0-40**: Malo - Re-procesar CVE

### Exploit Probability

Score del modelo calibrado (0.0-1.0):

- **≥0.75**: 🔴 CRITICAL - Acción inmediata
- **0.50-0.75**: 🟠 HIGH - Priorizar
- **0.25-0.50**: 🟡 MEDIUM - Monitorear
- **<0.25**: 🟢 LOW - Bajo riesgo

### Smart Label Score

Score interno de smart labeling (0.0-1.0):

Componentes:
```
final_score = (
    base_cvss * 
    tipo_weight * 
    cvss_multiplier * 
    infra_multiplier * 
    age_factor
) + keyword_bonus + exploit_bonus
```

---

## 🔍 FAQ

### ¿Cuándo usar método original vs smart labeling?

**Original:**
- Datasets pequeños (<100 CVEs)
- Sin información de infraestructura 5G
- Para comparación con versiones anteriores

**Smart Labeling:**
- Datasets grandes (>300 CVEs)
- Contexto 5G disponible
- Necesidad de reducir falsos positivos

---

### ¿Cómo ajustar thresholds?

Edita `smart_labeling.py`:

```python
TIPO_THRESHOLDS = {
    "Ejecución remota": 0.50,  # Bajar para más sensibilidad
    "Denegación de servicio": 0.70,  # Subir para más especificidad
}
```

**Efecto:**
- Threshold más **bajo** → Más CVEs clasificados como explotables
- Threshold más **alto** → Menos CVEs clasificados como explotables

---

### ¿Qué hacer si V2 no supera a V1?

1. **Revisar distribución de labels:**
   ```bash
   python label_validator.py
   ```

2. **Ajustar pesos:**
   - Incrementar `TIPO_WEIGHTS` para tipos críticos
   - Reducir thresholds para tipos importantes

3. **Verificar datos:**
   ```bash
   python ingest_main.py --debug
   ```

4. **Re-entrenar con más datos:**
   - Ingestar más CVEs desde NVD
   - Verificar calidad con telemetría

---

### ¿Cómo explicar predicciones a no técnicos?

Usa `--explain` flag:

```bash
python run_predict.py --cve CVE-2024-1234 --explain
```

Output incluye:
- Score final y threshold usado
- Componentes del cálculo
- Condiciones CVSS detectadas
- Ajustes aplicados con razones

---

### ¿Puedo usar smart labeling fuera de este proyecto?

Sí, `smart_labeling.py` es independiente:

```python
from smart_labeling import calculate_exploit_score

cve = {
    "cve_id": "CVE-2024-1234",
    "cvssv3": {"score": 8.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "tipo": "Ejecución remota",
    "descripcion_general": "Remote code execution via unauthenticated API",
    "infraestructura_5g_afectada": ["AMF"],
    "referencias_mitre": ["https://exploit-db.com/exploits/12345"]
}

score, metadata = calculate_exploit_score(cve)
print(f"Exploit score: {score:.3f}")
```

---

## 📞 Soporte

Para problemas o mejoras:

1. Revisa logs de telemetría: `reports/ingest_metrics.json`
2. Compara labels: `python label_validator.py`
3. Verifica modelos: `ls -lh models/`


**Versión:** 2.0  
**Última actualización:** Diciembre 2024