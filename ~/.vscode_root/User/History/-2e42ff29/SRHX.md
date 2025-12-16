# VulnDB 5G 
# Ingesta
python3 ingest.py

# Levantar IA
# 1. Entrenar V1 (YA HECHO ✅)
python3 train_exploit_model.py

# 2. Calibrar V1 (YA HECHO ✅)
python3 calibrate_exploit_model.py

# 3. Arreglar smart_labeling.py (NECESARIO)
# Añadir PHYSICAL al dict av_stats

# 4. Entrenar V2.1
python3 retrain_with_smart_labels.py

# 5. Calibrar V2.1
python3 calibrate_exploit_model.py --v21

# 6. Comparar versiones
python3 compare_versions.py

# 7. Probar predicciones
python3 run_predict.py --version v2.1 --top 20