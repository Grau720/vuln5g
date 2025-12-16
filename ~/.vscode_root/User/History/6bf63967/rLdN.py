import os
from dotenv import load_dotenv

load_dotenv()

MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_PORT = int(os.getenv("MONGO_PORT", 27017))
MONGO_USER = os.getenv("MONGO_USER", "admin")
MONGO_PASS = os.getenv("MONGO_PASS", "changeme")
MONGO_DB = os.getenv("MONGO_DB", "vulndb")
MONGO_AUTH_DB = os.getenv("MONGO_AUTH_DB", "admin")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION", "vulnerabilidades")

NVD_BASE_URL = os.getenv("NVD_BASE_URL")
NVD_RESULTS_PER_PAGE = int(os.getenv("NVD_RESULTS_PER_PAGE", 2000))
KEYWORDS="5G,Open5GS,NR-U,NR SA,NR NSA,gNB,NGAP,XnAP,F1AP,PFCP,UPF,SMF,AMF,AUSF,UDM,NEF,NSSF,SCP,CPRI,eCPRI,O-RAN,ORAN,RAN Intelligent Controller,RIC,E1AP,N1N2"
NVD_KEYWORDS = [kw.strip() for kw in os.getenv("NVD_KEYWORDS", "").split(",")]
# NVD_KEYWORDS = [kw.strip() for kw in KEYWORDS.split(",")]
NVD_API_KEY = os.getenv("NVD_API_KEY")
SLEEP_SECONDS = float(os.getenv("NVD_SLEEP_BETWEEN_REQUESTS", 1.5))
