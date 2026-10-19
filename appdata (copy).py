import os
import time
import glob
import uuid
import json
import logging
import threading
import subprocess
from queue import Queue
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse
import constants as C

# =========================================================
# Logging
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

# =========================================================
# Ensure Directories Exist
# =========================================================

os.makedirs(C.PCAP_FOLDER, exist_ok=True)
os.makedirs(C.CSV_FOLDER, exist_ok=True)
os.makedirs(C.PREDICTED_FOLDER, exist_ok=True)

os.makedirs(
    os.path.dirname(C.JSONL_FILE_PATH),
    exist_ok=True
)

os.makedirs(
    os.path.dirname(C.Malicious_JSONL_FILE_PATH),
    exist_ok=True
)

# =========================================================
# FastAPI App
# =========================================================

app = FastAPI(
    title="Network Traffic Prediction API",
    version="1.0"
)

# =========================================================
# Globals
# =========================================================

processing_queue = Queue()
processed_pcaps = set()
queued_pcaps = set()

traffic_model = None
anomaly_model = None
classification_model = None

traffic_features = None
anomaly_features = None
classification_features = None

traffic_label_encoder = None
anomaly_label_encoder = None
classification_label_encoder = None

# =========================================================
# Load Models / Artifacts
# =========================================================

def load_artifacts():
    global traffic_model
    global anomaly_model
    global classification_model

    global traffic_features
    global anomaly_features
    global classification_features

    global traffic_label_encoder
    global anomaly_label_encoder
    global classification_label_encoder

    try:
        traffic_model = joblib.load(
            C.TRAFFIC_MODEL_PATH
        )
        logger.info("[+] Traffic model loaded")
    except Exception as e:
        logger.error(f"Traffic model load failed: {e}")

    try:
        anomaly_model = joblib.load(
            C.ANOMALY_MODEL_PATH
        )
        logger.info("[+] Anomaly model loaded")
    except Exception as e:
        logger.error(f"Anomaly model load failed: {e}")

    try:
        classification_model = joblib.load(
            C.CLASSIFICATION_MODEL_PATH
        )
        logger.info("[+] Classification model loaded")
    except Exception as e:
        logger.error(f"Classification model load failed: {e}")

    try:
        traffic_features = list(
            joblib.load(C.TRAFFIC_FEATURES_PATH)
        )
    except Exception as e:
        logger.error(f"Traffic features load failed: {e}")
        traffic_features = []

    try:
        anomaly_features = list(
            joblib.load(C.ANOMALY_FEATURES_PATH)
        )
    except Exception as e:
        logger.error(f"Anomaly features load failed: {e}")
        anomaly_features = []

    try:
        classification_features = list(
            joblib.load(C.CLASSIFICATION_FEATURES_PATH)
        )
    except Exception as e:
        logger.error(f"Classification features load failed: {e}")
        classification_features = []

    try:
        traffic_label_encoder = joblib.load(
            C.TRAFFIC_ENCODER_PATH
        )
    except:
        traffic_label_encoder = None

    try:
        anomaly_label_encoder = joblib.load(
            C.ANOMALY_ENCODER_PATH
        )
    except:
        anomaly_label_encoder = None

    try:
        classification_label_encoder = joblib.load(
            C.CLASSIFICATION_ENCODER_PATH
        )
    except:
        classification_label_encoder = None


load_artifacts()

# =========================================================
# Helper Functions
# =========================================================

def wait_for_file_stability(
    path,
    checks=2,
    delay=1
):
    last_size = -1
    stable = 0

    while stable < checks:

        if not os.path.exists(path):
            return False

        current_size = os.path.getsize(path)

        if current_size > 24 and current_size == last_size:
            stable += 1
        else:
            stable = 0
            last_size = current_size

        time.sleep(delay)

    return True


def is_valid_pcap(path):
    return (
        os.path.exists(path)
        and os.path.getsize(path) > 24
    )


def prepare_dataframe(df, features):

    df = df.copy()

    for feature in features:
        if feature not in df.columns:
            df[feature] = 0

    df = df[features]

    df = df.replace(
        [np.inf, -np.inf],
        0
    )

    df = df.fillna(0)

    return df

# =========================================================
# CICFlowMeter
# =========================================================

def run_cicflowmeter(
    pcap_path,
    output_csv
):
    try:

        result = subprocess.run(
            [
                C.CICFLOWMETER_CMD,
                "-f",
                pcap_path,
                "-c",
                output_csv
            ],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            logger.error(
                f"CICFlowMeter Error: {result.stderr}"
            )
            return False

        return True

    except Exception as e:
        logger.error(
            f"CICFlowMeter Exception: {e}"
        )
        return False

# =========================================================
# Prediction Pipeline
# =========================================================

def process_csv(csv_path):

    try:

        df = pd.read_csv(csv_path)

        if df.empty:
            logger.warning(
                f"Empty CSV: {csv_path}"
            )
            return None

        # -----------------------------
        # Feature Preparation
        # -----------------------------

        df_traffic = prepare_dataframe(
            df,
            traffic_features
        )

        df_anomaly = prepare_dataframe(
            df,
            anomaly_features
        )

        df_classification = prepare_dataframe(
            df,
            classification_features
        )

        # -----------------------------
        # Predictions
        # -----------------------------

        traffic_pred = traffic_model.predict(
            df_traffic
        )

        anomaly_pred = anomaly_model.predict(
            df_anomaly
        )

        classification_pred = (
            classification_model.predict(
                df_classification
            )
        )

        # -----------------------------
        # Decode Labels
        # -----------------------------

        if traffic_label_encoder:
            traffic_pred = (
                traffic_label_encoder
                .inverse_transform(
                    traffic_pred
                )
            )

        if anomaly_label_encoder:
            anomaly_pred = (
                anomaly_label_encoder
                .inverse_transform(
                    anomaly_pred
                )
            )

        if classification_label_encoder:
            classification_pred = (
                classification_label_encoder
                .inverse_transform(
                    classification_pred
                )
            )

        # -----------------------------
        # Add Predictions
        # -----------------------------

        df["Traffic_Type"] = traffic_pred
        df["Traffic_Behaviour"] = anomaly_pred
        df["Attack_Class"] = classification_pred
        
        logger.info(f"Traffic predictions: {pd.Series(traffic_pred).value_counts().to_dict()}")
        logger.info(f"Anomaly predictions: {pd.Series(anomaly_pred).value_counts().to_dict()}")

        logger.info(f"Attack predictions: {pd.Series(classification_pred).value_counts().to_dict()}")

        # -----------------------------
        # Save Prediction CSV
        # -----------------------------
        logger.info(f"CSV Columns = {list(df.columns)}")

        logger.info(f"Attack Classes Found = "f"{df['Attack_Class'].unique().tolist()}")
        output_csv = os.path.join(
            C.PREDICTED_FOLDER,
            os.path.basename(
                csv_path
            ).replace(
                ".csv",
                "_pred.csv"
            )
        )

        df.to_csv(
            output_csv,
            index=False
        )

        logger.info(
            f"[+] Prediction saved: {output_csv}"
        )

        # -----------------------------
        # Append JSONL
        # -----------------------------

        records = df.to_dict(
            orient="records"
        )

        with open(C.JSONL_FILE_PATH, "a") as f:
            for record in records:
                f.write(json.dumps(record)+ "\n")

        logger.info(f"[+] Appended predictions to JSONL: {C.JSONL_FILE_PATH}")
        # -----------------------------
        # Save Malicious Flows
        # -----------------------------

        malicious_df = df[
            df["Traffic_Behaviour"]
            == "Malicious"
        ]

        if not malicious_df.empty:

            malicious_records = (
                malicious_df.to_dict(
                    orient="records"
                )
            )

            with open(
                C.Malicious_JSONL_FILE_PATH,
                "a"
            ) as f:

                for record in malicious_records:
                    f.write(
                        json.dumps(record)
                        + "\n"
                    )
                    
            logger.info(f"[+] Appended predictions to JSONL: {C.Malicious_JSONL_FILE_PATH}")

            logger.info(
                f"[+] Malicious flows saved: "
                f"{len(malicious_df)}"
            )

        return output_csv

    except Exception as e:
        logger.error(
            f"Prediction error: {e}"
        )
        return None

# =========================================================
# Worker Thread
# =========================================================

def worker():

    while True:

        pcap_file = processing_queue.get()

        if pcap_file is None:
            break

        try:

            csv_name = (
                os.path.basename(
                    pcap_file
                ).replace(
                    ".pcap",
                    ".csv"
                )
            )

            csv_path = os.path.join(
                C.CSV_FOLDER,
                csv_name
            )

            logger.info(f"[PROCESSING] {pcap_file}")

            if run_cicflowmeter(
                pcap_file,
                csv_path 
            ):

                logger.info(
                    f"[+] Flow extraction completed: "
                    f"{pcap_file}"
                )

                process_csv(csv_path)
                logger.info(f"[COMPLETED] {pcap_file}")

            processed_pcaps.add(pcap_file)
            queued_pcaps.discard(pcap_file)

        except Exception as e:
            logger.error(
                f"Worker error: {e}"
            )

        finally:
            processing_queue.task_done()

# =========================================================
# Watch PCAP Folder
# =========================================================

def watch_pcap_folder():

    while True:

        try:

            pcaps = glob.glob(
                os.path.join(
                    C.PCAP_FOLDER,
                    "*.pcap"
                )
            )

            for pcap in pcaps:

                if pcap in processed_pcaps:
                    continue

                if not wait_for_file_stability(
                    pcap
                ):
                    continue

                if not is_valid_pcap(
                    pcap
                ):
                    continue

                if pcap not in queued_pcaps:
                    processing_queue.put(pcap)
                    queued_pcaps.add(pcap)
                    
                    logger.info(f"[QUEUED] {pcap}")

            time.sleep(1)

        except Exception as e:
            logger.error(
                f"Watcher error: {e}"
            )

# =========================================================
# Cleanup Old PCAPs
# =========================================================

def cleanup_old_pcaps():

    while True:

        try:

            time.sleep(60)

            pcaps = glob.glob(
                os.path.join(
                    C.PCAP_FOLDER,
                    "*.pcap"
                )
            )

            if len(pcaps) <= C.MAX_PCAP_FILES:
                continue

            pcaps.sort(
                key=os.path.getmtime
            )

            old_pcaps = pcaps[
                :-C.MAX_PCAP_FILES
            ]

            for pcap in old_pcaps:

                if pcap not in processed_pcaps:
                    continue

                try:
                    os.remove(pcap)

                    processed_pcaps.discard(
                        pcap
                    )

                    logger.info(
                        f"[+] Deleted: {pcap}"
                    )

                except Exception as e:
                    logger.error(
                        f"Delete failed: {e}"
                    )

        except Exception as e:
            logger.error(
                f"Cleanup error: {e}"
            )

# =========================================================
# API Endpoints
# =========================================================

@app.post("/predict/")
async def predict(
    file: UploadFile = File(...)
):

    temp_csv = os.path.join(
        C.CSV_FOLDER,
        f"{uuid.uuid4().hex}_"
        f"{file.filename}"
    )

    with open(
        temp_csv,
        "wb"
    ) as f:

        f.write(
            await file.read()
        )

    output = process_csv(
        temp_csv
    )

    if output:
        return {
            "message":
            f"/download/"
            f"{os.path.basename(output)}"
        }

    return {
        "error":
        "processing failed"
    }


@app.get("/download/{filename}")
async def download(
    filename: str
):

    path = os.path.join(
        C.PREDICTED_FOLDER,
        filename
    )

    if os.path.exists(path):
        return FileResponse(path)

    return {
        "error": "not found"
    }

# =========================================================
# Startup
# =========================================================

@app.on_event("startup")
def startup_event():

    threading.Thread(
        target=worker,
        daemon=True
    ).start()

    threading.Thread(
        target=watch_pcap_folder,
        daemon=True
    ).start()

    threading.Thread(
        target=cleanup_old_pcaps,
        daemon=True
    ).start()

    logger.info(
        "[+] Background threads started"
    )

# =========================================================
# Main
# =========================================================

if __name__ == "__main__":

    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=9018,
        reload=False
    )
