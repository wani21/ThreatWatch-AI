

# ============================================================
# NEW CELL
# ============================================================# ============================================================
#  1. IMPORTS
# ============================================================
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import warnings
import os
from datetime import datetime

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, roc_curve, precision_recall_curve,
    average_precision_score
)

warnings.filterwarnings("ignore")
sns.set_theme(style="darkgrid", palette="muted")
plt.rcParams["figure.dpi"] = 120
print("✅ All libraries imported successfully.")

# ============================================================
#  2. LOAD DATASET
# ============================================================
DATASET_PATH = "login_data.csv"   # <-- change to your file path

df = pd.read_csv(DATASET_PATH)

print(f"📊 Dataset shape : {df.shape}")
print(f"📋 Columns       : {list(df.columns)}")
print()
df.head(3)

# ============================================================
#  3. BASIC EDA
# ============================================================
print("=== Data Types ===")
print(df.dtypes)
print()
print("=== Missing Values ===")
print(df.isnull().sum())
print()
print("=== Basic Stats ===")
df.describe(include="all").T

# Distribution of login_status
if "login_status" in df.columns:
    fig, axes = plt.subplots(1, 3, figsize=(16, 4))

    df["login_status"].value_counts().plot.bar(ax=axes[0], color=["#2ecc71","#e74c3c","#f39c12"])
    axes[0].set_title("Login Status Distribution")
    axes[0].set_xlabel("")

    if "login_hour" in df.columns:
        df["login_hour"].hist(bins=24, ax=axes[1], color="#3498db", edgecolor="white")
        axes[1].set_title("Login Hour Distribution")
        axes[1].set_xlabel("Hour of Day")

    if "failed_attempt_count" in df.columns:
        df["failed_attempt_count"].value_counts().head(15).plot.bar(ax=axes[2], color="#e67e22")
        axes[2].set_title("Failed Attempt Count Distribution")

    plt.tight_layout()
    plt.show()

# VPN / TOR / Flags
flag_cols = [c for c in ["vpn_detected","tor_detected","new_device","new_location","impossible_travel"] if c in df.columns]
if flag_cols:
    flag_df = df[flag_cols].mean().sort_values(ascending=False)
    flag_df.plot.barh(figsize=(8, 3), color="#9b59b6")
    plt.title("Proportion of Security Flag Events")
    plt.xlabel("Proportion")
    plt.tight_layout()
    plt.show()

# ============================================================
#  4. PREPROCESSING & FEATURE ENGINEERING
# ============================================================
data = df.copy()

# ── 4.1  Parse timestamp ──────────────────────────────────
if "timestamp" in data.columns:
    data["timestamp"] = pd.to_datetime(data["timestamp"], errors="coerce")
    data["login_hour"]    = data["timestamp"].dt.hour
    data["day_of_week"]   = data["timestamp"].dt.dayofweek        # 0=Mon … 6=Sun
    data["is_weekend"]    = (data["day_of_week"] >= 5).astype(int)
    data["is_night"]      = data["login_hour"].apply(lambda h: 1 if (h < 6 or h >= 22) else 0)
    data["is_business"]   = data["login_hour"].apply(lambda h: 1 if 9 <= h <= 17 else 0)
    print("✅ Timestamp features engineered")

# ── 4.2  Boolean → int ───────────────────────────────────
bool_cols = ["vpn_detected","tor_detected","new_device","new_location","impossible_travel"]
for col in bool_cols:
    if col in data.columns:
        data[col] = data[col].astype(str).str.lower().map(
            {"true":1,"false":0,"1":1,"0":0,"yes":1,"no":0}
        ).fillna(0).astype(int)
print("✅ Boolean flags converted to int")

# ── 4.3  Login status → binary flag ──────────────────────
if "login_status" in data.columns:
    data["login_failed"] = (data["login_status"].str.lower() == "failed").astype(int)

# ── 4.4  Per-user behavioral aggregates (rolling 7-day) ──
if "user_id" in data.columns and "timestamp" in data.columns:
    data_sorted = data.sort_values(["user_id","timestamp"])
    data_sorted["login_frequency_7d"] = (
        data_sorted.groupby("user_id")["timestamp"]
        .transform(lambda s: s.expanding().count())
    )
    if "failed_attempt_count" in data.columns:
        data_sorted["avg_failed_7d"] = (
            data_sorted.groupby("user_id")["failed_attempt_count"]
            .transform(lambda s: s.expanding().mean())
        )
    data = data_sorted
    print("✅ Behavioral aggregates computed")

# ── 4.5  Categorical encoding ────────────────────────────
cat_cols = ["country","city","device_type","browser"]
le_dict = {}
for col in cat_cols:
    if col in data.columns:
        le = LabelEncoder()
        data[col + "_enc"] = le.fit_transform(data[col].astype(str))
        le_dict[col] = le
print("✅ Categorical columns label-encoded")

# ── 4.6  Separate ground-truth label (if present) ────────
y_true = None
if "risk_label" in data.columns:
    y_true = data["risk_label"].copy()
    print(f"✅ Ground-truth label found. Distribution:\n{y_true.value_counts()}")

# ── 4.7  Select final feature set ────────────────────────
DROP_COLS = ["user_id","timestamp","ip_address","event_id",
             "login_status","risk_label","country","city","device_type","browser"]

FEATURE_COLS = [
    "login_hour", "day_of_week", "is_weekend", "is_night", "is_business",
    "failed_attempt_count", "login_failed",
    "vpn_detected", "tor_detected",
    "new_device", "new_location", "impossible_travel",
    "country_enc", "city_enc", "device_type_enc", "browser_enc",
]

# Add aggregates if computed
for col in ["login_frequency_7d","avg_failed_7d"]:
    if col in data.columns:
        FEATURE_COLS.append(col)

# Keep only columns that actually exist
FEATURE_COLS = [c for c in FEATURE_COLS if c in data.columns]
print(f"\n📐 Final feature set ({len(FEATURE_COLS)} features):")
print(FEATURE_COLS)

# ── 4.8  Build feature matrix & handle NaN ────────────────
X = data[FEATURE_COLS].copy()
X = X.fillna(X.median(numeric_only=True))
print(f"✅ Feature matrix shape: {X.shape}")
print(f"   NaN remaining: {X.isnull().sum().sum()}")
X.describe().T

# ============================================================
#  5. SCALING
# ============================================================
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
X_scaled_df = pd.DataFrame(X_scaled, columns=FEATURE_COLS, index=X.index)
print("✅ Features scaled with StandardScaler")
print(f"   Shape: {X_scaled_df.shape}")

# Feature correlation heatmap
plt.figure(figsize=(14, 10))
corr = X_scaled_df.corr()
mask = np.triu(np.ones_like(corr, dtype=bool))
sns.heatmap(corr, mask=mask, annot=True, fmt=".2f", cmap="coolwarm",
            linewidths=0.4, annot_kws={"size": 7})
plt.title("ALMAS Feature Correlation Matrix", fontsize=14, pad=12)
plt.tight_layout()
plt.show()

# ============================================================
#  6. ISOLATION FOREST TRAINING
# ============================================================

# --- Estimate contamination from ground-truth labels if available ---
if y_true is not None:
    anomaly_rate = (y_true != "normal").mean() if y_true.dtype == object else (y_true == 1).mean()
    CONTAMINATION = float(np.clip(anomaly_rate, 0.01, 0.30))
    print(f"📊 Ground-truth anomaly rate: {anomaly_rate:.3f}")
else:
    CONTAMINATION = 0.10   # default 10% for cybersecurity datasets
    print("ℹ️  No ground-truth label found — using default contamination=0.10")

print(f"🎯 Using contamination = {CONTAMINATION:.3f}")

# --- Train model ---
iso_forest = IsolationForest(
    n_estimators   = 150,
    max_samples    = "auto",
    contamination  = CONTAMINATION,
    max_features   = 1.0,
    bootstrap      = False,
    n_jobs         = -1,
    random_state   = 42,
    verbose        = 0
)

iso_forest.fit(X_scaled)
print("\n✅ Isolation Forest trained successfully!")
print(f"   Trees       : {iso_forest.n_estimators}")
print(f"   Features    : {X_scaled.shape[1]}")
print(f"   Samples     : {X_scaled.shape[0]}")
print(f"   Contam.     : {CONTAMINATION}")

# ============================================================
#  7. ANOMALY SCORES
# ============================================================

# Raw decision function (higher = more normal)
data["score_raw"]    = iso_forest.decision_function(X_scaled)

# Prediction: -1 = anomaly, +1 = normal
data["if_prediction"] = iso_forest.predict(X_scaled)

# Normalise to [0, 1] — 1 means most anomalous
score_min = data["score_raw"].min()
score_max = data["score_raw"].max()
data["anomaly_score"] = 1 - (data["score_raw"] - score_min) / (score_max - score_min)

anomaly_count = (data["if_prediction"] == -1).sum()
normal_count  = (data["if_prediction"] ==  1).sum()
print(f"✅ Anomaly scoring complete")
print(f"   Total events  : {len(data):,}")
print(f"   Normal (1)    : {normal_count:,}  ({normal_count/len(data)*100:.1f}%)")
print(f"   Anomaly (-1)  : {anomaly_count:,}  ({anomaly_count/len(data)*100:.1f}%)")
print()
data[["score_raw","anomaly_score","if_prediction"]].describe()

# ============================================================
#  8. ANOMALY SCORE VISUALISATIONS
# ============================================================
fig, axes = plt.subplots(2, 2, figsize=(16, 10))

# 1. Score distribution
axes[0,0].hist(data[data["if_prediction"]==1]["anomaly_score"],  bins=60,
               alpha=0.6, color="#2ecc71", label="Normal")
axes[0,0].hist(data[data["if_prediction"]==-1]["anomaly_score"], bins=60,
               alpha=0.7, color="#e74c3c", label="Anomaly")
axes[0,0].axvline(x=0.5, color="orange", linestyle="--", label="Threshold 0.5")
axes[0,0].set_title("Anomaly Score Distribution")
axes[0,0].set_xlabel("Anomaly Score (0=Normal, 1=Anomaly)")
axes[0,0].legend()

# 2. Score by hour
hour_score = data.groupby("login_hour")["anomaly_score"].mean()
axes[0,1].bar(hour_score.index, hour_score.values, color="#3498db", edgecolor="white")
axes[0,1].set_title("Average Anomaly Score by Login Hour")
axes[0,1].set_xlabel("Hour of Day")
axes[0,1].set_ylabel("Mean Anomaly Score")

# 3. Score by flag combinations
flag_present = [c for c in ["vpn_detected","tor_detected","new_device","impossible_travel"] if c in data.columns]
if flag_present:
    flag_scores = {col: [
        data[data[col]==0]["anomaly_score"].mean(),
        data[data[col]==1]["anomaly_score"].mean()
    ] for col in flag_present}
    flag_df = pd.DataFrame(flag_scores, index=["Flag=0","Flag=1"]).T
    flag_df.plot.bar(ax=axes[1,0], color=["#27ae60","#c0392b"], edgecolor="white")
    axes[1,0].set_title("Mean Anomaly Score by Security Flag")
    axes[1,0].set_ylabel("Mean Anomaly Score")
    axes[1,0].set_xticklabels(axes[1,0].get_xticklabels(), rotation=20)
    axes[1,0].legend(["No Flag","Flag Active"])

# 4. Top anomalous events
top_anomalies = data.nlargest(500, "anomaly_score")
axes[1,1].scatter(range(len(data)), data["anomaly_score"],
                  c=data["if_prediction"].map({1:"#2ecc71",-1:"#e74c3c"}),
                  s=0.5, alpha=0.4)
axes[1,1].set_title("All Events — Anomaly Score Scatter")
axes[1,1].set_xlabel("Event Index")
axes[1,1].set_ylabel("Anomaly Score")

plt.suptitle("ALMAS — Isolation Forest Anomaly Detection", fontsize=14, y=1.01)
plt.tight_layout()
plt.show()

# Feature importance proxy via score correlation
feat_importance = {}
for col in FEATURE_COLS:
    feat_importance[col] = abs(X_scaled_df[col].corr(data["anomaly_score"]))

fi_series = pd.Series(feat_importance).sort_values(ascending=True)
fi_series.plot.barh(figsize=(10, 6), color="#8e44ad")
plt.title("Feature Importance (Correlation with Anomaly Score)")
plt.xlabel("|Pearson r| with anomaly_score")
plt.tight_layout()
plt.show()

# ============================================================
#  9. EVALUATION WITH GROUND-TRUTH (if available)
# ============================================================
if y_true is not None:
    # Convert y_true to binary: 1=anomaly, 0=normal
    if y_true.dtype == object:
        y_bin = (y_true.str.lower() != "normal").astype(int)
    else:
        y_bin = y_true.astype(int)

    # IF prediction → binary (1=anomaly, 0=normal)
    y_pred_bin = (data["if_prediction"] == -1).astype(int)

    print("=" * 55)
    print("  ALMAS — Isolation Forest Evaluation Report")
    print("=" * 55)
    print(classification_report(y_bin, y_pred_bin,
                                  target_names=["Normal","Anomaly"]))

    # Confusion matrix
    cm = confusion_matrix(y_bin, y_pred_bin)
    plt.figure(figsize=(6, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Normal","Anomaly"],
                yticklabels=["Normal","Anomaly"])
    plt.title("Confusion Matrix — Isolation Forest")
    plt.ylabel("Actual")
    plt.xlabel("Predicted")
    plt.tight_layout()
    plt.show()

    # ROC Curve
    try:
        auc = roc_auc_score(y_bin, data["anomaly_score"])
        fpr, tpr, _ = roc_curve(y_bin, data["anomaly_score"])
        ap  = average_precision_score(y_bin, data["anomaly_score"])

        fig, axes = plt.subplots(1, 2, figsize=(13, 4))

        axes[0].plot(fpr, tpr, color="#e74c3c", lw=2, label=f"ROC AUC = {auc:.3f}")
        axes[0].plot([0,1],[0,1],"k--", lw=1)
        axes[0].set_title("ROC Curve")
        axes[0].set_xlabel("FPR")
        axes[0].set_ylabel("TPR")
        axes[0].legend()

        prec, rec, _ = precision_recall_curve(y_bin, data["anomaly_score"])
        axes[1].plot(rec, prec, color="#3498db", lw=2, label=f"AP = {ap:.3f}")
        axes[1].set_title("Precision-Recall Curve")
        axes[1].set_xlabel("Recall")
        axes[1].set_ylabel("Precision")
        axes[1].legend()

        plt.suptitle("ALMAS — Model Performance Curves", fontsize=13)
        plt.tight_layout()
        plt.show()

        print(f"\n📊 ROC-AUC Score    : {auc:.4f}")
        print(f"📊 Avg Precision    : {ap:.4f}")
    except Exception as e:
        print(f"ROC/PR curves error: {e}")
else:
    print("ℹ️  No 'risk_label' column found — skipping supervised evaluation.")
    print("   The model still generates anomaly scores for all events.")

# ============================================================
#  10. RISK AGGREGATION ENGINE
# ============================================================

def compute_brute_force_score(row):
    """
    Heuristic brute-force risk from failed_attempt_count.
    Maps: 0 failures → 0, 5+ failures → 100
    """
    if "failed_attempt_count" not in row.index:
        return 0
    failures = row["failed_attempt_count"]
    return min(float(failures) / 5.0 * 100, 100)


def compute_risk_score(row, bf_weight=0.6, ml_weight=0.4):
    """
    Final ALMAS risk score (0–100).
    bf_weight + ml_weight should sum to 1.0
    """
    bf_score  = compute_brute_force_score(row)
    ml_score  = row["anomaly_score"] * 100       # anomaly_score is [0,1]
    return (bf_weight * bf_score) + (ml_weight * ml_score)


def risk_level(score):
    if score < 40:
        return "SAFE"
    elif score <= 70:
        return "MFA_REQUIRED"
    else:
        return "LOCK_ACCOUNT"


def recommended_action(level):
    return {
        "SAFE"          : "Allow login",
        "MFA_REQUIRED"  : "Trigger multi-factor authentication",
        "LOCK_ACCOUNT"  : "Lock account + Send alert (Slack/Email/Telegram)",
    }[level]


# Apply risk engine to entire dataset
data["risk_score"]  = data.apply(compute_risk_score, axis=1)
data["risk_level"]  = data["risk_score"].apply(risk_level)
data["action"]      = data["risk_level"].apply(recommended_action)

print("✅ Risk scores computed for all events")
print()
print("=== Risk Level Distribution ===")
print(data["risk_level"].value_counts())
print()
print("=== Sample High-Risk Events ===")
high_risk = data[data["risk_level"] == "LOCK_ACCOUNT"].head(5)
display_cols = [c for c in ["user_id","login_hour","country","vpn_detected",
                             "tor_detected","impossible_travel","failed_attempt_count",
                             "anomaly_score","risk_score","risk_level","action"]
                if c in data.columns]
print(high_risk[display_cols].to_string(index=False))

# Risk level pie chart
risk_counts = data["risk_level"].value_counts()
colors = {"SAFE":"#2ecc71", "MFA_REQUIRED":"#f39c12", "LOCK_ACCOUNT":"#e74c3c"}
plt.figure(figsize=(7, 5))
plt.pie(risk_counts.values,
        labels=risk_counts.index,
        autopct="%1.1f%%",
        colors=[colors.get(k,"#95a5a6") for k in risk_counts.index],
        startangle=90,
        wedgeprops={"edgecolor":"white","linewidth":1.5})
plt.title("ALMAS — Risk Level Distribution", fontsize=13)
plt.tight_layout()
plt.show()

# Risk score histogram
plt.figure(figsize=(10, 4))
plt.hist(data[data["risk_level"]=="SAFE"]["risk_score"],          bins=50,
         alpha=0.6, color="#2ecc71", label="SAFE")
plt.hist(data[data["risk_level"]=="MFA_REQUIRED"]["risk_score"],  bins=50,
         alpha=0.6, color="#f39c12", label="MFA Required")
plt.hist(data[data["risk_level"]=="LOCK_ACCOUNT"]["risk_score"],  bins=50,
         alpha=0.7, color="#e74c3c", label="Lock Account")
plt.axvline(40, color="orange", linestyle="--", label="MFA Threshold (40)")
plt.axvline(70, color="red",    linestyle="--", label="Lock Threshold (70)")
plt.title("Risk Score Distribution by Action Level")
plt.xlabel("Risk Score (0–100)")
plt.ylabel("Count")
plt.legend()
plt.tight_layout()
plt.show()

# ============================================================
#  11. REAL-TIME INFERENCE PIPELINE
# ============================================================

def preprocess_single_event(event: dict) -> np.ndarray:
    """
    Convert a raw login event dict into a scaled feature vector.
    Returns shape (1, n_features) ready for Isolation Forest.
    """
    ts = pd.to_datetime(event.get("timestamp", datetime.utcnow()))
    hour = ts.hour

    row = {
        "login_hour"          : hour,
        "day_of_week"         : ts.dayofweek,
        "is_weekend"          : int(ts.dayofweek >= 5),
        "is_night"            : int(hour < 6 or hour >= 22),
        "is_business"         : int(9 <= hour <= 17),
        "failed_attempt_count": event.get("failed_attempt_count", 0),
        "login_failed"        : int(str(event.get("login_status","")).lower() == "failed"),
        "vpn_detected"        : int(event.get("vpn_detected", False)),
        "tor_detected"        : int(event.get("tor_detected", False)),
        "new_device"          : int(event.get("new_device", False)),
        "new_location"        : int(event.get("new_location", False)),
        "impossible_travel"   : int(event.get("impossible_travel", False)),
        "country_enc"         : le_dict["country"].transform(
                                    [event.get("country","Unknown")])[0]
                                if "country" in le_dict and event.get("country","Unknown")
                                   in le_dict["country"].classes_
                                else 0,
        "city_enc"            : 0,
        "device_type_enc"     : le_dict["device_type"].transform(
                                    [event.get("device_type","Unknown")])[0]
                                if "device_type" in le_dict and event.get("device_type","Unknown")
                                   in le_dict["device_type"].classes_
                                else 0,
        "browser_enc"         : le_dict["browser"].transform(
                                    [event.get("browser","Unknown")])[0]
                                if "browser" in le_dict and event.get("browser","Unknown")
                                   in le_dict["browser"].classes_
                                else 0,
        "login_frequency_7d"  : event.get("login_frequency_7d", 1),
        "avg_failed_7d"       : event.get("avg_failed_7d", 0),
    }

    # Keep only features the model was trained on
    vec = np.array([row.get(f, 0) for f in FEATURE_COLS], dtype=float).reshape(1, -1)
    return scaler.transform(vec)


def predict_login_event(event: dict) -> dict:
    """
    Full ALMAS real-time inference pipeline.
    Input : raw login event dict
    Output: risk assessment dict
    """
    X_event      = preprocess_single_event(event)
    raw_score    = iso_forest.decision_function(X_event)[0]
    prediction   = iso_forest.predict(X_event)[0]   # -1=anomaly, 1=normal

    # Normalise score
    anomaly_sc   = float(1 - (raw_score - score_min) / (score_max - score_min))
    anomaly_sc   = float(np.clip(anomaly_sc, 0, 1))

    # Brute-force score
    failures     = event.get("failed_attempt_count", 0)
    bf_score     = min(failures / 5.0 * 100, 100)

    # Final risk
    final_risk   = 0.6 * bf_score + 0.4 * anomaly_sc * 100
    level        = risk_level(final_risk)

    return {
        "user_id"           : event.get("user_id", "unknown"),
        "timestamp"         : str(event.get("timestamp", "")),
        "anomaly_score"     : round(anomaly_sc, 4),
        "brute_force_score" : round(bf_score,   2),
        "final_risk_score"  : round(final_risk, 2),
        "risk_level"        : level,
        "action"            : recommended_action(level),
        "is_anomaly"        : prediction == -1,
    }


# ── Demo ──────────────────────────────────────────────────
print("=" * 55)
print("  ALMAS REAL-TIME INFERENCE — DEMO")
print("=" * 55)

test_events = [
    {
        "user_id": "U001", "timestamp": "2026-05-22 09:30:00",
        "login_status": "success", "failed_attempt_count": 0,
        "vpn_detected": False, "tor_detected": False,
        "new_device": False, "new_location": False,
        "impossible_travel": False, "country": "India",
        "device_type": "Windows", "browser": "Chrome",
        "login_frequency_7d": 12, "avg_failed_7d": 0.2,
    },
    {
        "user_id": "U002", "timestamp": "2026-05-22 03:15:00",
        "login_status": "failed", "failed_attempt_count": 8,
        "vpn_detected": True, "tor_detected": False,
        "new_device": True, "new_location": True,
        "impossible_travel": True, "country": "Russia",
        "device_type": "Linux", "browser": "Unknown",
        "login_frequency_7d": 45, "avg_failed_7d": 6.5,
    },
    {
        "user_id": "U003", "timestamp": "2026-05-22 14:00:00",
        "login_status": "success", "failed_attempt_count": 1,
        "vpn_detected": False, "tor_detected": True,
        "new_device": False, "new_location": False,
        "impossible_travel": False, "country": "Germany",
        "device_type": "Mac", "browser": "Firefox",
        "login_frequency_7d": 8, "avg_failed_7d": 0.5,
    },
]

for ev in test_events:
    result = predict_login_event(ev)
    print(f"\n👤 User       : {result['user_id']}")
    print(f"   ML Score   : {result['anomaly_score']}")
    print(f"   BF Score   : {result['brute_force_score']}")
    print(f"   Risk Score : {result['final_risk_score']}")
    print(f"   Risk Level : {result['risk_level']}")
    print(f"   Action     : {result['action']}")

# ============================================================
#  12. SAVE MODEL ARTIFACTS
# ============================================================
MODEL_DIR = "almas_model"
os.makedirs(MODEL_DIR, exist_ok=True)

joblib.dump(iso_forest, f"{MODEL_DIR}/isolation_forest.pkl")
joblib.dump(scaler,     f"{MODEL_DIR}/scaler.pkl")
joblib.dump(le_dict,    f"{MODEL_DIR}/label_encoders.pkl")

# Save feature list
import json
with open(f"{MODEL_DIR}/feature_cols.json", "w") as f:
    json.dump(FEATURE_COLS, f, indent=2)

# Save score bounds for normalisation
bounds = {"score_min": float(score_min), "score_max": float(score_max)}
with open(f"{MODEL_DIR}/score_bounds.json", "w") as f:
    json.dump(bounds, f, indent=2)

print(f"✅ Model artifacts saved to '{MODEL_DIR}/'")
print(f"   isolation_forest.pkl")
print(f"   scaler.pkl")
print(f"   label_encoders.pkl")
print(f"   feature_cols.json")
print(f"   score_bounds.json")

# ============================================================
#  13. LOAD SAVED MODEL
# ============================================================
import json

loaded_model   = joblib.load(f"{MODEL_DIR}/isolation_forest.pkl")
loaded_scaler  = joblib.load(f"{MODEL_DIR}/scaler.pkl")
loaded_le_dict = joblib.load(f"{MODEL_DIR}/label_encoders.pkl")

with open(f"{MODEL_DIR}/feature_cols.json") as f:
    loaded_features = json.load(f)

with open(f"{MODEL_DIR}/score_bounds.json") as f:
    loaded_bounds = json.load(f)

print("✅ Model reloaded successfully")
print(f"   Features : {loaded_features}")
print(f"   Bounds   : {loaded_bounds}")

# Quick sanity check
test_vec     = loaded_scaler.transform(np.zeros((1, len(loaded_features))))
sanity_score = loaded_model.decision_function(test_vec)[0]
print(f"   Sanity check score (zeros): {sanity_score:.4f}  ✅")

# ============================================================
#  14. FINAL OUTPUT
# ============================================================
output_cols = [c for c in
    ["user_id","timestamp","login_hour","country","device_type","browser",
     "vpn_detected","tor_detected","impossible_travel","failed_attempt_count",
     "anomaly_score","risk_score","risk_level","action"]
    if c in data.columns]

output_df = data[output_cols].copy()
output_df.to_csv("almas_scored_output.csv", index=False)
print("✅ Scored dataset saved to 'almas_scored_output.csv'")
print()
print("=== Sample Scored Events ===")
print(output_df.head(10).to_string(index=False))
print()
print("=" * 55)
print("  ALMAS — Isolation Forest Pipeline COMPLETE ✅")
print("=" * 55)
print(f"  Total Events Scored  : {len(output_df):,}")
print(f"  Safe Events          : {(output_df['risk_level']=='SAFE').sum():,}")
print(f"  MFA Triggered        : {(output_df['risk_level']=='MFA_REQUIRED').sum():,}")
print(f"  Accounts Locked      : {(output_df['risk_level']=='LOCK_ACCOUNT').sum():,}")
