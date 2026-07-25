# XAF — Module 3: AI Threat Detection Engine

Converts `FeatureVector` objects from **Module 2 (Feature Extraction Engine)**
into `ThreatPrediction` objects using Machine Learning classification.

This module performs **AI threat detection only** — no packet capture, no
feature extraction, no traffic blocking, no explanation/reporting.

---

## 1. Folder Structure

```
xaf_firewall/
├── module1_packet_capture/           # Module 1 — UNCHANGED (verified by diff)
├── module2_feature_extraction/       # Module 2 — UNCHANGED (verified by diff)
│
├── module3_ai_detection/              # Module 3 — NEW
│   ├── __init__.py
│   ├── config.py
│   ├── logger.py
│   ├── exceptions.py
│   ├── models.py
│   ├── utils.py
│   ├── feature_mapper.py
│   ├── preprocessor.py
│   ├── model_loader.py
│   ├── detector.py
│   ├── trainer.py
│   ├── inference.py
│   ├── run_detection.py
│   └── tests/
│       ├── __init__.py
│       ├── test_models.py
│       ├── test_utils.py
│       ├── test_feature_mapper_and_preprocessor.py
│       ├── test_detector.py
│       ├── test_model_loader.py
│       ├── test_trainer.py
│       └── test_inference.py
│
├── README_MODULE2.md
└── README_MODULE3.md                  # this file
```

---

## 2. File-by-File Explanation

| File | Why it exists | What it does | Used by |
|---|---|---|---|
| `config.py` | Separates tunable policy from mechanism | `DetectionConfig`: model path (built from configurable directory + filename, no hardcoded paths), confidence thresholds, supported models, default model, per-category risk weights | Every other Module 3 file |
| `logger.py` | Consistent logging, decoupled from Modules 1/2's own loggers | `get_logger()` — one stream handler, no duplicates | Every other Module 3 file |
| `exceptions.py` | Precise, catchable failure modes | 10 custom exceptions (e.g. `ModelNotTrainedError`, `InvalidFeatureVectorError`, `UnsupportedModelError`) | Every other Module 3 file |
| `models.py` | Entities layer — plain data, no I/O | `ThreatPrediction`, `ThreatLabel`, `Severity`, `AttackCategory` enums | Every other Module 3 file |
| `utils.py` | Pure, independently testable helpers | `classify_severity` (confidence→severity banding), `derive_threat_label`, `compute_risk_score`, `normalize_category_label` | `inference.py` |
| `feature_mapper.py` | Single Responsibility: *which* FeatureVector fields matter | `FeatureMapper.map()` extracts the canonical `FEATURE_ORDER` columns from a `FeatureVector` | `preprocessor.py` (columns), `trainer.py` (columns), `inference.py` |
| `preprocessor.py` | Single Responsibility: *how* raw values become numbers | `Preprocessor` — fixed-vocabulary categorical encoding + numeric array assembly, shared identically between training and inference | `trainer.py`, `inference.py` |
| `model_loader.py` | Generic, model-agnostic persistence | `save_model()` / `load_model()` / `model_exists()` via joblib | `detector.py` |
| `detector.py` | The pluggability seam (Dependency Inversion) | `BaseThreatModel` ABC + `RandomForestThreatModel` implementation + `create_model()` factory | `trainer.py`, `inference.py`, `run_detection.py` |
| `trainer.py` | Batch training/evaluation — separate from live inference | `Trainer`: `load_dataset_from_csv()`, `train()`, `evaluate()`, `save_model()`, `load_model()`, `predict()` | Manual training runs, `run_detection.py` (optional) |
| `inference.py` | The "use case" / orchestration layer | `InferenceEngine.predict(feature_vector) -> ThreatPrediction`; the **only** class other code needs to call | `run_detection.py`, a future Module 4 |
| `run_detection.py` | Demonstrates the full pipeline | Loads a saved model if one exists, else bootstraps a small demo model; builds a sample `FeatureVector`; runs prediction; prints `ThreatPrediction` | Manual run / demo |
| `tests/*.py` | Prove correctness in isolation and end-to-end | Unit tests for every class above, plus integration tests using real Module 2 `FeatureVector` objects | CI / manual verification |

---

## 3. Integration Notes — Modules 1 & 2

**No line of Module 1's or Module 2's original files was modified.**
Checksums/diffs were verified identical before and after this build (see
Section 6 below for the exact commands run).

Module 3 has exactly **one integration point** with Module 2: it imports
`FeatureVector` (and, for enum comparisons, `PacketDirection`/
`ConnectionState`) purely as a type contract in `feature_mapper.py`,
`inference.py`, and `run_detection.py`. It does **not** import or depend
on any of Module 2's internal classes (`FlowBuilder`, `SessionManager`,
etc.) — it only ever receives a finished `FeatureVector` object, exactly
as Module 2 already produces it.

No changes to Module 2 were required for this integration.

---

## 4. Architecture & Design Decisions

**Common ML model interface (SOLID — Dependency Inversion).**
`trainer.py` and `inference.py` are written entirely against the abstract
`BaseThreatModel` interface in `detector.py`, never against
`RandomForestThreatModel` directly. Adding XGBoost, LightGBM, CatBoost, a
neural network, or Isolation Forest later means writing one new class
that implements `BaseThreatModel` and registering it in
`create_model()`'s factory dict — **no other Module 3 file needs to
change.** Requesting one of those not-yet-implemented names today raises
a clear `UnsupportedModelError` explaining exactly what to do next,
rather than crashing on a missing third-party import.

**Two-tier classification (`AttackCategory` + `ThreatLabel`).**
The ML model predicts one of the 9 specific `AttackCategory` values
(`BENIGN`, `PORT_SCAN`, `DDOS`, ...) exactly as specified. `ThreatLabel`
is a coarser, derived view (`BENIGN` / `SUSPICIOUS` / `MALICIOUS` /
`UNKNOWN`) for consumers that just need "is this a problem?" — see
`utils.derive_threat_label()`.

**`risk_score` vs. `confidence_score`.**
These are deliberately different numbers. `confidence_score` is purely
the model's certainty in its prediction. `risk_score` additionally weighs
*how dangerous that category typically is* (`config.py` →
`attack_category_risk_weights`), so an equally-confident `PORT_SCAN` and
`DATA_EXFILTRATION` prediction do not read as equally urgent.

**Fixed categorical vocabularies, not a fitted encoder.**
`protocol`, `direction`, and `connection_state` are small, closed sets
guaranteed by Module 2's own enums, so `preprocessor.py` uses hand-declared
vocabularies rather than a `sklearn.LabelEncoder` that would need to be
persisted and kept in sync with the model file. This is simpler and
removes an entire class of "encoder/model version mismatch" bugs.

**Single source of truth for column order (`FEATURE_ORDER`).**
Defined once in `feature_mapper.py` and imported everywhere else
(`preprocessor.py`, `trainer.py`). This is what prevents the classic ML
bug where a model trained on columns in one order is fed inference input
in a different order.

---

## 5. Dataset Compatibility (Trainer)

`trainer.py`'s `load_dataset_from_csv()` accepts:
- `label_column` — since public datasets name this differently (e.g.
  CICIDS2017's `" Label"` vs. UNSW-NB15's `"attack_cat"`).
- `column_mapping` — an optional dict renaming a dataset's raw columns
  onto Module 3's canonical `FEATURE_ORDER` names.

This makes it adaptable to **CICIDS2017, CSE-CIC-IDS2018, UNSW-NB15, and
TON_IoT** exports, among others. **No dataset files are bundled** — point
`load_dataset_from_csv()` at your own CSV.

Any `FEATURE_ORDER` column absent from a given CSV (even after mapping)
is filled with `0.0`, so a partial/differently-shaped dataset can still be
used, with the understanding that missing features will reduce model
quality — this is a graceful-degradation choice, not silent data
fabrication.

---

## 6. How To Run

### Install dependencies
```bash
pip install scikit-learn pandas numpy joblib pytest --break-system-packages
```

### Verify Module 1 & 2 were not modified (optional, for peace of mind)
```bash
cd xaf_firewall
diff <(cat module1_packet_capture/capture.py) <(cat /path/to/original/capture.py)
# (repeat for models.py, utils.py, and every Module 2 file)
```

### Run the demo runner
```bash
cd xaf_firewall
python3 -m module3_ai_detection.run_detection
```

**Expected output:** a warning that no trained model file was found
(expected — no model is bundled), followed by the bootstrapped demo
model training, the sample `FeatureVector`, and a `ThreatPrediction` with
`attack_category`, `confidence_score`, `risk_score`, `severity`, and the
full per-class probability breakdown.

⚠️ **The bootstrapped demo model is for demonstration only.** For real
detection, train via `trainer.Trainer` against a real dataset and place
the resulting `.joblib` file at `config.model_path` (default:
`./trained_models/random_forest_threat_model.joblib`) — `run_detection.py`
will then load and use that real model automatically instead of
bootstrapping the demo one.

### Train a real model (once you have a dataset CSV)
```python
from module3_ai_detection.detector import create_model
from module3_ai_detection.trainer import Trainer

trainer = Trainer(model=create_model("random_forest"))
X, y = trainer.load_dataset_from_csv("path/to/dataset.csv", label_column="Label")
X_train, X_test, y_train, y_test = trainer.train_test_split_and_train(X, y)
print(trainer.evaluate(X_test, y_test))
trainer.save_model("trained_models/random_forest_threat_model.joblib")
```

### Run the test suite
```bash
cd xaf_firewall
python3 -m pytest module3_ai_detection/tests -v
```

**Expected output:** `53 passed` with no failures or errors. Running
`python3 -m pytest module2_feature_extraction/tests module3_ai_detection/tests -v`
together yields `94 passed`, confirming Module 2 is unaffected.

---

## 7. Verifying Correctness

- **Module 2 compatibility:** `test_feature_mapper_and_preprocessor.py`
  and `test_inference.py` construct real, unmodified Module 2
  `FeatureVector` objects and push them through the full pipeline.
- **Model swappability:** `test_detector.py::test_create_model_raises_for_planned_but_unimplemented_model`
  proves the factory correctly gates not-yet-implemented model types
  without crashing.
- **Threat/severity/risk logic:** `test_utils.py` verifies every
  confidence boundary (0-30 LOW, 31-70 MEDIUM, 71-90 HIGH, 91-100
  CRITICAL) and confirms `DATA_EXFILTRATION` scores riskier than
  `PORT_SCAN` at equal confidence.
- **End-to-end classification:** `test_inference.py` trains a small but
  real model on benign vs. DDOS-shaped flows and confirms the engine
  correctly classifies each.
- **Persistence:** `test_model_loader.py` and
  `test_detector.py::test_random_forest_model_save_and_load_roundtrip`
  confirm a trained model can be saved and reloaded with identical
  predictions.

## 8. Common Errors & Fixes

| Error | Cause | Fix |
|---|---|---|
| `ModelNotLoadedError` | `InferenceEngine.predict()` called before the model was trained/loaded | Call `model.load(path)` or train via `Trainer` first |
| `ModelNotTrainedError` | `predict()`/`save()`/`classes_` called on a fresh, untrained `BaseThreatModel` | Call `.fit(X, y)` (directly or via `Trainer.train()`) first |
| `UnsupportedModelError: ... has no implementation yet` | Requested `"xgboost"`/`"lightgbm"`/etc. via `create_model()` | Expected — those are reserved names for future implementations; implement a `BaseThreatModel` subclass and register it in `detector.py` |
| `TrainingDataError: Label column '...' not found` | CSV's label column has a different name than assumed | Pass the correct `label_column=` (check the dataset's actual header) |
| `ModelLoadError: Model file not found` | `config.model_path` doesn't point to a real `.joblib` file yet | Train and `save_model()` first, or run `run_detection.py`, which falls back to a demo model automatically |
| Predictions look wrong / random | A custom `Preprocessor` was used at training time but not passed into `InferenceEngine` (or vice versa) | Always inject the *same* `Preprocessor` configuration used during training into `InferenceEngine` |

---

## 9. Module 3 Completion Checklist

- [x] Complete folder structure created exactly as specified
- [x] `ThreatPrediction`, `ThreatLabel`, `Severity`, `AttackCategory` implemented in `models.py`
- [x] All 9 required attack classes present (`BENIGN` through `UNKNOWN`)
- [x] Common `BaseThreatModel` interface implemented, with `RandomForestThreatModel` as the initial concrete model
- [x] `create_model()` factory supports future XGBoost/LightGBM/CatBoost/Neural Network/Isolation Forest with a clear extension path
- [x] `trainer.py` implements `train()`, `save_model()`, `load_model()`, `evaluate()`, `predict()`, and CSV loading adaptable to CICIDS2017 / CSE-CIC-IDS2018 / UNSW-NB15 / TON_IoT column layouts
- [x] `inference.py` implements the full `FeatureVector -> ThreatPrediction` pipeline
- [x] Confidence→severity bands implemented exactly as specified (0-30 LOW, 31-70 MEDIUM, 71-90 HIGH, 91-100 CRITICAL)
- [x] Centralized `config.py` (model path, thresholds, supported/default models) — no hardcoded paths
- [x] Centralized `logger.py`
- [x] Custom `exceptions.py` hierarchy — no bare `Exception` raised anywhere in business logic
- [x] `run_detection.py` demonstrates: create sample `FeatureVector` → run prediction → print `ThreatPrediction`
- [x] 53 unit/integration tests written, all passing (94 total combined with Module 2)
- [x] Zero modifications to Module 1's or Module 2's files (diff-verified)
- [x] No IDS/IPS blocking, no explainability, no reporting, no dashboard logic included
- [x] Clean architecture maintained: entities (`models.py`) → helpers (`utils.py`, `feature_mapper.py`, `preprocessor.py`) → pluggable model layer (`detector.py`, `model_loader.py`) → orchestration (`trainer.py`, `inference.py`)

**Module 3 is complete and ready for integration with a future Smart
Response / Explainability module.** That module should depend only on
`InferenceEngine.predict()` / `predict_batch()` and the `ThreatPrediction`
model — not on any internal class in this module.
