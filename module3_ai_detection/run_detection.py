"""
run_detection.py (Module 3)
------------------------------
Demo / example entry point for the AI Threat Detection Engine.

WHAT THIS SCRIPT DOES
1. Obtains a trained model -- either by loading a previously saved model
   artifact from disk (config.model_path), or, if none exists yet, by
   bootstrapping a small synthetic demo model in-memory so this script
   runs end-to-end with zero external dependencies (no dataset, no
   pretrained file required).
2. Builds a sample FeatureVector using Module 2's own, unmodified model
   class (proving real compatibility, not a duplicated/mocked type).
3. Runs it through InferenceEngine.predict().
4. Prints the resulting ThreatPrediction.

IMPORTANT: The bootstrapped demo model in bootstrap_demo_model() is
trained on a handful of synthetic, hand-crafted rows purely so this
script is runnable out of the box. It is NOT a real trained model and
must NOT be used for real threat detection. For production use, train a
real model via trainer.Trainer against a real dataset (CICIDS2017,
CSE-CIC-IDS2018, UNSW-NB15, TON_IoT, etc.) and load it via
model.load(config.model_path) instead of calling bootstrap_demo_model().

Run with:  python -m module3_ai_detection.run_detection
"""

import time

import numpy as np

from module2_feature_extraction.models import (
    FeatureVector, PacketDirection, ConnectionState,
)

from module3_ai_detection.config import DetectionConfig, DEFAULT_CONFIG
from module3_ai_detection.detector import BaseThreatModel, create_model
from module3_ai_detection.preprocessor import Preprocessor
from module3_ai_detection.inference import InferenceEngine
from module3_ai_detection.model_loader import model_exists
from module3_ai_detection.logger import get_logger

logger = get_logger("module3_ai_detection.run_detection")


def bootstrap_demo_model(config: DetectionConfig) -> BaseThreatModel:
    """
    Train a tiny, synthetic demo model purely so this script can run
    end-to-end without a real dataset or a pretrained model file.

    THIS IS NOT A REAL DETECTION MODEL. It is fit on a handful of
    hand-crafted rows covering each AttackCategory, just enough for
    predict_proba() to return sensible-shaped output for the demo.

    Args:
        config: DetectionConfig supplying the default model type to build.

    Returns:
        A trained (but not production-quality) BaseThreatModel instance.
    """
    logger.warning(
        "No trained model found at '%s'. Bootstrapping a small in-memory "
        "DEMO model instead -- this is for demonstration only and must "
        "NOT be used for real threat detection. Train a real model via "
        "trainer.Trainer against a real dataset for production use.",
        config.model_path,
    )

    preprocessor = Preprocessor()
    model = create_model(config.default_model)

    # Hand-crafted synthetic rows: [packet_length, flow_duration, packet_rate,
    # byte_rate, payload_size, avg_packet_size, total_packets_in_flow,
    # total_bytes, inter_arrival_time, ttl, window_size, avg_flow_time,
    # protocol, direction, connection_state] -- loosely caricaturing each
    # attack category's typical traffic shape, purely for demo purposes.
    synthetic_rows = [
        # (raw_features_dict, label)
        ({"packet_length": 500, "flow_duration": 5.0, "packet_rate": 2.0,
          "byte_rate": 200.0, "payload_size": 460, "avg_packet_size": 500,
          "total_packets_in_flow": 10, "total_bytes": 5000,
          "inter_arrival_time": 0.5, "ttl": 64, "window_size": 65535,
          "avg_flow_time": 5.0, "protocol": "TCP", "direction": "OUTBOUND",
          "connection_state": "ESTABLISHED"}, "BENIGN"),
        ({"packet_length": 60, "flow_duration": 0.05, "packet_rate": 500.0,
          "byte_rate": 3000.0, "payload_size": 0, "avg_packet_size": 60,
          "total_packets_in_flow": 200, "total_bytes": 12000,
          "inter_arrival_time": 0.002, "ttl": 64, "window_size": 1024,
          "avg_flow_time": 0.05, "protocol": "TCP", "direction": "OUTBOUND",
          "connection_state": "NEW"}, "PORT_SCAN"),
        ({"packet_length": 1400, "flow_duration": 1.0, "packet_rate": 5000.0,
          "byte_rate": 7000000.0, "payload_size": 1360, "avg_packet_size": 1400,
          "total_packets_in_flow": 5000, "total_bytes": 7000000,
          "inter_arrival_time": 0.0002, "ttl": 32, "window_size": 65535,
          "avg_flow_time": 1.0, "protocol": "UDP", "direction": "INBOUND",
          "connection_state": "STATELESS"}, "DDOS"),
        ({"packet_length": 80, "flow_duration": 10.0, "packet_rate": 20.0,
          "byte_rate": 1600.0, "payload_size": 40, "avg_packet_size": 80,
          "total_packets_in_flow": 200, "total_bytes": 16000,
          "inter_arrival_time": 0.05, "ttl": 64, "window_size": 512,
          "avg_flow_time": 10.0, "protocol": "TCP", "direction": "INBOUND",
          "connection_state": "ESTABLISHED"}, "BRUTE_FORCE"),
        ({"packet_length": 900, "flow_duration": 3.0, "packet_rate": 3.0,
          "byte_rate": 900.0, "payload_size": 860, "avg_packet_size": 900,
          "total_packets_in_flow": 9, "total_bytes": 8100,
          "inter_arrival_time": 0.3, "ttl": 55, "window_size": 65535,
          "avg_flow_time": 3.0, "protocol": "TCP", "direction": "OUTBOUND",
          "connection_state": "ESTABLISHED"}, "MALWARE"),
        ({"packet_length": 700, "flow_duration": 2.0, "packet_rate": 1.5,
          "byte_rate": 350.0, "payload_size": 660, "avg_packet_size": 700,
          "total_packets_in_flow": 3, "total_bytes": 2100,
          "inter_arrival_time": 0.6, "ttl": 128, "window_size": 8192,
          "avg_flow_time": 2.0, "protocol": "TCP", "direction": "INBOUND",
          "connection_state": "ESTABLISHED"}, "PHISHING"),
        ({"packet_length": 200, "flow_duration": 60.0, "packet_rate": 0.5,
          "byte_rate": 100.0, "payload_size": 160, "avg_packet_size": 200,
          "total_packets_in_flow": 30, "total_bytes": 6000,
          "inter_arrival_time": 2.0, "ttl": 64, "window_size": 65535,
          "avg_flow_time": 60.0, "protocol": "TCP", "direction": "OUTBOUND",
          "connection_state": "ESTABLISHED"}, "BOTNET"),
        ({"packet_length": 1500, "flow_duration": 30.0, "packet_rate": 10.0,
          "byte_rate": 15000.0, "payload_size": 1460, "avg_packet_size": 1500,
          "total_packets_in_flow": 300, "total_bytes": 450000,
          "inter_arrival_time": 0.1, "ttl": 64, "window_size": 65535,
          "avg_flow_time": 30.0, "protocol": "TCP", "direction": "OUTBOUND",
          "connection_state": "ESTABLISHED"}, "DATA_EXFILTRATION"),
    ]

    X = preprocessor.transform_batch([row for row, _ in synthetic_rows])
    y = np.array([label for _, label in synthetic_rows])

    model.fit(X, y)
    return model


def build_sample_feature_vector() -> FeatureVector:
    """
    Construct a single, realistic-looking FeatureVector using Module 2's
    own (unmodified) FeatureVector class, to demonstrate genuine
    Module 2 -> Module 3 compatibility rather than a mocked/duplicated type.

    Returns:
        A FeatureVector resembling a moderately suspicious TCP flow.
    """
    now = time.time()
    return FeatureVector(
        src_ip="192.168.1.25",
        dst_ip="203.0.113.77",
        src_port=51823,
        dst_port=445,
        protocol="TCP",
        packet_length=750,
        timestamp=now,
        ttl=64,
        tcp_flags="PA",
        window_size=8192,
        direction=PacketDirection.OUTBOUND,
        flow_id="demo-flow-0001",
        flow_duration=4.2,
        connection_state=ConnectionState.ESTABLISHED,
        total_packets_in_flow=25,
        total_bytes=18500,
        avg_packet_size=740.0,
        payload_size=710,
        packet_arrival_time=now,
        inter_arrival_time=0.18,
        packet_rate=6.0,
        byte_rate=4400.0,
        avg_flow_time=4.2,
    )


def main() -> None:
    """
    Entry point: obtain a model (loading a saved one if available, else
    bootstrapping a demo model), build a sample FeatureVector, run
    prediction, and print the resulting ThreatPrediction.
    """
    config = DEFAULT_CONFIG

    model = create_model(config.default_model)
    if model_exists(config.model_path):
        logger.info("Loading trained model from %s", config.model_path)
        model.load(config.model_path)
    else:
        model = bootstrap_demo_model(config)

    inference_engine = InferenceEngine(model=model, config=config)

    sample_feature_vector = build_sample_feature_vector()
    print("=== Sample FeatureVector (from Module 2) ===")
    print(sample_feature_vector)
    print()

    prediction = inference_engine.predict(sample_feature_vector)

    print("=== ThreatPrediction (from Module 3) ===")
    print(prediction)
    print()
    print("Full details:")
    for key, value in prediction.to_dict().items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
