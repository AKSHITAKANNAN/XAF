import csv
import os

from module1_packet_capture.capture import PacketCaptureEngine
from module2_feature_extraction.feature_extractor import FeatureExtractionEngine


OUTPUT_FILE = "datasets/real_traffic_features.csv"


def main():

    print("=" * 60)
    print("XAF - REAL TRAFFIC FEATURE EXTRACTION")
    print("=" * 60)

    os.makedirs("datasets", exist_ok=True)

    feature_engine = FeatureExtractionEngine()

    rows = []

    def on_packet(packet_data):

        try:
            # Module 1 PacketData
            print("\n[MODULE 1] Packet captured")
            print(packet_data)

            # Module 2 Feature Extraction
            feature_vector = feature_engine.extract(packet_data)

            print("[MODULE 2] Feature extracted")
            print(feature_vector)

            # Convert FeatureVector into dictionary
            if hasattr(feature_vector, "to_dict"):
                row = feature_vector.to_dict()
            else:
                row = vars(feature_vector)

            rows.append(row)

        except Exception as e:
            print("[ERROR] Feature extraction failed:", e)

    # IMPORTANT:
    # Use your working default interface.
    capture_engine = PacketCaptureEngine(
        on_packet=on_packet
    )

    print("\nStarting real packet capture...")
    print("Generate some normal network traffic now.")
    print("For example:")
    print("  - Open Chrome")
    print("  - Visit a few websites")
    print("  - Search something")
    print("  - Open YouTube")
    print("  - Run a ping")
    print("\nCapturing 50 packets...\n")

    capture_engine.start(
        packet_count=50,
        timeout=60
    )

    if not rows:
        print("\nNo feature vectors were generated.")
        return

    # Get all feature names
    fieldnames = sorted(
        set().union(*(row.keys() for row in rows))
    )

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(rows)

    print("\n" + "=" * 60)
    print("REAL FEATURE EXTRACTION COMPLETE")
    print("=" * 60)

    print(f"Packets/features generated : {len(rows)}")
    print(f"Dataset saved to            : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()