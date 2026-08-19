from module1_packet_capture.capture import PacketCaptureEngine
from module2_feature_extraction.feature_extractor import FeatureExtractionEngine


feature_engine = FeatureExtractionEngine()


def process_packet(packet_data):
    try:
        feature_vector = feature_engine.extract(packet_data)

        print("\n========== REAL PACKET ==========")
        print(packet_data)

        print("\n========== EXTRACTED FEATURES ==========")
        print(feature_vector)

        print("\n========== FEATURE DICTIONARY ==========")
        print(feature_vector.to_dict())

    except Exception as e:
        print(f"[ERROR] Feature extraction failed: {e}")


if __name__ == "__main__":

    print("==========================================")
    print(" XAF REAL-TIME FEATURE EXTRACTION")
    print(" Module 1 -> Module 2")
    print("==========================================")
    print("Capturing 30 packets...")
    print("Generate some network traffic while this is running.")
    print()

    capture_engine = PacketCaptureEngine(
        on_packet=process_packet
    )

    capture_engine.start(
        packet_count=30,
        timeout=60
    )

    print("\n==========================================")
    print("CAPTURE COMPLETE")
    print("==========================================")