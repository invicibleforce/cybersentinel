import argparse
import logging
import threading
import time
import os

import pandas as pd

from packet_capture import PacketCapture, check_privileges
from threat_detector import ThreatDetector
from ml_anomaly_detector import MLAnomalyDetector, DEFAULT_MODEL_PATH
from threat_intelligence import ThreatIntelligence
from dashboard import SecurityDashboard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("main")


def run_pipeline(args, ml_detector, threat_intel, shared_state):
    capturer = PacketCapture(auto_check_privileges=False)
    detector = ThreatDetector()

    logger.info("Pipeline started. Capturing %d packets per cycle on interface: %s",
                args.count, args.interface or "default")

    cycle = 0
    while True:
        cycle += 1
        logger.info("Cycle %d", cycle)

        df = capturer.start_capture(count=args.count, interface=args.interface)

        if df.empty:
            logger.warning("No packets captured this cycle. Retrying in 5s...")
            time.sleep(5)
            continue

        alerts = detector.run_all_detections(df)
        logger.info("Rule-based alerts: %d", len(alerts))

        if ml_detector.is_trained:
            df = ml_detector.detect(df)
            anomaly_count = int(df['is_anomaly'].sum()) if 'is_anomaly' in df.columns else 0
            logger.info("ML anomalies flagged: %d", anomaly_count)
        else:
            logger.warning("ML model not trained — skipping. Run with --baseline first.")

        if not args.no_intel and threat_intel is not None:
            suspicious_ips = _extract_suspicious_ips(alerts, df)
            if suspicious_ips:
                logger.info("Checking %d IPs against threat intelligence...", len(suspicious_ips))
                malicious = threat_intel.scan_ip_list(suspicious_ips, limit=5)
                if malicious:
                    report = threat_intel.generate_report(malicious)
                    logger.info("\n%s", report)
                    for hit in malicious:
                        alerts.append({
                            'timestamp':      pd.Timestamp.now(),
                            'type':           'Known Malicious IP',
                            'severity':       'CRITICAL',
                            'source_ip':      hit['ip'],
                            'description':    (f"{hit['ip']} has AbuseIPDB score "
                                               f"{hit['abuse_score']}/100 "
                                               f"({hit['total_reports']} reports)"),
                            'recommendation': 'Block immediately at firewall level.'
                        })

        with shared_state['lock']:
            shared_state['df']     = df
            shared_state['alerts'] = alerts

        logger.info("Cycle %d complete. Dashboard updated.", cycle)


def _extract_suspicious_ips(alerts, df):
    ips = set()
    for alert in alerts:
        if alert.get('severity') in ('HIGH', 'CRITICAL'):
            if 'source_ip' in alert:
                ips.add(alert['source_ip'])
    return list(ips)[:10]  # cap at 10 to respect API rate limits


def train_baseline(args):
    logger.info("=== BASELINE TRAINING MODE ===")
    logger.info("Capturing %d packets. Make sure no attacks are happening right now!",
                args.baseline_count)

    capturer = PacketCapture(auto_check_privileges=False)
    df = capturer.start_capture(count=args.baseline_count, interface=args.interface)

    if df.empty:
        logger.error("No packets captured for baseline. Aborting.")
        return False

    detector = MLAnomalyDetector(contamination=0.05)
    success  = detector.train(df, auto_save=True, save_path=DEFAULT_MODEL_PATH)

    if success:
        logger.info("Baseline model saved to: %s", DEFAULT_MODEL_PATH)
        logger.info("Now run `sudo python main.py` to start monitoring.")
    return success


def main():
    parser = argparse.ArgumentParser(description="CyberSentinel Network Monitor")
    parser.add_argument("--count",          type=int, default=200)
    parser.add_argument("--interface",      type=str, default=None)
    parser.add_argument("--baseline",       action="store_true")
    parser.add_argument("--baseline-count", type=int, default=500)
    parser.add_argument("--no-intel",       action="store_true")
    parser.add_argument("--port",           type=int, default=8050)
    args = parser.parse_args()

    if not check_privileges(raise_on_failure=False):
        return

    if args.baseline:
        train_baseline(args)
        return

    ml_detector = MLAnomalyDetector()
    if os.path.exists(DEFAULT_MODEL_PATH):
        ml_detector.load_model(DEFAULT_MODEL_PATH)
    else:
        logger.warning(
            "No baseline model found (%s). "
            "Run `sudo python main.py --baseline` first for ML detection.",
            DEFAULT_MODEL_PATH
        )

    threat_intel = None
    if not args.no_intel:
        abuseipdb_key = os.environ.get("ABUSEIPDB_KEY")
        vt_key        = os.environ.get("VT_KEY")
        if abuseipdb_key or vt_key:
            threat_intel = ThreatIntelligence(abuseipdb_key=abuseipdb_key, virustotal_key=vt_key)
            logger.info("Threat intelligence: enabled")
        else:
            logger.info("Threat intelligence: disabled (set ABUSEIPDB_KEY / VT_KEY to enable).")

    shared_state = {
        'df':     pd.DataFrame(),
        'alerts': [],
        'lock':   threading.Lock(),
    }

    def get_latest_data():
        with shared_state['lock']:
            return shared_state['df'].copy(), list(shared_state['alerts'])

    # daemon=True ensures the thread exits when the main process exits
    pipeline_thread = threading.Thread(
        target=run_pipeline,
        args=(args, ml_detector, threat_intel, shared_state),
        daemon=True,
        name="pipeline"
    )
    pipeline_thread.start()
    logger.info("Pipeline thread started.")
    logger.info("Starting dashboard at http://127.0.0.1:%d", args.port)

    dashboard = SecurityDashboard(data_callback=get_latest_data)
    dashboard.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()