from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
import numpy as np
import logging
import pickle
import os

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = 'baseline_anomaly_model.pkl'


class MLAnomalyDetector:

    def __init__(self, contamination: float = 0.05):
        self.contamination   = contamination
        self.model           = None
        self.scaler          = None
        self.feature_columns = None
        self.is_trained      = False

    def _prepare_features(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return pd.DataFrame()

        features = pd.DataFrame(index=df.index)

        if 'size'     in df.columns: features['packet_size'] = df['size']
        if 'protocol' in df.columns: features['protocol']    = df['protocol']
        if 'ttl'      in df.columns: features['ttl']         = df['ttl']

        if 'timestamp' in df.columns:
            ts = pd.to_datetime(df['timestamp'])
            features['hour']        = ts.dt.hour
            features['minute']      = ts.dt.minute
            features['day_of_week'] = ts.dt.dayofweek

        if 'source_ip' in df.columns:
            ip_counts = df.groupby('source_ip').size()
            features['connection_frequency'] = df['source_ip'].map(ip_counts)

        if 'dest_port' in df.columns:
            features['dest_port']      = df['dest_port']
            features['is_common_port'] = df['dest_port'].isin(
                [20, 21, 22, 25, 53, 80, 110, 143, 443, 587, 993, 995]
            ).astype(int)

        if 'tcp_flags' in df.columns:
            features['has_syn'] = df['tcp_flags'].str.contains('S', na=False).astype(int)
            features['has_ack'] = df['tcp_flags'].str.contains('A', na=False).astype(int)
            features['has_fin'] = df['tcp_flags'].str.contains('F', na=False).astype(int)
            features['has_rst'] = df['tcp_flags'].str.contains('R', na=False).astype(int)

        if 'source_ip' in df.columns and 'destination_ip' in df.columns:
            dest_counts = df.groupby('source_ip')['destination_ip'].nunique()
            features['unique_destinations'] = df['source_ip'].map(dest_counts)

        for col in features.columns:
            features[col] = pd.to_numeric(features[col], errors='coerce')
        features.fillna(0, inplace=True)

        self.feature_columns = features.columns.tolist()
        return features

    def train(self, baseline_df: pd.DataFrame, auto_save: bool = False,
              save_path: str = DEFAULT_MODEL_PATH) -> bool:
        logger.info("Training on baseline data (%d packets)...", len(baseline_df))

        features = self._prepare_features(baseline_df)
        if features.empty:
            logger.error("No features could be extracted from baseline_df.")
            return False

        self.scaler = StandardScaler()
        scaled      = self.scaler.fit_transform(features)

        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=200,   # more trees = stabler scores
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(scaled)
        self.is_trained = True
        logger.info("Baseline training complete.")

        if auto_save:
            self.save_model(save_path)

        return True

    def detect(self, df: pd.DataFrame) -> pd.DataFrame:
        if not self.is_trained:
            raise RuntimeError("Call train() or load_model() before detect().")

        if df.empty:
            logger.warning("detect() received an empty DataFrame.")
            return df.copy()

        features = self._prepare_features(df)

        # Align to training columns — fill any missing ones with 0
        for col in self.feature_columns:
            if col not in features.columns:
                features[col] = 0
        features = features[self.feature_columns]

        scaled      = self.scaler.transform(features)
        predictions = self.model.predict(scaled)       # 1 = normal, -1 = anomaly
        scores      = self.model.score_samples(scaled)

        out = df.copy()
        out['is_anomaly']    = predictions == -1
        out['anomaly_score'] = scores

        n_anomalies = int((predictions == -1).sum())
        logger.info("Detected %d anomalies out of %d packets (%.1f%%)",
                    n_anomalies, len(df), 100 * n_anomalies / len(df))
        return out

    def get_anomalies(self, df: pd.DataFrame) -> pd.DataFrame:
        if 'is_anomaly' not in df.columns:
            df = self.detect(df)
        return df[df['is_anomaly']].copy()

    def save_model(self, filepath: str = DEFAULT_MODEL_PATH) -> bool:
        if not self.is_trained:
            logger.warning("Nothing to save — model has not been trained.")
            return False
        payload = {
            'model':           self.model,
            'scaler':          self.scaler,
            'feature_columns': self.feature_columns,
            'contamination':   self.contamination,
        }
        with open(filepath, 'wb') as fh:
            pickle.dump(payload, fh)
        logger.info("Model saved -> %s", filepath)
        return True

    def load_model(self, filepath: str = DEFAULT_MODEL_PATH) -> bool:
        if not os.path.exists(filepath):
            logger.error("Model file not found: %s", filepath)
            return False
        with open(filepath, 'rb') as fh:
            payload = pickle.load(fh)
        self.model           = payload['model']
        self.scaler          = payload['scaler']
        self.feature_columns = payload['feature_columns']
        self.contamination   = payload.get('contamination', self.contamination)
        self.is_trained      = True
        logger.info("Model loaded <- %s", filepath)
        return True

    def retrain(self, new_baseline_df: pd.DataFrame, **kwargs) -> bool:
        logger.info("Retraining baseline model...")
        self.is_trained = False
        return self.train(new_baseline_df, **kwargs)


if __name__ == "__main__":
    baseline = pd.DataFrame({
        'timestamp':      pd.date_range('2024-01-01', periods=800, freq='1S'),
        'source_ip':      ['192.168.1.10'] * 800,
        'destination_ip': ['8.8.8.8'] * 800,
        'dest_port':      [80] * 800,
        'size':           [1500] * 800,
        'protocol':       [6] * 800,
        'ttl':            [64] * 800,
    })

    live = pd.DataFrame({
        'timestamp':      pd.date_range('2024-01-02', periods=200, freq='1S'),
        'source_ip':      ['192.168.1.10'] * 180 + ['10.99.99.99'] * 20,
        'destination_ip': ['8.8.8.8'] * 200,
        'dest_port':      [80] * 180 + list(range(1, 21)),
        'size':           [1500] * 180 + [9000] * 20,
        'protocol':       [6] * 200,
        'ttl':            [64] * 200,
    })

    detector  = MLAnomalyDetector(contamination=0.05)
    detector.train(baseline, auto_save=True)

    results   = detector.detect(live)
    anomalies = detector.get_anomalies(results)

    print(f"\n=== ML Anomaly Detection Results ===")
    print(f"Live packets : {len(results)}")
    print(f"Anomalies    : {len(anomalies)}")
    print("\nTop anomalous packets:")
    print(anomalies[['source_ip', 'dest_port', 'size', 'anomaly_score']].head(10))