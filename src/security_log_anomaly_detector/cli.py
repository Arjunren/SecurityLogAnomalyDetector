"""Train a benign baseline, report metrics, and score log windows."""

import argparse
import json
from pathlib import Path

from security_log_anomaly_detector.artifact import load_model
from security_log_anomaly_detector.features import LogWindow
from security_log_anomaly_detector.training import train


def main() -> None:
    parser = argparse.ArgumentParser(description="Security log anomaly detection")
    commands = parser.add_subparsers(dest="command", required=True)
    training = commands.add_parser("train")
    training.add_argument("--dataset", type=Path, required=True)
    training.add_argument("--model", type=Path, default=Path("models/model.json"))
    training.add_argument("--config", type=Path, default=Path("configs/training.json"))
    training.add_argument("--version", default="1.0.0")
    inference = commands.add_parser("predict")
    inference.add_argument("--model", type=Path, default=Path("models/model.json"))
    inference.add_argument("--observation", type=Path, required=True, help="Local JSON log window")
    evaluation = commands.add_parser("evaluate")
    evaluation.add_argument("--metadata", type=Path, default=Path("models/model.metadata.json"))
    args = parser.parse_args()
    if args.command == "train":
        result = train(args.dataset, args.model, args.config, args.version)
    elif args.command == "predict":
        observation = LogWindow.model_validate_json(args.observation.read_text(encoding="utf-8"))
        result = load_model(args.model).predict(observation)
    else:
        result = json.loads(args.metadata.read_text(encoding="utf-8"))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
