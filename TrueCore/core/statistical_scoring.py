import math
from collections import defaultdict
from datetime import datetime, timezone

from TrueCore.core.case_memory import get_recent_packet_events, get_recent_packet_runs, json_loads, parse_issues


TERMINAL_SUCCESS_OUTCOMES = {"approved"}
TERMINAL_NEGATIVE_OUTCOMES = {"denied"}
TERMINAL_OUTCOMES = TERMINAL_SUCCESS_OUTCOMES | TERMINAL_NEGATIVE_OUTCOMES
OUTCOME_FEATURE_KEYS = [
    "score_norm",
    "packet_confidence",
    "issue_count",
    "form_count",
    "missing_item_count",
    "review_flag_count",
    "scan_quality_score",
    "ocr_confidence",
]
_OUTCOME_MODEL_CACHE = {"signature": None, "model": None}


def clamp(value, lower=0.0, upper=1.0):
    return max(lower, min(float(value), upper))


def sigmoid(value):
    value = max(-35.0, min(35.0, float(value)))
    return 1.0 / (1.0 + math.exp(-value))


def logit(probability):
    probability = clamp(probability, 1e-6, 1.0 - 1e-6)
    return math.log(probability / (1.0 - probability))


def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return float(default)


def parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def utc_now():
    return datetime.now(timezone.utc)


def normalize_rate(value):
    numeric = safe_float(value, 0.0)
    if numeric > 1.0:
        numeric /= 100.0
    return clamp(numeric, 0.0, 1.0)


def wilson_interval(successes, total, z=1.96):
    try:
        successes = int(successes or 0)
        total = int(total or 0)
    except Exception:
        return None

    if total <= 0:
        return None

    p = successes / total
    z2 = z ** 2
    denominator = 1.0 + (z2 / total)
    center = (p + (z2 / (2.0 * total))) / denominator
    margin = (z / denominator) * math.sqrt((p * (1.0 - p) / total) + (z2 / (4.0 * (total ** 2))))
    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)
    return {
        "lower": round(lower, 3),
        "upper": round(upper, 3),
        "width": round(upper - lower, 3),
    }


def beta_smoothed_rate(successes, total, alpha=1.0, beta=1.0):
    denominator = float(total or 0) + alpha + beta
    if denominator <= 0:
        return 0.0
    return round((float(successes or 0.0) + alpha) / denominator, 3)


def empirical_bayes_average(values, prior_mean, prior_weight=5.0):
    values = [safe_float(value, None) for value in values]
    values = [value for value in values if value is not None]
    if not values:
        return round(safe_float(prior_mean, 0.0), 1)

    sample_mean = sum(values) / len(values)
    shrunk = ((prior_weight * safe_float(prior_mean, 0.0)) + (len(values) * sample_mean)) / (prior_weight + len(values))
    return round(shrunk, 1)


def midrank_percentile(score, scores):
    scores = [safe_float(item, None) for item in scores]
    scores = [item for item in scores if item is not None]
    if not scores:
        return 0.0

    score = safe_float(score, 0.0)
    below = sum(1 for item in scores if item < score)
    equal = sum(1 for item in scores if item == score)
    return round((below + (0.5 * equal)) / len(scores), 2)


def brier_score(labels, probabilities):
    pairs = [
        (int(label), clamp(probability))
        for label, probability in zip(labels, probabilities)
        if label in {0, 1} and probability is not None
    ]
    if not pairs:
        return None
    return round(sum((probability - label) ** 2 for label, probability in pairs) / len(pairs), 4)


def log_loss(labels, probabilities):
    pairs = [
        (int(label), clamp(probability, 1e-6, 1.0 - 1e-6))
        for label, probability in zip(labels, probabilities)
        if label in {0, 1} and probability is not None
    ]
    if not pairs:
        return None
    total = 0.0
    for label, probability in pairs:
        total += -(label * math.log(probability) + ((1 - label) * math.log(1.0 - probability)))
    return round(total / len(pairs), 4)


def roc_auc(labels, probabilities):
    positives = []
    negatives = []
    for label, probability in zip(labels, probabilities):
        if probability is None or label not in {0, 1}:
            continue
        if int(label) == 1:
            positives.append(float(probability))
        else:
            negatives.append(float(probability))

    if not positives or not negatives:
        return None

    wins = 0.0
    total = len(positives) * len(negatives)
    for positive in positives:
        for negative in negatives:
            if positive > negative:
                wins += 1.0
            elif positive == negative:
                wins += 0.5

    return round(wins / total, 4)


def calibration_curve(labels, probabilities, bins=5):
    pairs = [
        (int(label), clamp(probability))
        for label, probability in zip(labels, probabilities)
        if label in {0, 1} and probability is not None
    ]
    if not pairs:
        return []

    bins = max(2, int(bins or 5))
    bucketed = [[] for _ in range(bins)]
    for label, probability in pairs:
        index = min(int(probability * bins), bins - 1)
        bucketed[index].append((label, probability))

    curve = []
    for index, bucket in enumerate(bucketed):
        if not bucket:
            continue
        labels_in_bucket = [label for label, _ in bucket]
        probabilities_in_bucket = [probability for _, probability in bucket]
        success_count = sum(labels_in_bucket)
        total = len(bucket)
        actual_rate = success_count / total
        curve.append({
            "bin": index + 1,
            "range": [round(index / bins, 2), round((index + 1) / bins, 2)],
            "count": total,
            "average_predicted": round(sum(probabilities_in_bucket) / total, 3),
            "average_actual": round(actual_rate, 3),
            "interval": wilson_interval(success_count, total),
        })
    return curve


def expected_calibration_error(curve):
    if not curve:
        return None
    total = sum(int(item.get("count") or 0) for item in curve)
    if total <= 0:
        return None
    error = 0.0
    for item in curve:
        weight = (int(item.get("count") or 0) / total)
        error += weight * abs(safe_float(item.get("average_predicted"), 0.0) - safe_float(item.get("average_actual"), 0.0))
    return round(error, 4)


def fit_platt_scaler(probabilities, labels, epochs=500, learning_rate=0.05, l2=0.001):
    pairs = [
        (logit(probability), int(label))
        for label, probability in zip(labels, probabilities)
        if label in {0, 1} and probability is not None
    ]
    if len(pairs) < 12:
        return None

    positives = sum(1 for _, label in pairs if label == 1)
    negatives = len(pairs) - positives
    if positives == 0 or negatives == 0:
        return None

    slope = 1.0
    intercept = logit(beta_smoothed_rate(positives, len(pairs), alpha=1.0, beta=1.0))
    sample_size = len(pairs)

    for _ in range(epochs):
        grad_slope = 0.0
        grad_intercept = 0.0
        for feature, label in pairs:
            prediction = sigmoid((slope * feature) + intercept)
            error = prediction - label
            grad_slope += error * feature
            grad_intercept += error
        grad_slope = (grad_slope / sample_size) + (l2 * slope)
        grad_intercept /= sample_size
        slope -= learning_rate * grad_slope
        intercept -= learning_rate * grad_intercept

    return {
        "slope": round(slope, 6),
        "intercept": round(intercept, 6),
        "sample_size": sample_size,
        "method": "platt_scaling_v1",
    }


def apply_platt_scaler(probability, scaler):
    if not scaler:
        return clamp(probability)
    transformed = logit(probability)
    calibrated = sigmoid((safe_float(scaler.get("slope"), 1.0) * transformed) + safe_float(scaler.get("intercept"), 0.0))
    return round(clamp(calibrated), 4)


def ewma_series(values, alpha=0.25):
    numeric_values = [safe_float(value, None) for value in values]
    numeric_values = [value for value in numeric_values if value is not None]
    if not numeric_values:
        return []

    alpha = clamp(alpha, 0.01, 0.99)
    smoothed = []
    current = numeric_values[0]
    for value in numeric_values:
        current = (alpha * value) + ((1.0 - alpha) * current)
        smoothed.append(round(current, 3))
    return smoothed


def cusum_series(values, target=None, allowance=None, threshold=None):
    numeric_values = [safe_float(value, None) for value in values]
    numeric_values = [value for value in numeric_values if value is not None]
    if not numeric_values:
        return {
            "positive": [],
            "negative": [],
            "target": None,
            "signal": "insufficient_data",
        }

    mean = sum(numeric_values) / len(numeric_values)
    variance = sum((value - mean) ** 2 for value in numeric_values) / max(len(numeric_values), 1)
    stddev = math.sqrt(variance) or 1.0
    target = mean if target is None else safe_float(target, mean)
    allowance = stddev * 0.25 if allowance is None else safe_float(allowance, stddev * 0.25)
    threshold = stddev * 1.5 if threshold is None else safe_float(threshold, stddev * 1.5)

    positive = []
    negative = []
    pos = 0.0
    neg = 0.0
    signal = "stable"
    for value in numeric_values:
        pos = max(0.0, pos + (value - target - allowance))
        neg = min(0.0, neg + (value - target + allowance))
        positive.append(round(pos, 3))
        negative.append(round(neg, 3))
        if pos >= threshold:
            signal = "upward_shift"
        elif abs(neg) >= threshold:
            signal = "downward_shift"

    return {
        "positive": positive,
        "negative": negative,
        "target": round(target, 3),
        "threshold": round(threshold, 3),
        "signal": signal,
    }


def kaplan_meier_curve(observations):
    cleaned = []
    for observation in observations or []:
        duration = safe_float(observation.get("duration_hours"), None)
        if duration is None or duration < 0:
            continue
        cleaned.append({
            "duration_hours": duration,
            "event_observed": bool(observation.get("event_observed")),
        })

    if not cleaned:
        return {
            "point_count": 0,
            "median_survival_hours": None,
            "curve": [],
            "sample_size": 0,
            "event_count": 0,
            "censored_count": 0,
        }

    cleaned.sort(key=lambda item: item["duration_hours"])
    grouped = defaultdict(lambda: {"events": 0, "censored": 0})
    for item in cleaned:
        key = item["duration_hours"]
        if item["event_observed"]:
            grouped[key]["events"] += 1
        else:
            grouped[key]["censored"] += 1

    at_risk = len(cleaned)
    survival = 1.0
    curve = []
    median = None
    for duration in sorted(grouped):
        events = grouped[duration]["events"]
        censored = grouped[duration]["censored"]
        if events:
            survival *= (1.0 - (events / max(at_risk, 1)))
            curve.append({
                "duration_hours": round(duration, 2),
                "survival_probability": round(survival, 4),
                "at_risk": at_risk,
                "events": events,
                "censored": censored,
            })
            if median is None and survival <= 0.5:
                median = round(duration, 2)
        at_risk -= (events + censored)

    return {
        "point_count": len(curve),
        "median_survival_hours": median,
        "curve": curve[:10],
        "sample_size": len(cleaned),
        "event_count": sum(item["event_observed"] for item in cleaned),
        "censored_count": sum(1 for item in cleaned if not item["event_observed"]),
    }


def build_run_feature_map(row):
    row = dict(row or {})
    intel_summary = dict(json_loads(row.get("intel_summary_json"), default={}) or {})
    issues = parse_issues(row)
    forms = [item.strip() for item in str(row.get("forms_text") or "").split("|") if item.strip()]
    missing_items = list(intel_summary.get("missing_items", []) or [])
    review_flags = list(intel_summary.get("review_flags", []) or [])
    scan_quality_score = normalize_rate(row.get("scan_quality_score"))
    ocr_confidence = normalize_rate(row.get("ocr_confidence"))

    return {
        "score_norm": clamp(safe_float(row.get("score"), 0.0) / 100.0),
        "packet_confidence": normalize_rate(row.get("packet_confidence")),
        "issue_count": len(issues),
        "form_count": len(forms),
        "missing_item_count": len(missing_items),
        "review_flag_count": len(review_flags),
        "scan_quality_score": scan_quality_score,
        "ocr_confidence": ocr_confidence,
    }


def build_packet_feature_map(packet):
    intake = dict(getattr(packet, "intake_diagnostics", {}) or {})
    scan_quality = dict(intake.get("scan_quality", {}) or {})
    average_ocr = intake.get("average_ocr_confidence")

    return {
        "score_norm": clamp(safe_float(getattr(packet, "packet_score", 0.0), 0.0) / 100.0),
        "packet_confidence": normalize_rate(getattr(packet, "packet_confidence", 0.0)),
        "issue_count": len(getattr(packet, "conflicts", []) or []) + len(getattr(packet, "missing_fields", []) or []) + len(getattr(packet, "missing_documents", []) or []),
        "form_count": len(getattr(packet, "detected_documents", set()) or []),
        "missing_item_count": len(getattr(packet, "missing_fields", []) or []) + len(getattr(packet, "missing_documents", []) or []),
        "review_flag_count": len(set(getattr(packet, "review_flags", []) or [])),
        "scan_quality_score": normalize_rate(scan_quality.get("average_score")),
        "ocr_confidence": normalize_rate(average_ocr),
    }


def _build_training_examples(all_runs, all_events):
    terminal_events = defaultdict(list)
    for event in all_events:
        if str(event.get("event_type") or "").lower() != "manual_outcome":
            continue
        status = str(event.get("event_status") or "").lower()
        if status not in TERMINAL_OUTCOMES:
            continue
        case_key = event.get("case_key")
        created_at = parse_ts(event.get("created_at"))
        if not case_key or created_at is None:
            continue
        terminal_events[case_key].append({
            "timestamp": created_at,
            "label": 1 if status in TERMINAL_SUCCESS_OUTCOMES else 0,
            "status": status,
        })

    for case_key in terminal_events:
        terminal_events[case_key].sort(key=lambda item: item["timestamp"])

    examples = []
    for row in sorted(all_runs, key=lambda item: parse_ts(item.get("analyzed_at")) or datetime.min.replace(tzinfo=timezone.utc)):
        case_key = row.get("case_key")
        analyzed_at = parse_ts(row.get("analyzed_at"))
        if not case_key or analyzed_at is None:
            continue

        matching_event = None
        for event in terminal_events.get(case_key, []):
            if event["timestamp"] >= analyzed_at:
                matching_event = event
                break
        if not matching_event:
            continue

        examples.append({
            "features": build_run_feature_map(row),
            "label": matching_event["label"],
            "case_key": case_key,
            "analyzed_at": analyzed_at,
            "outcome_status": matching_event["status"],
            "outcome_at": matching_event["timestamp"],
        })

    return examples


def _standardize_matrix(feature_rows, feature_keys):
    means = {}
    stddevs = {}
    for key in feature_keys:
        values = [safe_float(row.get(key), 0.0) for row in feature_rows]
        mean = sum(values) / max(len(values), 1)
        variance = sum((value - mean) ** 2 for value in values) / max(len(values), 1)
        stddev = math.sqrt(variance)
        means[key] = mean
        stddevs[key] = stddev if stddev > 1e-6 else 1.0

    standardized = []
    for row in feature_rows:
        standardized.append([
            (safe_float(row.get(key), 0.0) - means[key]) / stddevs[key]
            for key in feature_keys
        ])
    return standardized, means, stddevs


def _train_logistic_model(feature_rows, labels, feature_keys, epochs=700, learning_rate=0.14, l2=0.01):
    standardized_rows, means, stddevs = _standardize_matrix(feature_rows, feature_keys)
    sample_size = len(standardized_rows)
    positive_count = sum(labels)
    intercept = logit(beta_smoothed_rate(positive_count, sample_size, alpha=1.0, beta=1.0))
    weights = [0.0 for _ in feature_keys]

    for _ in range(epochs):
        gradients = [0.0 for _ in feature_keys]
        grad_intercept = 0.0
        for row, label in zip(standardized_rows, labels):
            prediction = sigmoid(sum(weight * value for weight, value in zip(weights, row)) + intercept)
            error = prediction - label
            grad_intercept += error
            for index, value in enumerate(row):
                gradients[index] += error * value

        grad_intercept /= sample_size
        intercept -= learning_rate * grad_intercept
        for index in range(len(weights)):
            gradient = (gradients[index] / sample_size) + (l2 * weights[index])
            weights[index] -= learning_rate * gradient

    raw_probabilities = []
    for row in standardized_rows:
        raw_probabilities.append(sigmoid(sum(weight * value for weight, value in zip(weights, row)) + intercept))

    platt = fit_platt_scaler(raw_probabilities, labels)
    calibrated_probabilities = [apply_platt_scaler(probability, platt) for probability in raw_probabilities] if platt else [round(probability, 4) for probability in raw_probabilities]
    curve = calibration_curve(labels, calibrated_probabilities, bins=5)
    ece = expected_calibration_error(curve)
    auc = roc_auc(labels, calibrated_probabilities)
    brier = brier_score(labels, calibrated_probabilities)
    loss = log_loss(labels, calibrated_probabilities)

    sample_factor = min(sample_size / 80.0, 1.0)
    auc_factor = 0.0 if auc is None else clamp((auc - 0.5) / 0.5)
    calibration_factor = 0.0 if ece is None else clamp(1.0 - (ece / 0.3))
    brier_factor = 0.0 if brier is None else clamp(1.0 - (brier / 0.35))
    reliability = round((sample_factor * 0.4) + (auc_factor * 0.25) + (calibration_factor * 0.2) + (brier_factor * 0.15), 2)

    return {
        "available": True,
        "model_type": "logistic_regression_platt_v1" if platt else "logistic_regression_v1",
        "feature_keys": list(feature_keys),
        "weights": {key: round(weight, 6) for key, weight in zip(feature_keys, weights)},
        "intercept": round(intercept, 6),
        "means": {key: round(means[key], 6) for key in feature_keys},
        "stddevs": {key: round(stddevs[key], 6) for key in feature_keys},
        "sample_size": sample_size,
        "positive_count": int(positive_count),
        "negative_count": int(sample_size - positive_count),
        "positive_rate": round(positive_count / sample_size, 3),
        "platt_scaler": platt,
        "metrics": {
            "brier_score": brier,
            "log_loss": loss,
            "roc_auc": auc,
            "ece": ece,
            "calibration_curve": curve,
            "reliability_score": reliability,
            "reliability_band": "high" if reliability >= 0.78 else "moderate" if reliability >= 0.52 else "low",
            "evaluation_basis": "recent_labeled_history_in_sample_v1",
        },
    }


def _build_base_rate_model(labels, feature_keys, reason):
    sample_size = len(labels)
    positive_count = sum(labels)
    negative_count = sample_size - positive_count
    base_probability = beta_smoothed_rate(positive_count, sample_size, alpha=1.0, beta=1.0)
    probabilities = [base_probability for _ in labels]
    curve = calibration_curve(labels, probabilities, bins=3)
    ece = expected_calibration_error(curve)
    brier = brier_score(labels, probabilities)
    loss = log_loss(labels, probabilities)
    interval = wilson_interval(positive_count, sample_size)
    interval_width = safe_float((interval or {}).get("width"), 1.0)
    sample_factor = min(sample_size / 40.0, 1.0)
    interval_factor = clamp(1.0 - interval_width)
    reliability = round((sample_factor * 0.55) + (interval_factor * 0.45), 2)

    return {
        "available": True,
        "model_type": "bayesian_base_rate_v1",
        "feature_keys": list(feature_keys),
        "weights": {},
        "intercept": None,
        "means": {},
        "stddevs": {},
        "sample_size": sample_size,
        "positive_count": int(positive_count),
        "negative_count": int(negative_count),
        "positive_rate": round(positive_count / max(sample_size, 1), 3),
        "base_probability": round(base_probability, 4),
        "fallback_only": True,
        "metrics": {
            "brier_score": brier,
            "log_loss": loss,
            "roc_auc": None,
            "ece": ece,
            "calibration_curve": curve,
            "reliability_score": reliability,
            "reliability_band": "moderate" if reliability >= 0.5 else "low",
            "evaluation_basis": reason,
            "positive_rate_interval": interval,
        },
    }


def build_outcome_model(all_runs=None, all_events=None):
    all_runs = list(all_runs if all_runs is not None else get_recent_packet_runs(limit=280))
    all_events = list(all_events if all_events is not None else get_recent_packet_events(limit=280))

    signature = (
        len(all_runs),
        len(all_events),
        all_runs[0].get("analyzed_at") if all_runs else None,
        all_events[0].get("created_at") if all_events else None,
    )
    cached = _OUTCOME_MODEL_CACHE.get("model")
    if _OUTCOME_MODEL_CACHE.get("signature") == signature and cached is not None:
        return cached

    examples = _build_training_examples(all_runs, all_events)
    labels = [example["label"] for example in examples]
    feature_rows = [example["features"] for example in examples]
    positive_count = sum(labels)
    negative_count = len(labels) - positive_count

    if len(labels) < 6:
        model = {
            "available": False,
            "sample_size": len(labels),
            "positive_count": int(positive_count),
            "negative_count": int(negative_count),
            "reason": "insufficient_labeled_history",
            "feature_keys": list(OUTCOME_FEATURE_KEYS),
            "examples": len(examples),
        }
    elif len(labels) < 12:
        model = _build_base_rate_model(
            labels,
            OUTCOME_FEATURE_KEYS,
            reason="limited_labeled_history_base_rate",
        )
    elif positive_count == 0 or negative_count == 0:
        model = _build_base_rate_model(
            labels,
            OUTCOME_FEATURE_KEYS,
            reason="single_class_labeled_history_base_rate",
        )
    else:
        model = _train_logistic_model(feature_rows, labels, OUTCOME_FEATURE_KEYS)
        model["examples"] = len(examples)

    _OUTCOME_MODEL_CACHE["signature"] = signature
    _OUTCOME_MODEL_CACHE["model"] = model
    return model


def predict_outcome_probability(model, feature_map):
    model = dict(model or {})
    if not model.get("available"):
        return {
            "available": False,
            "raw_probability": None,
            "calibrated_probability": None,
            "reliability_score": None,
            "reliability_band": None,
        }

    if model.get("base_probability") is not None and not model.get("weights"):
        base_probability = clamp(model.get("base_probability"))
        metrics = dict(model.get("metrics", {}) or {})
        return {
            "available": True,
            "raw_probability": round(base_probability, 4),
            "calibrated_probability": round(base_probability, 4),
            "reliability_score": metrics.get("reliability_score"),
            "reliability_band": metrics.get("reliability_band"),
            "feature_map": dict(feature_map or {}),
        }

    feature_keys = list(model.get("feature_keys", []) or [])
    weights = dict(model.get("weights", {}) or {})
    means = dict(model.get("means", {}) or {})
    stddevs = dict(model.get("stddevs", {}) or {})
    intercept = safe_float(model.get("intercept"), 0.0)

    standardized = []
    for key in feature_keys:
        value = safe_float((feature_map or {}).get(key), 0.0)
        mean = safe_float(means.get(key), 0.0)
        stddev = safe_float(stddevs.get(key), 1.0) or 1.0
        standardized.append((value - mean) / stddev)

    raw_probability = sigmoid(sum(safe_float(weights.get(key), 0.0) * value for key, value in zip(feature_keys, standardized)) + intercept)
    calibrated_probability = apply_platt_scaler(raw_probability, model.get("platt_scaler"))

    metrics = dict(model.get("metrics", {}) or {})
    return {
        "available": True,
        "raw_probability": round(raw_probability, 4),
        "calibrated_probability": round(calibrated_probability, 4),
        "reliability_score": metrics.get("reliability_score"),
        "reliability_band": metrics.get("reliability_band"),
        "feature_map": dict(feature_map or {}),
    }


def summarize_outcome_model(model):
    model = dict(model or {})
    if not model.get("available"):
        return {
            "available": False,
            "sample_size": model.get("sample_size", 0),
            "positive_count": model.get("positive_count", 0),
            "negative_count": model.get("negative_count", 0),
            "reason": model.get("reason") or "insufficient_labeled_history",
        }

    metrics = dict(model.get("metrics", {}) or {})
    return {
        "available": True,
        "model_type": model.get("model_type"),
        "sample_size": model.get("sample_size"),
        "positive_count": model.get("positive_count"),
        "negative_count": model.get("negative_count"),
        "positive_rate": model.get("positive_rate"),
        "base_probability": model.get("base_probability"),
        "brier_score": metrics.get("brier_score"),
        "log_loss": metrics.get("log_loss"),
        "roc_auc": metrics.get("roc_auc"),
        "ece": metrics.get("ece"),
        "reliability_score": metrics.get("reliability_score"),
        "reliability_band": metrics.get("reliability_band"),
        "calibration_curve": metrics.get("calibration_curve"),
        "evaluation_basis": metrics.get("evaluation_basis"),
        "positive_rate_interval": metrics.get("positive_rate_interval"),
    }


def build_turnaround_observations(all_runs, all_events):
    outcomes_by_case = defaultdict(list)
    for event in all_events:
        if str(event.get("event_type") or "").lower() != "manual_outcome":
            continue
        created_at = parse_ts(event.get("created_at"))
        if created_at is None:
            continue
        outcomes_by_case[event.get("case_key")].append({
            "created_at": created_at,
            "status": str(event.get("event_status") or "").lower(),
        })

    for case_key in outcomes_by_case:
        outcomes_by_case[case_key].sort(key=lambda item: item["created_at"])

    observations = []
    now = utc_now()
    for row in all_runs:
        analyzed_at = parse_ts(row.get("analyzed_at"))
        case_key = row.get("case_key")
        if analyzed_at is None or not case_key:
            continue

        matched = None
        for event in outcomes_by_case.get(case_key, []):
            if event["created_at"] >= analyzed_at:
                matched = event
                break

        if matched:
            duration = (matched["created_at"] - analyzed_at).total_seconds() / 3600.0
            observations.append({
                "duration_hours": max(duration, 0.0),
                "event_observed": True,
                "status": matched["status"],
            })
        else:
            duration = (now - analyzed_at).total_seconds() / 3600.0
            observations.append({
                "duration_hours": max(duration, 0.0),
                "event_observed": False,
                "status": None,
            })
    return observations
