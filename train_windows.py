#!/usr/bin/env python3
"""Entraîne un modèle de fenêtres locales avec séparation par session."""

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit

from features import FEATURES


def split_groups(groups, y, test_size, seed):
    splitter = GroupShuffleSplit(n_splits=200, test_size=test_size,
                                 random_state=seed)
    for left, right in splitter.split(y, y, groups):
        if set(y.iloc[left]) == {0, 1} and set(y.iloc[right]) == {0, 1}:
            return left, right
    return None


def score_at(y_true, probability, threshold):
    prediction = (probability >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, prediction, labels=[0, 1]).ravel()
    return {"threshold": float(threshold), "tn": int(tn), "fp": int(fp),
            "fn": int(fn), "tp": int(tp),
            "precision": float(precision_score(y_true, prediction, zero_division=0)),
            "recall": float(recall_score(y_true, prediction, zero_division=0)),
            "f1": float(f1_score(y_true, prediction, zero_division=0)),
            "fpr": float(fp / max(1, fp + tn))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, required=True,
                        help="répertoire de sessions indépendantes avec windows.csv")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--max-fpr", type=float, default=0.01,
                        help="FPR maximal ciblé sur la validation, défaut 1 %%")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    files = sorted(args.runs.rglob("windows.csv"))
    if not files:
        parser.error(f"aucun windows.csv trouvé dans {args.runs}")
    chunks = []
    for file in files:
        frame = pd.read_csv(file)
        missing = set(FEATURES + ["phase", "label"]) - set(frame.columns)
        if missing:
            parser.error(f"colonnes manquantes dans {file}: {sorted(missing)}")
        frame = frame.loc[frame.phase.isin(["active", "idle"])
                          & frame.label.isin([0, 1])].copy()
        frame["session"] = str(file.parent.relative_to(args.runs))
        chunks.append(frame)
    data = pd.concat(chunks, ignore_index=True)
    data = data.dropna(subset=FEATURES)
    data = data.loc[~data[FEATURES].isin([float("inf"), float("-inf")]).any(axis=1)]
    x = data[FEATURES].astype(float)
    y = data.label.astype(int)
    groups = data.session
    if set(y) != {0, 1} or groups.nunique() < 4:
        parser.error("Fournir au moins 4 sessions indépendantes et les deux classes")

    test_split = split_groups(groups, y, 0.20, args.seed)
    if test_split is None:
        parser.error("Impossible de séparer un test par session ; ajouter des sessions")
    train_val_idx, test_idx = test_split
    validation_split = split_groups(groups.iloc[train_val_idx],
                                    y.iloc[train_val_idx], 0.25, args.seed + 1)
    if validation_split is None:
        parser.error("La validation doit aussi contenir normal et attaque ; ajouter des sessions")
    train_local, validation_local = validation_split
    train_idx = train_val_idx[train_local]
    validation_idx = train_val_idx[validation_local]

    model = RandomForestClassifier(n_estimators=300, min_samples_leaf=2,
                                   class_weight="balanced_subsample",
                                   random_state=args.seed, n_jobs=-1)
    model.fit(x.iloc[train_idx], y.iloc[train_idx])
    validation_probability = model.predict_proba(x.iloc[validation_idx])[:, 1]
    candidates = sorted(set([0.0, 1.001, *validation_probability.tolist()]))
    valid_scores = [score_at(y.iloc[validation_idx], validation_probability, t)
                    for t in candidates]
    eligible = [s for s in valid_scores if s["fpr"] <= args.max_fpr]
    chosen = max(eligible, key=lambda s: (s["recall"], s["precision"], s["threshold"])) if eligible else min(
        valid_scores, key=lambda s: (s["fpr"], -s["recall"]))

    test_probability = model.predict_proba(x.iloc[test_idx])[:, 1]
    test_metrics = score_at(y.iloc[test_idx], test_probability, chosen["threshold"])
    test_metrics["roc_auc"] = float(roc_auc_score(y.iloc[test_idx], test_probability))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    bundle = {"kind": "local_windows", "features": FEATURES, "model": model,
              "threshold": chosen["threshold"], "validation_metrics": chosen,
              "test_metrics": test_metrics,
              "sessions": {"train": sorted(groups.iloc[train_idx].unique()),
                           "validation": sorted(groups.iloc[validation_idx].unique()),
                           "test": sorted(groups.iloc[test_idx].unique())},
              "seed": args.seed}
    joblib.dump(bundle, args.out)
    print(json.dumps({"model": str(args.out), "validation": chosen,
                      "test": test_metrics, "sessions": bundle["sessions"]}, indent=2))


if __name__ == "__main__":
    main()
