#!/usr/bin/env python3
"""Exécute les scénarios S0-S5 dans la maquette Mininet locale et isolée."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True,
                        help="bundle local_windows produit par train_windows.py")
    parser.add_argument("--out", type=Path, required=True,
                        help="nouveau répertoire racine des résultats")
    parser.add_argument("--duration", type=int, default=180)
    parser.add_argument("--start", type=int, default=30)
    parser.add_argument("--active", type=int, default=90)
    parser.add_argument("--repetitions", type=int, default=1,
                        help="nombre de répétitions indépendantes, ex. 5")
    parser.add_argument("--attack-interval", default="u1000",
                        help="intervalle hping3 borné, 1000 paquets/s par défaut")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Exécuter dans la VM Debian dédiée avec sudo")
    if not args.model.is_file():
        parser.error(f"modèle introuvable : {args.model}")
    if args.repetitions < 1 or args.repetitions > 10:
        parser.error("--repetitions doit être entre 1 et 10")
    if args.out.exists():
        parser.error("Le répertoire de sortie existe déjà ; choisir un nouveau nom")
    if not (0 < args.start and args.start + args.active < args.duration):
        parser.error("La durée doit inclure un état calme avant et après la charge")
    args.model = args.model.resolve()
    args.out = args.out.resolve()

    here = Path(__file__).resolve().parent
    runner = here / "run_lab.py"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    args.out.mkdir(parents=True)
    common = [sys.executable, str(runner), "--duration", str(args.duration),
              "--start", str(args.start), "--active", str(args.active)]
    scenarios = [
        ("S0_baseline", "none", "none", "hping3"),
        ("S1_attaque_sans_protection", "none", "attack", "hping3"),
        ("S2_qos_statique", "qos", "attack", "hping3"),
        ("S3_detection_seuil", "threshold", "attack", "hping3"),
        ("S4_detection_IA", "ml", "attack", "hping3"),
        ("S5_pic_benin_seuil", "threshold", "flash", "iperf3"),
        ("S5_pic_benin_IA", "ml", "flash", "iperf3"),
    ]
    manifest = {"created_utc": datetime.now(timezone.utc).isoformat(),
                "safety": "hping3 UDP privé et cadencé ; aucune cible hors Mininet",
                "scenarios": []}
    for repetition in range(1, args.repetitions + 1):
        rotation = (repetition - 1) % len(scenarios)
        ordered = scenarios[rotation:] + scenarios[:rotation]
        for name, mode, kind, generator in ordered:
            run_dir = args.out / f"{stamp}_{name}_r{repetition:02d}"
            argv = common + ["--mode", mode, "--kind", kind,
                             "--generator", generator, "--out", str(run_dir)]
            if generator == "hping3":
                argv += ["--hping-interval", args.attack_interval]
            if mode == "ml":
                argv += ["--model", str(args.model)]
            entry = {"name": name, "repetition": repetition,
                     "command": argv, "output": str(run_dir)}
            print(f"[{name} r{repetition:02d}] démarrage")
            try:
                subprocess.run(argv, check=True, cwd=here)
                entry["status"] = "completed"
            except subprocess.CalledProcessError as error:
                entry["status"] = "failed"
                entry["returncode"] = error.returncode
                manifest["scenarios"].append(entry)
                (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2))
                raise
            manifest["scenarios"].append(entry)
            (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"Campagne terminée : {args.out}")


if __name__ == "__main__":
    main()
