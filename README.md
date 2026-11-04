# Maquette Mininet/QoS — Debian 13

Cette maquette compare la QoS de référence, le policing à seuil et le policing déclenché par un modèle sur le même petit réseau isolé.

## Topologie

`h1` (VoIP UDP 64 kbit/s) et `h2` (source de surcharge) sont reliés à `s1`. La liaison `s1`–`h3` est le goulot `TCLink` limité à 10 Mbit/s. `run_lab.py` place le policing dynamique en entrée du port de `h2`, avant le goulot ; les mesures du flux voix sont prises à `h3`.

Dans la VM Debian 13 dédiée, installer Mininet/Open vSwitch, `iperf3`, `hping3`, `iproute2`, `ethtool`, `tcpdump`, Python venv, puis Scapy, pandas, scikit-learn et joblib dans un venv. Vérifier les paquets avec `apt-cache policy mininet hping3 iperf3` avant l'installation.

Valider la topologie seule :

```bash
sudo mn --custom topology.py --topo ddosqos --test pingall
sudo mn --custom topology.py --topo ddosqos
```

Le premier test doit afficher trois hôtes et `pingall` doit avoir 0 % de perte. Dans la console Mininet, vérifier `sh tc -s qdisc show dev s1-eth3` puis `sh tc -s class show dev s1-eth3` : la liaison `s1`–`h3` doit afficher un débit de 10 Mbit/s. Quitter Mininet avec `exit`, puis nettoyer avec `sudo mn -c`.

## Préparer le modèle S4

Les fenêtres locales ont une définition différente des statistiques complètes CIC-DDoS2019. Pour éviter une fausse correspondance, entraîner le modèle utilisé dans la maquette sur des sessions locales séparées ; garder les captures destinées aux scénarios S0–S5 comme test final.

Créer au moins six sessions d'apprentissage indépendantes (quatre avec surcharge hping3 et deux avec pic bénin), une session par commande et un dossier distinct par session. Chaque exécution fournit aussi une période inactive. `run_lab.py` écrit les caractéristiques et labels dans `windows.csv`.

```bash
sudo python3 run_lab.py --mode none --kind attack --generator hping3 \
  --out results/train/attaque_01
sudo python3 run_lab.py --mode none --kind attack --generator hping3 \
  --out results/train/attaque_02
sudo python3 run_lab.py --mode none --kind flash --generator iperf3 \
  --out results/train/pic_benin_01
sudo python3 run_lab.py --mode none --kind flash --generator iperf3 \
  --out results/train/pic_benin_02
python3 train_windows.py --runs results/train \
  --out models/traffic_windows.joblib --max-fpr 0.01
```

Le script sépare les données par dossier/session : entraînement, réglage de seuil sur validation, puis test indépendant. Il refuse les données trop petites ou sans les deux classes dans chaque partition. Il faut archiver métriques et identifiants des sessions avec le modèle.

## Campagne S0–S5

Depuis un répertoire vierge pour les sorties, lancer la campagne dans la VM Linux dédiée :

```bash
sudo python3 run_scenarios.py --model models/traffic_windows.joblib \
  --out results/final_2026-12-11 --repetitions 5
```

| Scénario | Trafic | Protection |
|---|---|---|
| S0 | VoIP seule, sans surcharge | Aucune action dynamique |
| S1 | VoIP + surcharge UDP hping3 | Goulot seulement |
| S2 | Même demande | Classe voix prioritaire statique |
| S3 | Même demande | QoS statique + seuil de débit |
| S4 | Même demande | QoS statique + Random Forest |
| S5 | Pic bénin iperf3 | Deux essais : seuil puis IA, pour compter les faux positifs et la perte légitime |

Dans la maquette, `hping3` envoie des datagrammes UDP de 1400 octets vers `10.0.0.3:5203`, avec cadence par défaut plafonnée à 1 paquet/ms (environ 11,4 Mbit/s IP) et durée bornée (90 s). Ce générateur est utilisé uniquement depuis le namespace `h2` vers l'adresse privée Mininet `h3`. Le mode `--flood` n'est volontairement pas utilisé : il supprime la limite de cadence et rend la charge moins reproductible. `iperf3` fournit le pic bénin S5 sur un port distinct.

## Journaux et délais de réaction

Chaque exécution crée `config.json`, `windows.csv`, `events.jsonl`, `voice.json`, `ping.log`, `tc.jsonl` et `timestamps.json`. Les événements portent un temps monotone relatif et un horodatage UTC. La définition est la suivante :

| Repère | Événement observé |
|---|---|
| t0 | Premier paquet de surcharge capturé à la sortie de h2 |
| t1 | Première fenêtre disponible au collecteur |
| t2 | Première décision positive du seuil ou du modèle après confirmation |
| t3 | Retour réussi de l'installation de la règle de policing par `tc` |
| t4 | Première fin d'une série de 5 intervalles voix iperf3 respectant perte ≤ 1 % et gigue ≤ 30 ms, après un intervalle ayant dépassé au moins un seuil |

Calculer et publier séparément `t2−t0`, `t3−t0` et `t4−t0`. Si la voix reste dans les seuils pendant tout l'essai, t4 est non applicable car aucune dégradation n'a été observée ; si elle est dégradée sans série de récupération, consigner t4 non atteint. `t4` est estimé à partir des intervalles récepteur iperf3 et aligné sur l'origine monotone locale ; mentionner cette précision dans l'analyse. Les seuils de récupération sont des choix de protocole à figer avant les essais finaux, pas des seuils universels.

Faire cinq répétitions par scénario dans un ordre alterné si le temps le permet. Conserver les fichiers bruts. Après chaque essai, vérifier les processus, exécuter `sudo mn -c`, puis redémarrer la topologie pour éviter les règles ou états résiduels.
