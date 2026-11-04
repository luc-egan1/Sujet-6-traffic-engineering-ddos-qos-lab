#!/usr/bin/env python3
"""Maquette Mininet locale. Execute seulement dans la VM Linux dediee."""
import argparse
import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time

from features import FEATURES, Window


def command(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True)


def configure_link(protected):
    dev = 's1-eth3'
    command('tc', 'qdisc', 'replace', 'dev', dev, 'root', 'handle', '1:',
            'htb', 'default', '20' if protected else '10')
    command('tc', 'class', 'replace', 'dev', dev, 'parent', '1:', 'classid', '1:1',
            'htb', 'rate', '10mbit', 'ceil', '10mbit')
    classes = [('10', '256kbit', '256kbit', '0', '20'),
               ('20', '9744kbit', '10mbit', '1', '100')] if protected else [
                   ('10', '10mbit', '10mbit', '0', '100')]
    for minor, rate, ceil, priority, limit in classes:
        command('tc', 'class', 'replace', 'dev', dev, 'parent', '1:1',
                'classid', '1:' + minor, 'htb', 'rate', rate, 'ceil', ceil, 'prio', priority)
        command('tc', 'qdisc', 'replace', 'dev', dev, 'parent', '1:' + minor,
                'handle', minor + ':', 'pfifo', 'limit', limit)
    if protected:
        # Reconnaissance locale de la voix par port, et du ping de mesure par source.
        command('tc', 'filter', 'replace', 'dev', dev, 'protocol', 'ip', 'parent', '1:',
                'pref', '10', 'flower', 'ip_proto', 'udp', 'dst_port', '5201',
                'classid', '1:10')
        command('tc', 'filter', 'replace', 'dev', dev, 'protocol', 'ip', 'parent', '1:',
                'pref', '11', 'flower', 'ip_proto', 'icmp', 'src_ip', '10.0.0.1',
                'classid', '1:10')
    command('tc', 'qdisc', 'replace', 'dev', 's1-eth2', 'clsact')


def police(enabled, destination_port):
    if enabled:
        command('tc', 'filter', 'replace', 'dev', 's1-eth2', 'ingress',
                'protocol', 'ip', 'pref', '10', 'flower', 'ip_proto', 'udp',
                'dst_ip', '10.0.0.3', 'dst_port', str(destination_port), 'action', 'police',
                'rate', '1mbit', 'burst', '32k', 'conform-exceed', 'drop/ok')
    else:
        command('tc', 'filter', 'del', 'dev', 's1-eth2', 'ingress',
                'protocol', 'ip', 'pref', '10')


def find_durable_voice_recovery(path, voice_origin, overload_start_mono,
                                loss_limit, jitter_limit,
                                stable_intervals):
    """Return (recovery time, whether degradation occurred) from receiver intervals."""
    try:
        report = json.loads(path.read_text())
        receiver = report.get('server_output_json')
        if isinstance(receiver, str):
            receiver = json.loads(receiver)
        if not isinstance(receiver, dict):
            return None, False
        intervals = receiver.get('intervals', [])
        stable = 0
        degraded = False
        for interval in intervals:
            summary = interval.get('sum_received') or interval.get('sum') or {}
            if not summary:
                continue
            end_s = float(summary.get('end', 0))
            lost_percent = float(summary.get('lost_percent', 100))
            jitter_ms = float(summary.get('jitter_ms', float('inf')))
            interval_end_mono = voice_origin + end_s
            if interval_end_mono < overload_start_mono:
                continue
            within_qos = lost_percent <= loss_limit and jitter_ms <= jitter_limit
            if not within_qos:
                degraded = True
                stable = 0
            elif degraded:
                stable += 1
                if stable >= stable_intervals:
                    return interval_end_mono, True
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None, False
    return None, degraded


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--mode', choices=['none', 'qos', 'threshold', 'ml'], default='none')
    p.add_argument('--kind', choices=['none', 'attack', 'flash'], default='attack')
    p.add_argument('--generator', choices=['hping3', 'iperf3'], default='hping3')
    p.add_argument('--hping-interval', default='u1000')
    p.add_argument('--load-rate', default='20M')
    p.add_argument('--load-size', type=int, default=1400)
    p.add_argument('--duration', type=int, default=180)
    p.add_argument('--start', type=int, default=30)
    p.add_argument('--active', type=int, default=90)
    p.add_argument('--model', type=Path)
    p.add_argument('--threshold-mbps', type=float, default=10.0)
    p.add_argument('--recovery-loss-percent', type=float, default=1.0)
    p.add_argument('--recovery-jitter-ms', type=float, default=30.0)
    p.add_argument('--recovery-stable-intervals', type=int, default=5)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    if os.geteuid() != 0:
        p.error('Lancer avec sudo dans la VM Linux')
    if not (0 < args.start < args.start + args.active < args.duration):
        p.error('Il faut une phase normale avant et apres la charge')
    if args.load_size < 64 or args.load_size > 1400:
        p.error('Taille UDP entre 64 et 1400 octets pour ce lab')
    if args.out.exists():
        p.error('Choisir un nouveau repertoire pour ne pas remplacer un essai')
    if args.mode == 'ml' and not args.model:
        p.error('--model requis en mode ml')
    if args.kind == 'attack' and args.generator == 'iperf3':
        p.error('S1/S3/S4 utilisent hping3 à débit borné ; iperf3 reste la charge bénigne S5')
    if args.kind == 'flash' and args.generator != 'iperf3':
        p.error('Le pic bénin S5 utilise iperf3')
    if args.kind == 'attack':
        interval = re.fullmatch(r'u([0-9]+)', args.hping_interval)
        if interval is None or int(interval.group(1)) < 1000:
            p.error('--hping-interval doit être u1000 ou plus lent (plafond 1000 paquets/s)')
    if args.recovery_stable_intervals < 1:
        p.error('--recovery-stable-intervals doit être supérieur à zéro')

    from mininet.net import Mininet
    from mininet.node import OVSBridge
    from scapy.all import AsyncSniffer, IP, UDP
    from topology import DDoSQoSTopo

    bundle = None
    if args.mode == 'ml':
        import joblib
        bundle = joblib.load(args.model)  # Uniquement un fichier local que vous avez produit.
        if bundle.get('kind') != 'local_windows' or bundle['features'] != FEATURES:
            raise ValueError('Modele incompatible : utiliser train_windows.py, pas le modele CIC')
    args.out.mkdir(parents=True)
    serializable = {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()}
    (args.out / 'config.json').write_text(json.dumps(serializable, indent=2))
    lock = threading.Lock()
    window = Window()
    processes, handles = [], []
    net = Mininet(topo=DDoSQoSTopo(), controller=None, switch=OVSBridge,
                  build=False, autoSetMacs=True)
    sniffer = None
    activated = False
    try:
        net.build()
        h1, h2, h3 = [net.get(name) for name in ('h1', 'h2', 'h3')]
        net.start()
        for host in [h1, h2, h3]:
            host.cmd('ethtool -K %s-eth0 gro off gso off tso off' % host.name)
        for iface in ['s1-eth1', 's1-eth2', 's1-eth3']:
            command('ethtool', '-K', iface, 'gro', 'off', 'gso', 'off', 'tso', 'off', check=False)
        if net.pingAll(timeout='2') != 0:
            raise RuntimeError('Echec pingAll avant configuration')
        configure_link(args.mode != 'none')

        def spawn(host, filename, argv, quiet=False):
            handle = None if quiet else (args.out / filename).open('w')
            if handle is not None:
                handles.append(handle)
            output = subprocess.DEVNULL if quiet else handle
            proc = host.popen(argv, stdout=output, stderr=subprocess.STDOUT)
            processes.append(proc)
            return proc

        spawn(h3, 'server_voice.log', ['iperf3', '-s', '-p', '5201'])
        spawn(h3, 'server_load.log', ['iperf3', '-s', '-p', '5202'])
        time.sleep(1)
        for proc in processes:
            if proc.poll() is not None:
                raise RuntimeError('Un serveur iperf3 a echoue : lire les logs')

        load_port = 5203 if args.generator == 'hping3' else 5202
        first_load_packet = [None]

        def packet(pkt):
            if IP in pkt and UDP in pkt and pkt[IP].src == '10.0.0.2' and pkt[IP].dst == '10.0.0.3' and pkt[UDP].dport == load_port:
                with lock:
                    if first_load_packet[0] is None:
                        first_load_packet[0] = time.monotonic()
                    window.add(int(pkt[IP].len), pkt[IP].src, int(pkt[UDP].sport))

        # Capture au départ de h2, avant policing ; ceci n'est pas un export NetFlow.
        sniffer = AsyncSniffer(iface='h2-eth0', filter=f'udp and dst port {load_port}',
                               prn=packet, store=False)
        sniffer.start()
        time.sleep(.3)
        if not sniffer.running:
            raise RuntimeError('La capture Scapy ne fonctionne pas')
        voice_origin = time.monotonic()
        voice_origin_utc = time.time()
        voice = spawn(h1, 'voice.json', ['iperf3', '-c', '10.0.0.3', '-p', '5201',
                       '-u', '-b', '64K', '-l', '160', '-t', str(args.duration),
                       '-i', '1', '-J', '--get-server-output'])
        spawn(h1, 'ping.log', ['ping', '-D', '-i', '0.2', '-w', str(args.duration), '10.0.0.3'])
        clock_start = previous = time.monotonic()
        load = None
        active_start = active_end = None
        active_start_mono = None
        hi = lo = 0
        activation_time = 0.0
        timestamps = {}
        with (args.out / 'windows.csv').open('w', newline='') as fp, (args.out / 'events.jsonl').open('w') as events, (args.out / 'tc.jsonl').open('w') as qlog:
            fields = ['elapsed', 'duration', 'phase', 'label', *FEATURES, 'score', 'limited']
            writer = csv.DictWriter(fp, fieldnames=fields)
            writer.writeheader()

            def event(name, at_mono=None, **extra):
                instant = time.monotonic() if at_mono is None else at_mono
                elapsed_event = instant - clock_start
                event_record = {'elapsed_monotonic_s': elapsed_event,
                                'timestamp_utc': datetime.fromtimestamp(
                                    voice_origin_utc + instant - voice_origin,
                                    timezone.utc).isoformat(),
                                'event': name, **extra}
                events.write(json.dumps(event_record) + '\n')
                events.flush()
                return elapsed_event

            event('measurement_start')
            while time.monotonic() - clock_start < args.duration:
                elapsed = time.monotonic() - clock_start
                if args.kind != 'none' and load is None and elapsed >= args.start:
                    if args.generator == 'hping3':
                        hping = h2.cmd('command -v hping3').strip()
                        if not hping:
                            raise RuntimeError('hping3 absent dans la VM ; installer le paquet hping3')
                        # Cadence bornée par --hping-interval (>= 1 ms) et durée par --active.
                        # Pas de --flood : la charge reste mesurable et sûre dans le lab.
                        load = spawn(h2, 'load_hping3.log', ['hping3', '--udp', '-p',
                                      str(load_port), '-d', str(args.load_size), '-i',
                                      args.hping_interval,
                                      '10.0.0.3'], quiet=True)
                    else:
                        load = spawn(h2, 'load_iperf3.json', ['iperf3', '-c', '10.0.0.3',
                                      '-p', str(load_port), '-u', '-b', args.load_rate,
                                      '-l', str(args.load_size), '-t', str(args.active),
                                      '-i', '1', '-J', '--get-server-output'])
                    active_start = time.monotonic() - clock_start
                    active_start_mono = time.monotonic()
                    offered_rate = (args.load_rate if args.generator == 'iperf3'
                                    else f"{1_000_000 / int(args.hping_interval[1:]):.1f} packets/s maximum")
                    event('load_process_started', kind=args.kind, generator=args.generator,
                          rate=offered_rate)
                if (load is not None and active_end is None and args.generator == 'hping3'
                        and active_start_mono is not None
                        and time.monotonic() - active_start_mono >= args.active):
                    load.terminate()
                    load.wait(timeout=3)
                    active_end = time.monotonic() - clock_start
                    event('load_finished', returncode=load.returncode, reason='duration_limit')
                if load is not None and active_end is None and load.poll() is not None:
                    active_end = time.monotonic() - clock_start
                    event('load_finished', returncode=load.returncode, reason='generator_exit')
                    if load.returncode != 0:
                        raise RuntimeError('Charge iperf3 en echec : lire load.json')
                time.sleep(max(0.0, previous + 1.0 - time.monotonic()))
                with lock:
                    now = time.monotonic()
                    vector = window.values(now - previous)
                    window = Window()
                elapsed = now - clock_start
                start_elapsed = previous - clock_start
                if first_load_packet[0] is not None and 't0' not in timestamps:
                    timestamps['t0'] = first_load_packet[0]
                    event('t0_surcharge_premier_paquet', at_mono=timestamps['t0'])
                if vector['pps'] > 0 and 't1' not in timestamps:
                    timestamps['t1'] = now
                    event('t1_premiere_observation_collecteur', paquets=vector['pps'])
                # Exclure de l'entrainement les fenetres proches des transitions.
                if active_start is None:
                    phase, label = 'idle', 0
                elif start_elapsed >= active_start + 2 and active_end is None:
                    phase, label = 'active', int(args.kind == 'attack')
                elif active_end is not None and start_elapsed >= active_end + 2:
                    phase, label = 'idle', 0
                else:
                    phase, label = 'transition', -1
                score = None
                if args.mode == 'ml':
                    score = float(bundle['model'].predict_proba([[vector[x] for x in FEATURES]])[0, 1])
                    suspicious = score >= bundle['threshold']
                else:
                    suspicious = vector['bps'] >= args.threshold_mbps * 1_000_000
                if args.mode in ['threshold', 'ml']:
                    hi, lo = (hi + 1, 0) if suspicious else (0, lo + 1)
                    if not activated and hi >= 2:
                        timestamps['t2'] = now
                        event('t2_decision_detection', score=score, mode=args.mode)
                        police(True, load_port)
                        timestamps['t3'] = time.monotonic()
                        activated, activation_time = True, timestamps['t3']
                        event('t3_policing_effectif', at_mono=timestamps['t3'],
                              destination_port=load_port, rate='1mbit')
                    elif activated and lo >= 3 and now - activation_time >= 10:
                        police(False, load_port)
                        activated = False
                        event('police_retire', score=score)
                writer.writerow(dict(elapsed=elapsed, duration=now - previous,
                                     phase=phase, label=label, **vector,
                                     score=score, limited=int(activated)))
                fp.flush()
                snapshot = {'elapsed': elapsed}
                for key, argv in [('qdisc', ['tc', '-s', '-j', 'qdisc', 'show', 'dev', 's1-eth3']),
                                  ('police', ['tc', '-s', '-j', 'filter', 'show', 'dev', 's1-eth2', 'ingress'])]:
                    snapshot[key] = json.loads(command(*argv).stdout)
                qlog.write(json.dumps(snapshot) + '\n')
                qlog.flush()
                previous = now
            voice.wait(timeout=15)
            if args.kind != 'none' and first_load_packet[0] is None:
                raise RuntimeError('Aucun paquet de surcharge capturé ; essai invalide')
            if voice.returncode != 0:
                raise RuntimeError('Flux voix en echec : lire voice.json')
            if args.kind != 'none' and 't0' in timestamps:
                recovered_at, degraded = find_durable_voice_recovery(
                    args.out / 'voice.json', voice_origin, timestamps['t0'],
                    args.recovery_loss_percent,
                    args.recovery_jitter_ms, args.recovery_stable_intervals)
                if recovered_at is not None:
                    timestamps['t4'] = recovered_at
                    event('t4_recuperation_voix_durable', at_mono=recovered_at,
                          loss_percent_max=args.recovery_loss_percent,
                          jitter_ms_max=args.recovery_jitter_ms,
                          consecutive_intervals=args.recovery_stable_intervals,
                          time_basis='intervalle récepteur iperf3, estimé depuis le démarrage du client')
                elif not degraded:
                    event('t4_non_applicable',
                          reason='le flux voix est resté dans les seuils QoS après t0')
                else:
                    event('t4_non_atteint',
                          reason='le flux voix a été dégradé après t0 et aucune récupération durable n’a été mesurée')
            (args.out / 'timestamps.json').write_text(json.dumps({
                key: {'elapsed_monotonic_s': value - clock_start,
                      'timestamp_utc': datetime.fromtimestamp(
                          voice_origin_utc + value - voice_origin,
                          timezone.utc).isoformat()}
                for key, value in timestamps.items()
            }, indent=2))
            event('measurement_end')
        print('Essai termine :', args.out)
    finally:
        if sniffer is not None and sniffer.running:
            sniffer.stop()
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
        for proc in processes:
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        for handle in handles:
            handle.close()
        net.stop()


if __name__ == '__main__':
    main()
