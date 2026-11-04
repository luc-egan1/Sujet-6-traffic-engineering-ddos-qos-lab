"""Features causales de fenetre pour le lab UDP (bibliotheque standard)."""
from collections import Counter
import math

FEATURES = ['pps', 'bps', 'mean_ip_bytes', 'std_ip_bytes',
            'source_entropy', 'source_port_entropy']


def entropy(values):
    total = sum(values)
    return -sum((n / total) * math.log2(n / total) for n in values if n) if total else 0.0


class Window:
    def __init__(self):
        self.n = self.bytes = self.squares = 0
        self.sources = Counter()
        self.ports = Counter()

    def add(self, size, source, port):
        self.n += 1
        self.bytes += size
        self.squares += size * size
        self.sources[source] += 1
        self.ports[port] += 1

    def values(self, duration):
        if duration <= 0:
            raise ValueError('La duree doit etre positive')
        mean = self.bytes / self.n if self.n else 0.0
        variance = max(0.0, self.squares / self.n - mean * mean) if self.n else 0.0
        return dict(zip(FEATURES, [self.n / duration, 8 * self.bytes / duration,
                                  mean, math.sqrt(variance), entropy(self.sources.values()),
                                  entropy(self.ports.values())]))
