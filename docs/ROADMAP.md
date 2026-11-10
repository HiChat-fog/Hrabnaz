# Roadmap

Hrabnaz is a working detection system: eBPF probes, a userspace engine, forensic logging, and blocking. It runs on kernels from 3.10 to 7.x.

## Security graph

Attacks unfold as graphs: a process spawns a child, the child writes a file, the file is encrypted, the original process exits. A kernel-maintained security graph, with processes, files, and sockets as nodes and their interactions as edges, would let detection operate on attack patterns rather than individual events. The `process_tree` map already maintains part of this structure.

## Cross-kernel semantic equivalence

The eBPF verifier guarantees that a program is memory-safe and terminates. It does not guarantee that a security verdict means the same thing across kernel generations. Kernel upgrades change helper semantics, short-lived processes evade `/proc` snapshotting, and PID reuse can carry stale risk scores onto unrelated processes. Hrabnaz's five-tier build system and cross-kernel test infrastructure make it a practical platform for studying when the same rule produces the same verdict on different kernels, and when it does not, identifying which layer caused the divergence.

## Graduated containment

Real incident response is graduated: isolate, freeze, snapshot, terminate. eBPF programs can trigger cgroup operations and namespace transitions from kernel space. A response model that maps attack-chain position to containment strategy would make enforcement proportional to the threat.

## Policy verification

Writing correct detection rules is hard. If the rule engine's semantics were formalized, you could statically reason about whether a set of rules covers a given attack technique, or whether two rules produce contradictory verdicts on the same event. This connects to ongoing academic work on eBPF verification.

## Distributed evidence

Attack chains cross hosts: initial access on one machine, lateral movement on another, exfiltration on a third. If chain anchors could be cross-referenced between hosts, the evidence would form a graph with cryptographic guarantees at every node.

## Shared test infrastructure

The QEMU-based test harness spans dozens of distribution kernels across five tiers. Any eBPF program that needs to work across kernel generations could benefit from automated testing against such a matrix.

## Contributing

If any of these directions interest you, or if you want to contribute rules, probe implementations, or kernel compatibility patches, see [CONTRIBUTING](CONTRIBUTING.md). Bug reports and kernel compatibility reports are especially valuable.
