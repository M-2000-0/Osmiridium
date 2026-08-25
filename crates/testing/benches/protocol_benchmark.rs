use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use osmiridium_protocol::crypto::field::Scalar;
use osmiridium_protocol::crypto::sharing::{AdditiveShare, SharingScheme};
use osmiridium_protocol::ArithmeticCircuit;

fn bench_sharing(c: &mut Criterion) {
    let mut g = c.benchmark_group("sharing");
    for n in [3, 10] {
        g.bench_function(format!("split_n={n}"), |b| {
            b.iter(|| {
                let v = Scalar::from_u64(42);
                criterion::black_box(AdditiveShare::<Scalar>::split(&v, n, 0).unwrap())
            })
        });
    }
    g.finish();
}

fn bench_circuit_build(c: &mut Criterion) {
    c.bench_function("circuit_50_gates", |b| {
        b.iter_batched(
            ArithmeticCircuit::new,
            |mut circuit| {
                let a = circuit.constant(Scalar::from_u64(1));
                let mut w = a;
                for _ in 0..25 {
                    let o = circuit.constant(Scalar::from_u64(1));
                    w = circuit.add(w, o);
                }
                circuit.set_num_inputs(0);
                criterion::black_box(circuit.validate().unwrap());
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_offline(c: &mut Criterion) {
    use osmiridium_protocol::offline::{OfflinePhase, PreprocessingConfig};
    c.bench_function("offline_50_triples", |b| {
        b.iter(|| {
            let phase = OfflinePhase::new(
                PreprocessingConfig {
                    num_parties: 3,
                    num_triples: 50,
                    ..Default::default()
                },
                0,
            );
            let triples = phase
                .generate_triples(Scalar::from_u64(7), Scalar::from_u64(3), 3000, 50)
                .unwrap();
            criterion::black_box(triples);
        })
    });
}

criterion_group!(benches, bench_sharing, bench_circuit_build, bench_offline);
criterion_main!(benches);
