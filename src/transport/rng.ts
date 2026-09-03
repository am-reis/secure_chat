/**
 * mulberry32 — a small, well-known deterministic PRNG. Used only for
 * simulating network fault conditions (drop/duplicate/corrupt decisions,
 * delay values) in the mock transport; never for anything cryptographic.
 * Using Math.random() here would make fault-injection tests flaky and
 * non-reproducible — a "rare" dropped-message bug should be exactly as
 * reproducible as any other test failure.
 */
export function createSeededRng(seed: number): () => number {
    let state = seed >>> 0;
    return function next(): number {
        state = (state + 0x6d2b79f5) >>> 0;
        let t = state;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}
