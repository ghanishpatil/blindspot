/**
 * AnimatedBackground — a canvas-based, product-native background for the landing.
 *
 * Three overlaid behaviours, all evoking the "cryptographic discovery" story:
 *
 *   1. A dim static grid, matching the CSS grid tokens used elsewhere.
 *   2. Random cell "pulses" — grid squares that softly light up and decay,
 *      as if a scanner is probing that region of the surface.
 *   3. A slow diagonal scan beam that traverses the viewport every ~12 s.
 *   4. Occasional cryptographic constants that flicker in at grid crossings
 *      — real SHA-256 H0 words, RSA / ECDH / AES / ML-KEM labels, and the
 *      rsaEncryption OID — the exact fingerprints the binary scanner looks
 *      for. This ties the background to the product's own vocabulary.
 *
 * All motion is slow (2–5 s per event), sparse (never more than ~5 concurrent
 * glyphs), and low-contrast (max ~50 % opacity for anything moving). One RAF
 * loop drives everything; pauses when the tab is hidden; obeys prefers-
 * reduced-motion by not mounting at all.
 */
import { useEffect, useRef } from 'react';

/** Real cryptographic values — the same the product actually looks for. */
const GLYPH_POOL: string[] = [
  // SHA-256 initial hash values (FIPS 180-4) — the binary scanner's fingerprint.
  '0x6a09e667', '0xbb67ae85', '0x3c6ef372', '0xa54ff53a',
  '0x510e527f', '0x9b05688c', '0x1f83d9ab', '0x5be0cd19',
  // SHA-1 / MD5 shared prefix words.
  '0x67452301', '0xefcdab89', '0x98badcfe', '0x10325476', '0xc3d2e1f0',
  // AES S-box opening bytes.
  '63 7c 77 7b', 'f2 6b 6f c5', '30 01 67 2b',
  // Algorithm labels the tool reports on.
  'RSA-2048', 'RSA-3072', 'ECDH', 'ECDSA', 'AES-256', 'AES-GCM',
  'ML-KEM-768', 'ML-KEM-1024', 'ML-DSA-65', 'ML-DSA-87',
  'X25519', 'Ed25519', 'SHA-256', 'SHA-512',
  // Real OIDs — rsaEncryption, ecdsa-with-SHA256, id-ecPublicKey.
  '1.2.840.113549.1.1.1',
  '1.2.840.10045.4.3.2',
  '1.2.840.10045.2.1',
];

interface Pulse {
  cx: number;
  cy: number;
  age: number;
  duration: number;
}

interface Glyph {
  x: number;
  y: number;
  text: string;
  age: number;
  duration: number;
}

const GRID = 56;             // must match the CSS grid tokens
const PULSE_MAX = 6;
const GLYPH_MAX = 5;

export const AnimatedBackground: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    // Reduced motion → never mount the animation. A static grid CSS layer
    // covers the visual role in that case (see `.aurora-grid` in index.css).
    if (typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) {
      return;
    }

    // getContext throws in jsdom (test env) unless the `canvas` npm package
    // is installed. Fail silently — the background simply doesn't animate
    // in that environment, which is correct behaviour.
    let ctx: CanvasRenderingContext2D | null = null;
    try {
      ctx = canvas.getContext('2d', { alpha: true });
    } catch {
      return;
    }
    if (!ctx) return;

    // ── State ────────────────────────────────────────────────────────────
    const state = {
      dpr: Math.min(window.devicePixelRatio || 1, 2),
      w: 0,
      h: 0,
      pulses: [] as Pulse[],
      glyphs: [] as Glyph[],
      scanX: -400,
      lastPulseSpawn: 0,
      lastGlyphSpawn: 0,
      last: performance.now(),
    };

    const resize = () => {
      state.w = window.innerWidth;
      state.h = window.innerHeight;
      canvas.width = state.w * state.dpr;
      canvas.height = state.h * state.dpr;
      canvas.style.width = `${state.w}px`;
      canvas.style.height = `${state.h}px`;
      ctx.setTransform(state.dpr, 0, 0, state.dpr, 0, 0);
    };

    resize();
    window.addEventListener('resize', resize);

    // ── Spawners ─────────────────────────────────────────────────────────
    const spawnPulse = () => {
      if (state.pulses.length >= PULSE_MAX) state.pulses.shift();
      const cols = Math.ceil(state.w / GRID);
      const rows = Math.ceil(state.h / GRID);
      state.pulses.push({
        cx: Math.floor(Math.random() * cols),
        cy: Math.floor(Math.random() * rows),
        age: 0,
        duration: 2 + Math.random() * 2.5,
      });
    };

    const spawnGlyph = () => {
      if (state.glyphs.length >= GLYPH_MAX) state.glyphs.shift();
      const cols = Math.ceil(state.w / GRID);
      const rows = Math.ceil(state.h / GRID);
      state.glyphs.push({
        x: Math.floor(Math.random() * cols) * GRID + 8,
        y: Math.floor(Math.random() * rows) * GRID + GRID / 2 + 4,
        text: GLYPH_POOL[Math.floor(Math.random() * GLYPH_POOL.length)],
        age: 0,
        duration: 4 + Math.random() * 3,
      });
    };

    // Prime with a handful of pulses + one glyph so the page never looks
    // empty on first paint — animation is visible before the first spawn tick.
    for (let i = 0; i < 3; i += 1) spawnPulse();
    spawnGlyph();

    // ── RAF loop ─────────────────────────────────────────────────────────
    let raf = 0;
    let running = true;

    const render = (now: number) => {
      if (!running) return;
      const dt = Math.min(0.08, (now - state.last) / 1000);
      state.last = now;

      // Spawn cadence — sparse, jittered.
      if (now - state.lastPulseSpawn > 900 + Math.random() * 1400) {
        spawnPulse();
        state.lastPulseSpawn = now;
      }
      if (now - state.lastGlyphSpawn > 3200 + Math.random() * 4000) {
        spawnGlyph();
        state.lastGlyphSpawn = now;
      }

      // Advance ages; drop expired.
      for (const p of state.pulses) p.age += dt / p.duration;
      for (const g of state.glyphs) g.age += dt / g.duration;
      state.pulses = state.pulses.filter((p) => p.age < 1);
      state.glyphs = state.glyphs.filter((g) => g.age < 1);

      // Scan beam — 12 s to traverse, then a brief pause off-screen.
      state.scanX += dt * ((state.w + 800) / 12);
      if (state.scanX > state.w + 400) state.scanX = -400 - Math.random() * 400;

      // ── Draw ──────────────────────────────────────────────────────────
      ctx.clearRect(0, 0, state.w, state.h);

      // Base grid.
      ctx.strokeStyle = 'rgba(27, 36, 46, 0.42)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      for (let x = GRID; x < state.w; x += GRID) {
        ctx.moveTo(x + 0.5, 0);
        ctx.lineTo(x + 0.5, state.h);
      }
      for (let y = GRID; y < state.h; y += GRID) {
        ctx.moveTo(0, y + 0.5);
        ctx.lineTo(state.w, y + 0.5);
      }
      ctx.stroke();

      // Cell pulses.
      for (const p of state.pulses) {
        // fade in first 30 %, hold, fade out last 40 %
        const t = p.age;
        const alpha =
          t < 0.3 ? t / 0.3 : t > 0.6 ? 1 - (t - 0.6) / 0.4 : 1;
        const x = p.cx * GRID;
        const y = p.cy * GRID;
        // Soft fill.
        ctx.fillStyle = `rgba(124, 209, 224, ${(alpha * 0.075).toFixed(3)})`;
        ctx.fillRect(x + 2, y + 2, GRID - 4, GRID - 4);
        // Crisp inline border.
        ctx.strokeStyle = `rgba(124, 209, 224, ${(alpha * 0.28).toFixed(3)})`;
        ctx.lineWidth = 1;
        ctx.strokeRect(x + 0.5, y + 0.5, GRID - 1, GRID - 1);
      }

      // Diagonal scan beam.
      if (state.scanX > -220 && state.scanX < state.w + 220) {
        const beamW = 260;
        const grad = ctx.createLinearGradient(
          state.scanX - beamW / 2, 0, state.scanX + beamW / 2, 0,
        );
        grad.addColorStop(0, 'rgba(124, 209, 224, 0)');
        grad.addColorStop(0.45, 'rgba(124, 209, 224, 0.06)');
        grad.addColorStop(0.55, 'rgba(124, 209, 224, 0.06)');
        grad.addColorStop(1, 'rgba(124, 209, 224, 0)');
        ctx.fillStyle = grad;
        // Slight shear for a diagonal look, drawn with a rotated rect via
        // save/restore + transform.
        ctx.save();
        ctx.translate(state.scanX, 0);
        ctx.transform(1, 0, -0.08, 1, 0, 0);
        ctx.fillRect(-beamW / 2, -50, beamW, state.h + 100);
        ctx.restore();

        // Trailing crisp line at the beam's leading edge.
        ctx.strokeStyle = 'rgba(124, 209, 224, 0.15)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(state.scanX + beamW / 2 - state.h * 0.08, 0);
        ctx.lineTo(state.scanX + beamW / 2, state.h);
        ctx.stroke();
      }

      // Crypto glyphs — real values from the product's fingerprint tables.
      ctx.font = '11px "JetBrains Mono", "Fira Code", ui-monospace, monospace';
      ctx.textBaseline = 'middle';
      for (const g of state.glyphs) {
        const t = g.age;
        const alpha =
          t < 0.2 ? t / 0.2 : t > 0.55 ? 1 - (t - 0.55) / 0.45 : 1;
        ctx.fillStyle = `rgba(124, 209, 224, ${(alpha * 0.55).toFixed(3)})`;
        ctx.fillText(g.text, g.x, g.y);
      }

      raf = requestAnimationFrame(render);
    };

    const onVisibility = () => {
      if (document.hidden) {
        running = false;
        cancelAnimationFrame(raf);
      } else if (!running) {
        running = true;
        state.last = performance.now();
        raf = requestAnimationFrame(render);
      }
    };
    document.addEventListener('visibilitychange', onVisibility);

    raf = requestAnimationFrame(render);

    return () => {
      running = false;
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-0"
    />
  );
};
