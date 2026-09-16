/**
 * useCursorAurora — write cursor coordinates to CSS custom properties.
 *
 * A CSS radial gradient anchored on `--cursor-x` / `--cursor-y` follows the
 * cursor, illuminating the page background wherever the user's attention is.
 * Because the update goes straight to the DOM via `style.setProperty`, no
 * React re-render happens on `mousemove` — the animation is essentially free.
 *
 * The effect is turned off on touch devices (they have no cursor) and when
 * the OS reports reduced-motion preference.
 */
import { useEffect } from 'react';

export function useCursorAurora(enabled: boolean = true): void {
  useEffect(() => {
    if (!enabled) return;
    if (typeof window === 'undefined') return;

    // Skip on touch-only devices and when motion is reduced.
    const isCoarse = window.matchMedia?.('(pointer: coarse)').matches;
    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    if (isCoarse || reduced) return;

    const root = document.documentElement;
    root.classList.add('has-aurora');

    // Prime the position at viewport center so the aurora doesn't flash from
    // the top-left corner on first paint.
    root.style.setProperty('--cursor-x', `${window.innerWidth / 2}px`);
    root.style.setProperty('--cursor-y', `${window.innerHeight / 3}px`);

    let raf = 0;
    let lastX = 0;
    let lastY = 0;

    const handleMove = (event: MouseEvent) => {
      lastX = event.clientX;
      lastY = event.clientY;
      if (raf) return;
      raf = window.requestAnimationFrame(() => {
        root.style.setProperty('--cursor-x', `${lastX}px`);
        root.style.setProperty('--cursor-y', `${lastY}px`);
        raf = 0;
      });
    };

    const handleLeave = () => {
      // Ease the aurora back to a neutral resting point when the cursor
      // leaves the window — CSS transition on the layer handles the smoothing.
      root.style.setProperty('--cursor-x', `${window.innerWidth / 2}px`);
      root.style.setProperty('--cursor-y', `${window.innerHeight / 3}px`);
    };

    window.addEventListener('mousemove', handleMove, { passive: true });
    window.addEventListener('mouseleave', handleLeave);
    return () => {
      window.removeEventListener('mousemove', handleMove);
      window.removeEventListener('mouseleave', handleLeave);
      if (raf) cancelAnimationFrame(raf);
      root.classList.remove('has-aurora');
    };
  }, [enabled]);
}
