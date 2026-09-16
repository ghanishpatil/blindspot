/**
 * useReveal — one-shot IntersectionObserver hook for scroll-in reveals.
 *
 * Returns a ref to attach to the target element and a boolean that flips to
 * true the first time the target intersects the viewport. Once revealed we
 * disconnect the observer, so the animation runs exactly once and never
 * flickers if the user scrolls back up.
 *
 * Pair with the `.reveal-target` CSS class (see index.css). Add a stagger by
 * setting `style={{ transitionDelay: `${idx * 80}ms` }}` on child elements.
 */
import { useEffect, useRef, useState } from 'react';

export interface UseRevealOptions {
  /** IntersectionObserver threshold (0..1). Default 0.15. */
  threshold?: number;
  /** rootMargin — pulls the trigger inward, so reveals fire slightly early. */
  rootMargin?: string;
}

export function useReveal<T extends HTMLElement = HTMLElement>({
  threshold = 0.15,
  rootMargin = '0px 0px -8% 0px',
}: UseRevealOptions = {}) {
  const ref = useRef<T | null>(null);
  const [revealed, setRevealed] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (revealed) return;
    // Reduced motion — reveal immediately, skip the animation.
    if (typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) {
      setRevealed(true);
      return;
    }
    // Environments without IntersectionObserver (jsdom tests, older engines):
    // reveal immediately so content is always visible.
    if (typeof IntersectionObserver === 'undefined') {
      setRevealed(true);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setRevealed(true);
            observer.disconnect();
            return;
          }
        }
      },
      { threshold, rootMargin },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [revealed, threshold, rootMargin]);

  return { ref, revealed };
}
