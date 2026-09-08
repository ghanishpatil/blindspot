/**
 * Firebase client configuration tests.
 *
 * Tests run with no env vars regardless of what's in `.env`, because we need
 * to prove the unconfigured path works: the login page must name the missing
 * variables, not crash.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  getFirebaseApp,
  getFirebaseAuth,
  isFirebaseConfigured,
  missingFirebaseConfigKeys,
  resetFirebaseForTests,
} from '@/services/firebase';

// Stub import.meta.env to simulate no-config, regardless of real .env file.
beforeEach(() => {
  resetFirebaseForTests();
  vi.stubEnv('VITE_FIREBASE_API_KEY', '');
  vi.stubEnv('VITE_FIREBASE_AUTH_DOMAIN', '');
  vi.stubEnv('VITE_FIREBASE_PROJECT_ID', '');
  vi.stubEnv('VITE_FIREBASE_STORAGE_BUCKET', '');
  vi.stubEnv('VITE_FIREBASE_MESSAGING_SENDER_ID', '');
  vi.stubEnv('VITE_FIREBASE_APP_ID', '');
});

describe('with no Firebase configuration', () => {
  it('reports itself as unconfigured rather than throwing', () => {
    expect(isFirebaseConfigured()).toBe(false);
  });

  it('names every missing environment variable', () => {
    expect(missingFirebaseConfigKeys()).toEqual([
      'VITE_FIREBASE_API_KEY',
      'VITE_FIREBASE_AUTH_DOMAIN',
      'VITE_FIREBASE_PROJECT_ID',
      'VITE_FIREBASE_APP_ID',
    ]);
  });

  it('returns null instead of initialising a broken app', () => {
    expect(getFirebaseApp()).toBeNull();
    expect(getFirebaseAuth()).toBeNull();
  });
});
