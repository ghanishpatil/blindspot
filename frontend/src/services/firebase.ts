/**
 * Firebase Web SDK initialisation.
 *
 * Config comes from `VITE_FIREBASE_*` environment variables. Firebase web
 * config values are not secrets — they ship in the client bundle by design —
 * but they are environment specific, so they stay out of source control.
 *
 * Initialisation is lazy and tolerant: with no configuration present the app
 * still loads and reports that authentication is unavailable. Phase 1 has to be
 * runnable before a Firebase project exists.
 *
 * Auth flow (implemented in Phase 2):
 *
 *   sign in -> Firebase ID token -> Authorization: Bearer <token>
 *     -> backend verifies with the Admin SDK
 */

import { type FirebaseApp, getApps, initializeApp } from 'firebase/app';
import { type Auth, getAuth } from 'firebase/auth';

export interface FirebaseConfig {
  apiKey: string;
  authDomain: string;
  projectId: string;
  storageBucket: string;
  messagingSenderId: string;
  appId: string;
}

/** Environment variables that must be present for auth to work. */
const REQUIRED_KEYS = [
  'VITE_FIREBASE_API_KEY',
  'VITE_FIREBASE_AUTH_DOMAIN',
  'VITE_FIREBASE_PROJECT_ID',
  'VITE_FIREBASE_APP_ID',
] as const;

function readConfig(): FirebaseConfig {
  return {
    apiKey: import.meta.env.VITE_FIREBASE_API_KEY ?? '',
    authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN ?? '',
    projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID ?? '',
    storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET ?? '',
    messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID ?? '',
    appId: import.meta.env.VITE_FIREBASE_APP_ID ?? '',
  };
}

/** Names of the required env vars that are missing or blank. */
export function missingFirebaseConfigKeys(): string[] {
  const config = readConfig();
  const values: Record<(typeof REQUIRED_KEYS)[number], string> = {
    VITE_FIREBASE_API_KEY: config.apiKey,
    VITE_FIREBASE_AUTH_DOMAIN: config.authDomain,
    VITE_FIREBASE_PROJECT_ID: config.projectId,
    VITE_FIREBASE_APP_ID: config.appId,
  };

  return REQUIRED_KEYS.filter((key) => values[key].trim() === '');
}

export function isFirebaseConfigured(): boolean {
  return missingFirebaseConfigKeys().length === 0;
}

let cachedApp: FirebaseApp | null = null;

/** The Firebase app, or null when configuration is incomplete. */
export function getFirebaseApp(): FirebaseApp | null {
  if (!isFirebaseConfigured()) {
    return null;
  }
  if (cachedApp) {
    return cachedApp;
  }

  const existing = getApps();
  cachedApp = existing.length > 0 ? existing[0]! : initializeApp(readConfig());
  return cachedApp;
}

/** The Auth instance, or null when Firebase is not configured. */
export function getFirebaseAuth(): Auth | null {
  const app = getFirebaseApp();
  return app ? getAuth(app) : null;
}

/**
 * Current user's ID token, or null when not signed in.
 *
 * Every protected API call routes through this so there is exactly one place
 * the token is obtained.
 */
export async function getIdToken(forceRefresh = false): Promise<string | null> {
  const auth = getFirebaseAuth();
  const user = auth?.currentUser;
  if (!user) {
    return null;
  }
  return user.getIdToken(forceRefresh);
}

/** Reset cached state. Test-only. */
export function resetFirebaseForTests(): void {
  cachedApp = null;
}
