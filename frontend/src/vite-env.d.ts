/// <reference types="vite/client" />

/**
 * Typed environment variables.
 *
 * Everything is optional at the type level and validated at runtime, so a
 * missing variable produces a readable message in the UI rather than an
 * undefined value propagating silently.
 */
interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;

  readonly VITE_FIREBASE_API_KEY?: string;
  readonly VITE_FIREBASE_AUTH_DOMAIN?: string;
  readonly VITE_FIREBASE_PROJECT_ID?: string;
  readonly VITE_FIREBASE_STORAGE_BUCKET?: string;
  readonly VITE_FIREBASE_MESSAGING_SENDER_ID?: string;
  readonly VITE_FIREBASE_APP_ID?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
