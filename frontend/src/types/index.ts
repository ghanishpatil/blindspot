/**
 * Shared API contracts.
 *
 * These mirror the backend Pydantic models in `backend/app/models/`. The
 * backend serialises with camelCase aliases, so the field names here match the
 * wire format and the Firestore schema exactly.
 *
 * Keep the two in step: a change to a Pydantic model needs a change here.
 */

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

export type CryptoPrimitive =
  | 'drbg'
  | 'mac'
  | 'block-cipher'
  | 'stream-cipher'
  | 'signature'
  | 'hash'
  | 'pke'
  | 'xof'
  | 'kdf'
  | 'key-agree'
  | 'kem'
  | 'ae'
  | 'combiner'
  | 'other'
  | 'unknown';

export type ArtefactType =
  | 'key-exchange'
  | 'signature'
  | 'encryption'
  | 'hash'
  | 'mac'
  | 'key-derivation'
  | 'random'
  | 'certificate'
  | 'unknown';

export type CryptoUsage =
  | 'key_establishment'
  | 'key_transport'
  | 'key_generation'
  | 'digital_signature'
  | 'session_signature'
  | 'certificate_signing'
  | 'code_signing'
  | 'data_encryption'
  | 'data_at_rest_encryption'
  | 'transport_encryption'
  | 'integrity_hash'
  | 'password_hashing'
  | 'message_authentication'
  | 'key_derivation'
  | 'random_generation'
  | 'unknown';

export type SecurityGoal = 'confidentiality' | 'authenticity' | 'integrity' | 'unknown';

export type ParameterStatus = 'resolved' | 'unresolved' | 'not_applicable';

export type DetectionMethod =
  | 'semgrep_api_pattern'
  | 'semgrep_ast_confirmed'
  | 'semgrep_string_match'
  | 'dependency_manifest'
  | 'config_inference'
  | 'unknown';

export type ConfidenceLevel = 'high' | 'medium' | 'low';

export type Criticality = 'low' | 'medium' | 'high';

/** Quantum migration urgency, from Mosca's inequality. */
export type RiskTier = 'overdue' | 'transitional' | 'low-risk';

/** Severity of a present-day weakness. Separate from {@link RiskTier}. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none';

export type QuantumThreat = 'shor_breaks' | 'grover_weakens' | 'none_known' | 'unknown';

export type MigrationStrategy = 'PQC' | 'HYBRID' | 'DEFER' | 'REMEDIATE_NOW' | 'INVESTIGATE';

export type CipherMode =
  | 'cbc'
  | 'ecb'
  | 'ccm'
  | 'gcm'
  | 'cfb'
  | 'ofb'
  | 'ctr'
  | 'other'
  | 'unknown';

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/** Where and how a finding was detected. */
export interface Evidence {
  filePath: string;
  lineNumber: number | null;
  endLineNumber: number | null;
  codeSnippet: string;
  contextLines: string[];
  detectionMethod: DetectionMethod;
  confidence: number;
  confidenceLevel: ConfidenceLevel;
  ruleId: string | null;
}

export interface Classification {
  artefactType: ArtefactType;
  securityGoal: SecurityGoal;
  /** Mosca X. */
  dataLifetimeYears: number;
  criticality: Criticality;
  isLongLivedTrustAnchor: boolean;
  lifetimeSource: string;
  rationale: string;
}

/** Present-day security assessment. Independent of quantum concerns. */
export interface CurrentRisk {
  isCurrentlyWeak: boolean;
  severity: Severity;
  reason: string;
  references: string[];
}

/** Quantum exposure of the primitive, independent of timing. */
export interface QuantumRisk {
  isQuantumVulnerable: boolean;
  threat: QuantumThreat;
  effectiveSecurityLoss: string | null;
  reason: string;
}

/**
 * Mosca's inequality for one finding: `X + Y > Z`.
 *
 * The UI renders {@link equation} verbatim, alongside the individual X, Y, and
 * Z values, so the reasoning is inspectable rather than asserted.
 */
export interface MoscaAssessment {
  x: number;
  y: number;
  z: number;
  equation: string;
  result: boolean;
  tier: RiskTier;
  marginYears: number;
  zSource: string;
  applicable: boolean;
  notes: string | null;
}

export interface Recommendation {
  strategy: MigrationStrategy;
  algorithm: string;
  parameterSet: string | null;
  rationale: string;
  replaces: string | null;
  priority: number;
  effort: string | null;
  migrationNotes: string[];
  references: string[];
  isQuantumRecommendation: boolean;
}

export interface Finding {
  id: string;
  scanId: string | null;
  projectId: string | null;

  algorithm: string;
  displayName: string;
  primitive: CryptoPrimitive;
  parameter: string | null;
  parameterStatus: ParameterStatus;
  mode: CipherMode | null;
  curve: string | null;
  usage: CryptoUsage;
  artefactType: ArtefactType;
  library: string | null;

  evidence: Evidence;
  filePath: string;
  lineNumber: number | null;
  unresolvedParameters: string[];

  classification: Classification | null;
  currentRisk: CurrentRisk | null;
  quantumRisk: QuantumRisk | null;
  mosca: MoscaAssessment | null;
  riskTier: RiskTier | null;
  recommendation: Recommendation | null;

  isQuantumSensitive: boolean;
  isCurrentlyWeak: boolean;
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';

/** Whether results came from a real scan or the cached fallback. Always shown. */
export type ScanMode = 'live' | 'cached';

export interface ScanSummary {
  totalFindings: number;
  quantumSensitive: number;
  overdue: number;
  transitional: number;
  lowRisk: number;
  currentWeakCrypto: number;
  unresolvedParameters: number;
  byAlgorithm: Record<string, number>;
  byArtefactType: Record<string, number>;
  byConfidenceLevel: Record<string, number>;
  filesScanned: number;
}

export interface ScanRequest {
  projectId?: string;
  repositoryPath?: string;
  mode?: ScanMode;
}

export interface ScanResponse {
  scanId: string;
  status: ScanStatus;
  mode: ScanMode;
  repository: string;
  findingCount: number;
  summary: ScanSummary;
  durationSeconds: number | null;
  cbomAvailable: boolean;
  message: string | null;
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

export interface SubsystemStatus {
  available: boolean;
  reason: string | null;
  [key: string]: unknown;
}

export interface ZPreset {
  name: string;
  z: number;
  targetYear: number;
  source: string;
}

export interface MoscaConfig {
  activeZ: number;
  activeZSource: string;
  defaultY: number;
  zPresets: ZPreset[];
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  environment: string;
  phase: string;
  readiness: 'ready' | 'degraded';
  degradedSubsystems: string[];
  subsystems: {
    firebase: SubsystemStatus;
    semgrep: SubsystemStatus;
    demoRepository: SubsystemStatus;
    fallbackCache: SubsystemStatus;
  };
  mosca: MoscaConfig;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Body of a 501 from an endpoint whose phase has not landed yet.
 *
 * The backend returns this instead of invented data, so the UI can say
 * "not built yet" truthfully rather than rendering a plausible fiction.
 */
export interface NotImplementedDetail {
  error: 'not_implemented';
  endpoint: string;
  phase: string;
  message: string;
  implemented: false;
}
