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
  | 'hardware-module'
  | 'cloud-service'
  | 'protocol'
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
  | 'tls_probe'
  | 'binary_signature'
  | 'infra_declaration'
  | 'static_cert_file'
  | 'static_key_material'
  | 'static_keystore'
  | 'pkcs11_attested'
  | 'aws_kms_attested'
  | 'azure_kv_attested'
  | 'gcp_kms_attested'
  | 'config_policy_declared'
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

/** Published FIPS parameter sizes for a PQC target — the honest "cost" signal. */
export interface CostProfile {
  target: string;
  publicKeyBytes: number | null;
  ciphertextBytes: number | null;
  signatureBytes: number | null;
  privateKeyBytes: number | null;
  classicalPublicKeyBytes: number | null;
  classicalSignatureBytes: number | null;
  relativeCost: string;
  sizeSummary: string;
  basis: string;
  sources: string[];
}

/**
 * Cited reference-latency profile for a PQC target.
 *
 * Every field either came from a published source (CRYSTALS submissions,
 * Cloudflare / IETF measurement papers) or is intentionally absent. The UI
 * MUST render `platformNote` alongside any cycle count and MUST label the
 * whole block as reference-only, never as this system's measured latency.
 */
export interface LatencyProfile {
  target: string;
  keygenCycles: number | null;
  encapsulateCycles: number | null;
  decapsulateCycles: number | null;
  signCycles: number | null;
  verifyCycles: number | null;
  classicalSignCycles: number | null;
  classicalVerifyCycles: number | null;
  classicalEncapsulateCycles: number | null;
  classicalDecapsulateCycles: number | null;
  handshakeExtraBytes: number | null;
  handshakeExtraBytesSource: string | null;
  relativeLatency: string;
  summary: string;
  platformNote: string;
  basis: string;
  sources: string[];
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
  costProfile?: CostProfile | null;
  latencyProfile?: LatencyProfile | null;
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
  /** Confidentiality + quantum-vulnerable + overdue: harvest-now-decrypt-later. */
  isHndlExposed: boolean;
  /** Low detection confidence or an unresolved parameter — flag for manual review. */
  needsVerification: boolean;
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
  hndlExposed: number;
  needsVerification: number;
  unresolvedParameters: number;
  byAlgorithm: Record<string, number>;
  byArtefactType: Record<string, number>;
  byConfidenceLevel: Record<string, number>;
  filesScanned: number;
}

export interface ScanRequest {
  projectId?: string;
  repositoryUrl?: string;
  repositoryPath?: string;
  /** Container image reference to pull (via a host container CLI) and scan. */
  imageRef?: string;
  /** Local saved image archive (docker save / OCI). Development only. */
  imageArchivePath?: string;
  /**
   * Optional live TLS endpoints to probe alongside the repository / image
   * scan. Each entry is `host` (defaults to 443) or `host:port`. Findings
   * from these probes flow through the SAME classifier + risk engine +
   * recommender as source findings, so a real ECDSA certificate is
   * treated identically to ECDSA in source code.
   *
   * Serialised as `tls_targets` on the wire (backend uses snake_case).
   */
  tlsTargets?: string[];
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

/**
 * Storage backend state, reported by the health endpoint.
 *
 * `requested` is exactly what the operator set (auto | local | firebase).
 * `effective` is what the running process resolved to; this is the one to
 * point at when someone asks "prove nothing leaves the box" -- when it
 * reads `local` the tool has zero outbound Firebase traffic on any code
 * path, and every scan lands on `artifactsDir` + `fallbackCachePath`.
 */
export interface StorageStatus {
  requested: 'auto' | 'local' | 'firebase' | string;
  effective: 'local' | 'firebase' | string;
  artifactsDir: string;
  fallbackCachePath: string;
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
  /**
   * Optional -- present on backends that report the storage-backend
   * resolution. Missing on older builds, which the UI degrades to
   * "unknown".
   */
  storage?: StorageStatus;
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


// ---------------------------------------------------------------------------
// Migration Roadmap (hero)
// ---------------------------------------------------------------------------

/** One finding placed in the migration plan. Mirrors backend RoadmapItem. */
export interface RoadmapItem {
  findingId: string;
  displayName: string;
  algorithm: string;
  filePath: string;
  lineNumber: number | null;
  strategy: MigrationStrategy;
  currentAlgorithm: string;
  targetAlgorithm: string;
  parameterSet: string | null;
  riskTier: RiskTier | null;
  criticality: string | null;
  priorityScore: number;
  blastRadius: number;
  effort: string;
  costBand: string;
  rationale: string;
  isCurrentWeakness: boolean;
}

/** An ordered group of roadmap items sharing a migration strategy. */
export interface MigrationWave {
  key: string;
  order: number;
  title: string;
  description: string;
  strategy: MigrationStrategy;
  items: RoadmapItem[];
  itemCount: number;
}

/** The full prioritized, costed migration plan for a scan. */
export interface MigrationRoadmap {
  scanId: string | null;
  generatedAt: string;
  totalItems: number;
  waves: MigrationWave[];
  summary: Record<string, number>;
}

// ---------------------------------------------------------------------------
// Compliance Sensitivity (re-tier findings under alternate quantum horizons)
// ---------------------------------------------------------------------------

/** A named quantum horizon (regulatory deadline or research estimate). */
export interface CompliancePreset {
  name: string;
  z: number;
  targetYear: number;
  source: string;
}

/** One finding's Mosca urgency under one preset's Z. */
export interface ComplianceTier {
  tier: RiskTier;
  applicable: boolean;
  x: number;
  y: number;
  z: number;
  equation: string;
  marginYears: number;
}

/** A finding with its tier under every preset, keyed by preset name. */
export interface ComplianceFinding {
  findingId: string;
  displayName: string;
  algorithm: string;
  filePath: string;
  lineNumber: number | null;
  criticality: string | null;
  isQuantumVulnerable: boolean;
  baselineTier: RiskTier;
  tiersByPreset: Record<string, ComplianceTier>;
}

/** Tier counts for all findings under one preset. */
export interface ComplianceSummary {
  overdue: number;
  transitional: number;
  lowRisk: number;
  notApplicable: number;
  total: number;
  overdueDelta: number;
}

/** The full compliance-sensitivity matrix for one scan. */
export interface ComplianceEvaluation {
  scanId: string | null;
  generatedAt: string;
  baselinePresetName: string;
  totalFindings: number;
  presets: CompliancePreset[];
  findings: ComplianceFinding[];
  summaryByPreset: Record<string, ComplianceSummary>;
}

// ---------------------------------------------------------------------------
// Live TLS / certificate scan
// ---------------------------------------------------------------------------

export interface TlsCertificate {
  subject: string;
  issuer: string;
  notAfter: string;
  expired: boolean;
  signatureAlgorithm: string;
  keyType: string;
  keyBits: number | null;
  curve: string | null;
}

export interface TlsScanResult {
  host: string;
  port: number;
  protocol: string;
  protocolSecure: boolean;
  cipherSuite: string | null;
  cipherBits: number | null;
  certificate: TlsCertificate;
  notes: string[];
  findings: Finding[];
}
