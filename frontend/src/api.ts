const API_BASE_URL = "http://localhost:8000";

export type DataSource = "aws" | "mock";

export interface ResourceItem {
  resource_id: string;
  name: string;
  service: string;
  resource_type: string;
  status: string;
  region?: string | null;
  arn?: string | null;
  updated_at?: string | null;
  details?: Record<string, unknown>;
}

export interface CollectorCoverage {
  collector: string;
  service: string;
  status: "ok" | "partial" | "failed";
  resource_count: number;
  permissions: string[];
  error_code?: string | null;
  message?: string | null;
}

export interface ResourceInventoryResponse {
  source: DataSource;
  account_id?: string | null;
  region?: string;
  retrieved_at?: string;
  status?: "ok" | "partial" | "failed";
  count: number;
  services_monitored: string[];
  service_counts: Record<string, number>;
  resources: ResourceItem[];
  coverage?: CollectorCoverage[];
  warnings: string[];
  coverage_note?: string;
}

export type ImpactCategory = "deletion" | "security" | "lifecycle";

export interface CloudTrailEvent {
  event_id: string;
  event_name: string;
  event_source?: string | null;
  event_time?: string | null;
  timestamp?: string | null;
  aws_region?: string | null;
  username?: string | null;
  actor?: string | null;
  identity_type?: string | null;
  actor_arn?: string | null;
  source_ip?: string | null;
  read_only?: boolean | null;
  error_code?: string | null;
  event_category?: string | null;
  resource_id?: string | null;
  resource_ids?: string[];
  resource_type?: string | null;
  action?: string | null;
  impact_category?: ImpactCategory | null;
  evidence_source?: string | null;
  assessment_status?: string | null;
  assessment?: unknown;
  rag_assessment?: unknown;
}

export interface ResourceChangesResponse {
  source: DataSource;
  status?: "ok" | "partial" | "failed";
  count?: number;
  region?: string;
  retrieved_at?: string;
  window?: { start: string; end: string; lookback_days: number };
  truncated?: boolean;
  changes: CloudTrailEvent[];
  coverage_note?: string;
  error?: string;
}

export interface FieldChange {
  previous?: unknown;
  current?: unknown;
}

export interface InventoryDiff {
  added: ResourceItem[];
  removed: ResourceItem[];
  changed: { resource: ResourceItem; changes: Record<string, FieldChange> }[];
  unchanged_count: number;
  compared_services: string[];
  skipped_services: string[];
  previous_collected_at?: string | null;
  current_collected_at?: string | null;
}

export interface SnapshotResult {
  snapshot_id: string;
  collected_at: string;
  status: string;
  count: number;
  changes: InventoryDiff | null;
  message: string | null;
}

async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, init);
  if (!response.ok) {
    let message = `API request failed (${response.status})`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") message = body.detail;
    } catch {
      /* response may not contain JSON */
    }
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

// `refresh` skips the backend's short-lived cache and queries AWS again.
function query(source: DataSource, refresh: boolean): string {
  return `source=${encodeURIComponent(source)}${refresh ? "&refresh=true" : ""}`;
}

export function getResourceInventory(source: DataSource = "aws", refresh = false) {
  return apiRequest<ResourceInventoryResponse>(`/aws/resources?${query(source, refresh)}`);
}

export function getResourceChanges(source: DataSource = "aws", refresh = false) {
  return apiRequest<ResourceChangesResponse>(`/aws/resource-changes?${query(source, refresh)}`);
}

export function createInventorySnapshot() {
  return apiRequest<SnapshotResult>("/aws/resources/snapshot", { method: "POST" });
}