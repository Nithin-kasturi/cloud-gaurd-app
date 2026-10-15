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
  evidence_source?: string | null;
  assessment_status?: string | null;
  assessment?: unknown;
  rag_assessment?: unknown;
}

export interface ResourceInventoryResponse {
  source: DataSource;
  region?: string;
  retrieved_at?: string;
  count: number;
  services_monitored: string[];
  service_counts: Record<string, number>;
  resources: ResourceItem[];
  warnings: string[];
  coverage_note?: string;
}

export interface ResourceChangesResponse {
  source: DataSource;
  count?: number;
  region?: string;
  retrieved_at?: string;
  changes: CloudTrailEvent[];
  summary?: { events_with_detected_changes: number; resource_change_records: number };
  coverage_note?: string;
  error?: string;
}

export interface Finding {
  finding_id: string;
  title: string;
  description: string;
  severity: string;
  resource_id?: string | null;
  recommendation: string;
  category?: string;
  assessment_status?: string;
  evidence?: string[];
  confidence?: number | null;
}

export interface FindingsSummary {
  source: DataSource;
  total_findings: number;
  severity_counts: { high: number; medium: number; low: number; [key: string]: number };
  category_counts: Record<string, number>;
}

export interface Ec2Instance {
  instance_id: string;
  instance_type: string;
  state: string;
  availability_zone?: string | null;
  launch_time?: string | null;
  name?: string | null;
}

export interface InventoryChangeInstance {
  instance_id: string;
  name?: string | null;
  instance_type?: string | null;
  state?: string | null;
  changes?: Record<string, { previous?: unknown; current?: unknown }>;
}

export interface InventoryChanges {
  new_instances?: InventoryChangeInstance[];
  missing_instances?: InventoryChangeInstance[];
  changed_instances?: InventoryChangeInstance[];
  unchanged_count?: number;
  message?: string | null;
}

async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`);
  if (!response.ok) {
    let message = `API request failed (${response.status})`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") message = body.detail;
    } catch { /* response may not contain JSON */ }
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

export function getResourceInventory(source: DataSource = "aws"): Promise<ResourceInventoryResponse> {
  return apiGet(`/aws/resources?source=${encodeURIComponent(source)}`);
}
export function getFindings(source: DataSource = "mock") {
  return apiGet<{ source: DataSource; count: number; findings: Finding[] }>(`/aws/findings?source=${encodeURIComponent(source)}`);
}
export function getSummary(source: DataSource = "mock") {
  return apiGet<FindingsSummary>(`/aws/findings/summary?source=${encodeURIComponent(source)}`);
}
export function getInventory(source: DataSource = "mock") {
  return apiGet<{ source: DataSource; count: number; state_counts?: Record<string, number>; instances: Ec2Instance[] }>(`/aws/ec2/inventory?source=${encodeURIComponent(source)}`);
}
export async function getResourceChanges(source: DataSource = "aws"): Promise<ResourceChangesResponse> {
  const response = await apiGet<ResourceChangesResponse & { events?: CloudTrailEvent[] }>(`/aws/resource-changes?source=${encodeURIComponent(source)}`);
  return { ...response, changes: response.changes ?? response.events ?? [] };
}
export function getInventoryChanges(): Promise<InventoryChanges> {
  return apiGet("/db/inventory/changes");
}
export function getCloudTrailEvents(source: DataSource = "mock") {
  return apiGet<{ source: DataSource; count: number; events: CloudTrailEvent[] }>(`/aws/cloudtrail/events?source=${encodeURIComponent(source)}`);
}
export function getAwsIdentity() {
  return apiGet<{ connected: boolean; identity: Record<string, unknown> }>("/api/aws/identity");
}
