
const API_BASE_URL = "http://127.0.0.1:8000";

export interface Finding {
  finding_id: string;
  category: string;
  severity: string;
  resource_id: string | null;
  resource_type: string;
  title: string;
  description: string;
  recommendation: string;
  event_time?: string;
}

export interface FindingsSummary {
  source: string;
  total_findings: number;
  severity_counts: Record<string, number>;
  category_counts: Record<string, number>;
}

export interface CloudTrailEvent {
  event_id: string;
  event_name: string;
  event_source: string;
  event_time: string | null;
  aws_region: string;
  username: string;
  resource_id?: string | null;
}

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`);

  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export const getFindings = () =>
  fetchJson<{ findings: Finding[] }>("/aws/findings?source=mock");

export const getSummary = () =>
  fetchJson<FindingsSummary>("/aws/findings/summary?source=mock");

export const getEvents = () =>
  fetchJson<{ events: CloudTrailEvent[] }>(
    "/aws/cloudtrail/events?source=mock",
  );

export interface Ec2Instance {
  instance_id: string;
  instance_type: string;
  state: string;
  availability_zone: string;
  launch_time: string | null;
  name: string;
}

export interface Ec2Inventory {
  source: string;
  count: number;
  state_counts: Record<string, number>;
  instances: Ec2Instance[];
}

export const getInventory = (source: "mock" | "aws" = "mock") =>
  fetchJson<Ec2Inventory>(`/aws/ec2/inventory?source=${source}`);


export interface InventoryChange {
  instance_id: string;
  instance_type?: string;
  state?: string;
  availability_zone?: string;
  name?: string;
}

export interface ChangedInstance {
  instance_id: string;
  changes: Record<
    string,
    {
      previous: string | null;
      current: string | null;
    }
  >;
}

export interface InventoryChanges {
  message?: string;
  previous_snapshot_id?: string;
  latest_snapshot_id?: string;
  previous_snapshot_at?: string;
  latest_snapshot_at?: string;
  new_instances: InventoryChange[];
  missing_instances: InventoryChange[];
  changed_instances: ChangedInstance[];
  unchanged_count: number;
}

export async function getInventoryChanges(): Promise<InventoryChanges> {
  const response = await fetch(
    `${API_BASE_URL}/db/inventory/changes`
  );

  if (!response.ok) {
    throw new Error("Failed to fetch inventory changes");
  }

  return response.json();
}
