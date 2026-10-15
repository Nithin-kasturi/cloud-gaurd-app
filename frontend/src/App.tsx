import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Alert,
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Button,
  Chip,
  CircularProgress,
  Collapse,
  Divider,
  FormControl,
  InputLabel,
  LinearProgress,
  MenuItem,
  Paper,
  Select,
  Skeleton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
} from "@mui/material";
import type { SelectChangeEvent } from "@mui/material/Select";

import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  Camera,
  CheckCircle2,
  ChevronDown,
  CircleHelp,
  Clock3,
  Cloud,
  Database,
  Layers,
  RefreshCw,
  Server,
  Shield,
  ShieldCheck,
  Sparkles,
} from "lucide-react";

import {
  createInventorySnapshot,
  getResourceChanges,
  getResourceInventory,
  type CloudTrailEvent,
  type DataSource,
  type FieldChange,
  type ResourceItem,
  type SnapshotResult,
} from "./api";

type AssessmentStatus = "assessed" | "unassessed";

const HEALTHY_STATES = new Set([
  "running",
  "available",
  "active",
  "present",
  "in-use",
  "configured",
]);

const TRANSITIONAL_STATES = new Set([
  "pending",
  "starting",
  "stopping",
  "shutting-down",
  "creating",
  "modifying",
  "updating",
]);

const ACTION_LABELS: Record<string, string> = {
  created_or_updated: "Created or updated",
  deleted: "Deleted",
  modified: "Modified",
  failed: "Failed",
  detected: "Detected",
};

const IMPACT_LABELS: Record<string, { label: string; color: string; bg: string }> = {
  deletion: { label: "Deletion", color: "#b42318", bg: "#fef3f2" },
  security: { label: "Security & access", color: "#b54708", bg: "#fffaeb" },
  lifecycle: { label: "Create / start / stop", color: "#3159d9", bg: "#edf2ff" },
};

function formatDate(value?: string | null): string {
  if (!value) return "Time unavailable";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Time unavailable";
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function formatValue(value: unknown): string {
  if (value === undefined || value === null) return "Unknown";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

function normalizeResource(resourceId?: string | null): string {
  if (!resourceId) return "";
  const value = resourceId.trim();
  const s3Arn = value.match(/^arn:[^:]+:s3:::(.+)$/i);
  return (s3Arn ? s3Arn[1] : value).toLowerCase();
}

function deduplicateEvents(events: CloudTrailEvent[]): CloudTrailEvent[] {
  const seen = new Set<string>();
  return events.filter((event) => {
    // Prefer the stable CloudTrail event ID. The fallback handles duplicate
    // records that describe the same event using an ARN and a friendly name.
    const key = event.event_id
      ? `id:${event.event_id}`
      : [
          event.event_name?.toLowerCase() ?? "",
          event.event_source?.toLowerCase() ?? "",
          normalizeResource(event.resource_id),
          event.action?.toLowerCase() ?? "",
          event.timestamp ?? event.event_time ?? "",
        ].join("|");

    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function eventAssessment(event: CloudTrailEvent): AssessmentStatus {
  return event.assessment ||
    event.rag_assessment ||
    event.assessment_status === "assessed"
    ? "assessed"
    : "unassessed";
}

function actionLabel(event: CloudTrailEvent): string {
  if (!event.action) return "Recorded event";
  return ACTION_LABELS[event.action.toLowerCase()] ?? event.action;
}

function stateStyle(state?: string | null) {
  const value = (state ?? "").toLowerCase();
  if (HEALTHY_STATES.has(value)) return { bgcolor: "#ecfdf3", color: "#027a48" };
  if (TRANSITIONAL_STATES.has(value)) return { bgcolor: "#fffaeb", color: "#b54708" };
  return { bgcolor: "#f2f4f7", color: "#475467" };
}

function errorMessage(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

const pageSx = {
  minHeight: "100vh",
  color: "#172033",
  px: { xs: 2, md: 4 },
  py: { xs: 2, md: 3 },
  fontFamily: '"Inter", "Roboto", sans-serif',
};

const panelSx = {
  border: "1px solid #e7ebf2",
  borderRadius: 3,
  boxShadow: "0 2px 8px rgba(16, 24, 40, 0.035)",
  bgcolor: "#fff",
};

const headCellSx = {
  color: "#667085",
  fontWeight: 700,
  fontSize: 12,
  borderColor: "#edf0f5",
  bgcolor: "#fafbfc",
};

interface DiffItem {
  kind: "Added" | "Removed" | "Changed";
  resource: ResourceItem;
  changes?: Record<string, FieldChange>;
}

function App() {
  const [source, setSource] = useState<DataSource>("aws");

  const [inventoryLoading, setInventoryLoading] = useState(true);
  const [inventoryError, setInventoryError] = useState("");
  const [resources, setResources] = useState<ResourceItem[]>([]);
  const [warnings, setWarnings] = useState<string[]>([]);

  const [activityLoading, setActivityLoading] = useState(true);
  const [activityError, setActivityError] = useState("");
  const [events, setEvents] = useState<CloudTrailEvent[]>([]);
  const [windowDays, setWindowDays] = useState<number | null>(null);

  const [snapshot, setSnapshot] = useState<SnapshotResult | null>(null);
  const [snapshotLoading, setSnapshotLoading] = useState(false);
  const [snapshotError, setSnapshotError] = useState("");

  // Ignore responses that belong to an older request (e.g. after switching source).
  const latestRequest = useRef(0);

  const loadDashboard = useCallback(
    async (refresh = false) => {
      const requestId = ++latestRequest.current;
      const isCurrent = () => latestRequest.current === requestId;

      setInventoryLoading(true);
      setActivityLoading(true);
      setInventoryError("");
      setActivityError("");
      setSnapshot(null);
      setSnapshotError("");

      // Inventory and activity load independently: each panel fills in as soon
      // as its own data arrives, and one failing does not blank the other.
      const inventoryTask = getResourceInventory(source, refresh)
        .then((data) => {
          if (!isCurrent()) return;
          setResources(data.resources ?? []);
          setWarnings(data.warnings ?? []);
        })
        .catch((err) => {
          if (!isCurrent()) return;
          setInventoryError(errorMessage(err, "Could not load the resource inventory."));
          setResources([]);
          setWarnings([]);
        })
        .finally(() => {
          if (isCurrent()) setInventoryLoading(false);
        });

      const activityTask = getResourceChanges(source, refresh)
        .then((data) => {
          if (!isCurrent()) return;
          setEvents(data.changes ?? []);
          setWindowDays(data.window?.lookback_days ?? null);
          if (data.error) setActivityError(data.error);
        })
        .catch((err) => {
          if (!isCurrent()) return;
          setActivityError(errorMessage(err, "Could not load resource activity."));
          setEvents([]);
        })
        .finally(() => {
          if (isCurrent()) setActivityLoading(false);
        });

      await Promise.all([inventoryTask, activityTask]);
    },
    [source],
  );

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  const handleSnapshot = async () => {
    setSnapshotLoading(true);
    setSnapshotError("");
    try {
      setSnapshot(await createInventorySnapshot());
    } catch (err) {
      setSnapshotError(errorMessage(err, "Could not save a snapshot."));
    } finally {
      setSnapshotLoading(false);
    }
  };

  const loading = inventoryLoading || activityLoading;
  const loadingMessage = useMemo(() => {
    const pending = [
      inventoryLoading && "resource inventory",
      activityLoading && "resource activity",
    ].filter(Boolean);
    const where = source === "aws" ? "your AWS account" : "demo data";
    return source === "aws"
      ? `Loading ${pending.join(" and ")} from ${where}. Live AWS queries can take a few seconds…`
      : `Loading ${pending.join(" and ")} from ${where}…`;
  }, [inventoryLoading, activityLoading, source]);

  const resourceEvents = useMemo(
    () =>
      deduplicateEvents(events).sort((a, b) => {
        const aTime = new Date(a.timestamp ?? a.event_time ?? 0).getTime();
        const bTime = new Date(b.timestamp ?? b.event_time ?? 0).getTime();
        return bTime - aTime;
      }),
    [events],
  );

  const serviceCount = useMemo(
    () => new Set(resources.map((resource) => resource.service)).size,
    [resources],
  );

  const diff = snapshot?.changes ?? null;
  const diffItems: DiffItem[] = diff
    ? [
        ...diff.added.map((resource): DiffItem => ({ kind: "Added", resource })),
        ...diff.removed.map((resource): DiffItem => ({ kind: "Removed", resource })),
        ...diff.changed.map(
          ({ resource, changes }): DiffItem => ({ kind: "Changed", resource, changes }),
        ),
      ]
    : [];

  const metricCards = [
    {
      label: "Resources monitored",
      value: resources.length,
      note: "Current resources returned by this source",
      icon: <Server size={19} />,
      color: "#3159d9",
      background: "#edf2ff",
      loading: inventoryLoading,
    },
    {
      label: "Services covered",
      value: serviceCount,
      note: "AWS services with at least one resource",
      icon: <Layers size={19} />,
      color: "#027a48",
      background: "#ecfdf3",
      loading: inventoryLoading,
    },
    {
      label: "High-impact changes",
      value: resourceEvents.length,
      note: "Deletions, security changes and lifecycle events",
      icon: <Activity size={19} />,
      color: "#6941c6",
      background: "#f4f0ff",
      loading: activityLoading,
    },
  ];

  const handleSourceChange = (event: SelectChangeEvent<DataSource>) => {
    setSource(event.target.value as DataSource);
  };

  return (
    <Box sx={{ minHeight: "100vh", bgcolor: "#f6f8fb" }}>
      <Box sx={{ position: "sticky", top: 0, zIndex: 1300 }}>
        <Collapse in={loading} unmountOnExit>
          <Paper
            square
            elevation={3}
            role="status"
            aria-live="polite"
            sx={{ bgcolor: "#f5f7ff", borderBottom: "1px solid #dbe3ff" }}
          >
            <LinearProgress />
            <Stack
              direction="row"
              spacing={1.2}
              sx={{ px: 2, py: 1.1, alignItems: "center", justifyContent: "center" }}
            >
              <CircularProgress size={16} />
              <Typography variant="body2" sx={{ fontWeight: 600, color: "#344054" }}>
                {loadingMessage}
              </Typography>
            </Stack>
          </Paper>
        </Collapse>
      </Box>

      <Box sx={pageSx}>
        <Box sx={{ maxWidth: 1600, mx: "auto" }}>
          <Stack
            sx={{
              flexDirection: { xs: "column", sm: "row" },
              alignItems: { xs: "stretch", sm: "center" },
              justifyContent: "space-between",
              gap: 2,
              mb: 4,
            }}
          >
            <Stack
              direction="row"
              spacing={2}
              sx={{
                alignItems: "center",
                bgcolor: "#fff",
                border: "1px solid #e4e7ec",
                borderRadius: 2,
                px: 2,
                py: 1,
              }}
            >
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2.5,
                  display: "grid",
                  placeItems: "center",
                  color: "#fff",
                  background: "linear-gradient(145deg, #3159d9, #6d5ce8)",
                  boxShadow: "0 6px 16px rgba(49, 89, 217, .22)",
                }}
              >
                <Shield size={25} />
              </Box>
              <Box>
                <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }}>
                  <Typography variant="h5" sx={{ fontWeight: 800, letterSpacing: "-.6px" }}>
                    CloudGuard <Box component="span" sx={{ color: "#5269db" }}>AI</Box>
                  </Typography>
                  <Chip
                    size="small"
                    label="BETA"
                    sx={{ fontWeight: 800, fontSize: 10, bgcolor: "#eef2ff", color: "#4338ca" }}
                  />
                </Stack>
                <Typography variant="body2" sx={{ color: "#667085", mt: 0.3 }}>
                  Cloud resource visibility and change tracking
                </Typography>
              </Box>
            </Stack>

            <Stack sx={{ flexDirection: { xs: "column", sm: "row" }, gap: 1.5 }}>
              <FormControl size="small" sx={{ minWidth: 160, bgcolor: "#fff" }}>
                <InputLabel id="data-source-label">Data source</InputLabel>
                <Select<DataSource>
                  labelId="data-source-label"
                  value={source}
                  label="Data source"
                  onChange={handleSourceChange}
                >
                  <MenuItem value="aws">Live AWS</MenuItem>
                  <MenuItem value="mock">Demo data</MenuItem>
                </Select>
              </FormControl>
              <Button
                variant="contained"
                onClick={() => void loadDashboard(true)}
                disabled={loading}
                startIcon={loading ? <CircularProgress size={16} color="inherit" /> : <RefreshCw size={16} />}
                sx={{
                  textTransform: "none",
                  fontWeight: 700,
                  borderRadius: 2,
                  px: 2.2,
                  boxShadow: "none",
                  bgcolor: "#3159d9",
                  "&:hover": { bgcolor: "#2548bd", boxShadow: "none" },
                }}
              >
                {loading ? "Refreshing" : "Refresh data"}
              </Button>
            </Stack>
          </Stack>

          <Paper
            elevation={0}
            sx={{
              ...panelSx,
              p: { xs: 2.5, md: 3.5 },
              mb: 3,
              background: "linear-gradient(110deg, #ffffff 0%, #f5f7ff 100%)",
            }}
          >
            <Stack
              sx={{
                flexDirection: { xs: "column", md: "row" },
                justifyContent: "space-between",
                alignItems: { xs: "flex-start", md: "center" },
                gap: 2,
              }}
            >
              <Box>
                <Typography
                  variant="overline"
                  sx={{ color: "#5269db", fontWeight: 800, letterSpacing: 1.4 }}
                >
                  CLOUD OVERVIEW
                </Typography>
                <Typography
                  variant="h4"
                  sx={{ fontWeight: 800, letterSpacing: "-1px", mt: 0.2, fontSize: { xs: 27, md: 34 } }}
                >
                  Your cloud, at a glance.
                </Typography>
                <Typography sx={{ color: "#667085", mt: 1, maxWidth: 680 }}>
                  See the current state of your resources and the changes that matter most.
                  CloudGuard is read-only; it does not modify your AWS resources.
                </Typography>
              </Box>
              <Stack
                direction="row"
                spacing={1}
                sx={{ bgcolor: "#fff", border: "1px solid #e4e7ec", borderRadius: 2, px: 1.5, py: 1, alignItems: "center" }}
              >
                <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: source === "aws" ? "#12b76a" : "#f79009" }} />
                <Typography variant="body2" sx={{ fontWeight: 700, color: "#344054" }}>
                  {source === "aws" ? "AWS account source" : "Development demo source"}
                </Typography>
              </Stack>
            </Stack>
          </Paper>

          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: { xs: "1fr", sm: "repeat(2, 1fr)", xl: "repeat(3, 1fr)" },
              gap: 2,
              mb: 3,
            }}
          >
            {metricCards.map((card) => (
              <Paper key={card.label} elevation={0} sx={{ ...panelSx, p: 2.5 }}>
                <Stack direction="row" sx={{ alignItems: "flex-start", justifyContent: "space-between" }}>
                  <Box>
                    <Typography variant="body2" sx={{ color: "#667085", fontWeight: 600 }}>
                      {card.label}
                    </Typography>
                    {card.loading ? (
                      <Skeleton width={70} height={48} />
                    ) : (
                      <Typography variant="h4" sx={{ fontWeight: 800, letterSpacing: "-1px", mt: 0.7 }}>
                        {card.value}
                      </Typography>
                    )}
                  </Box>
                  <Box sx={{ width: 42, height: 42, display: "grid", placeItems: "center", borderRadius: 2, color: card.color, bgcolor: card.background }}>
                    {card.icon}
                  </Box>
                </Stack>
                <Typography variant="caption" sx={{ display: "block", mt: 1, color: "#667085" }}>
                  {card.note}
                </Typography>
              </Paper>
            ))}
          </Box>

          <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", xl: "minmax(0, 1.2fr) minmax(380px, .8fr)" }, gap: 3, mb: 3 }}>
            <Paper elevation={0} sx={{ ...panelSx, minWidth: 0 }}>
              <Box sx={{ p: 2.5 }}>
                <Stack direction="row" spacing={2} sx={{ justifyContent: "space-between", alignItems: "flex-start" }}>
                  <Box>
                    <Typography variant="h6" sx={{ fontWeight: 800 }}>Resource inventory</Typography>
                    <Typography variant="body2" sx={{ color: "#667085", mt: 0.5 }}>
                      Resources that exist right now and their current state
                    </Typography>
                  </Box>
                  <Chip
                    icon={<Cloud size={15} />}
                    label={`${resources.length} resources`}
                    variant="outlined"
                    sx={{ fontWeight: 700, borderColor: "#e4e7ec" }}
                  />
                </Stack>
              </Box>
              <Divider sx={{ borderColor: "#edf0f5" }} />

              {inventoryError && (
                <Alert severity="error" sx={{ borderRadius: 0 }}>{inventoryError}</Alert>
              )}
              {warnings.length > 0 && (
                <Alert severity="warning" sx={{ borderRadius: 0 }}>
                  {warnings.map((warning) => (
                    <Typography key={warning} variant="body2">{warning}</Typography>
                  ))}
                </Alert>
              )}

              {inventoryLoading ? (
                <Stack spacing={1.5} sx={{ p: 2.5 }}>
                  <Skeleton height={38} />
                  <Skeleton height={38} />
                  <Skeleton height={38} />
                </Stack>
              ) : resources.length === 0 && !inventoryError ? (
                <Box sx={{ px: 3, py: 5, textAlign: "center" }}>
                  <Server size={28} color="#98a2b3" />
                  <Typography sx={{ fontWeight: 700, mt: 1 }}>No resources returned</Typography>
                  <Typography variant="body2" sx={{ color: "#667085", mt: 0.5 }}>
                    This source did not return any resources.
                  </Typography>
                </Box>
              ) : resources.length > 0 ? (
                <TableContainer sx={{ maxHeight: 560 }}>
                  <Table size="small" stickyHeader aria-label="Resource inventory">
                    <TableHead>
                      <TableRow>
                        {["Resource", "Service", "Type", "State", "Location"].map((label) => (
                          <TableCell key={label} sx={headCellSx}>{label}</TableCell>
                        ))}
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {resources.map((resource) => (
                        <TableRow key={`${resource.service}-${resource.resource_id}`} hover>
                          <TableCell sx={{ borderColor: "#edf0f5", py: 1.6, maxWidth: 320 }}>
                            <Typography variant="body2" sx={{ fontWeight: 700, overflowWrap: "anywhere" }}>
                              {resource.name || "Unnamed resource"}
                            </Typography>
                            <Typography
                              variant="caption"
                              sx={{ color: "#667085", fontFamily: "monospace", overflowWrap: "anywhere" }}
                            >
                              {resource.resource_id}
                            </Typography>
                          </TableCell>
                          <TableCell sx={{ borderColor: "#edf0f5", whiteSpace: "nowrap" }}>
                            {resource.service}
                          </TableCell>
                          <TableCell sx={{ borderColor: "#edf0f5", whiteSpace: "nowrap" }}>
                            {resource.resource_type}
                          </TableCell>
                          <TableCell sx={{ borderColor: "#edf0f5" }}>
                            <Chip
                              size="small"
                              label={resource.status || "Unknown"}
                              sx={{ textTransform: "capitalize", fontWeight: 700, ...stateStyle(resource.status) }}
                            />
                          </TableCell>
                          <TableCell sx={{ borderColor: "#edf0f5", color: "#475467", whiteSpace: "nowrap" }}>
                            {resource.region || "—"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              ) : null}
              <Box sx={{ px: 2.5, py: 1.5, bgcolor: "#fcfcfd", borderTop: "1px solid #edf0f5" }}>
                <Typography variant="caption" sx={{ color: "#667085" }}>
                  Inventory is a current-state view. Deletions and other changes appear under Resource activity.
                </Typography>
              </Box>
            </Paper>

            <Paper elevation={0} sx={{ ...panelSx, minWidth: 0 }}>
              <Box sx={{ p: 2.5 }}>
                <Stack direction="row" spacing={1.2} sx={{ alignItems: "center" }}>
                  <Box sx={{ bgcolor: "#eef2ff", color: "#5269db", borderRadius: 2, p: 1, display: "grid", placeItems: "center" }}>
                    <Sparkles size={19} />
                  </Box>
                  <Box>
                    <Typography variant="h6" sx={{ fontWeight: 800 }}>Inventory changes</Typography>
                    <Typography variant="body2" sx={{ color: "#667085", mt: 0.3 }}>
                      Compare the current inventory with your last saved snapshot
                    </Typography>
                  </Box>
                </Stack>
              </Box>
              <Divider sx={{ borderColor: "#edf0f5" }} />
              {source === "mock" ? (
                <Box sx={{ p: 3 }}>
                  <Alert severity="info" icon={<CircleHelp size={18} />} sx={{ borderRadius: 2 }}>
                    Snapshots are available for live AWS only.
                  </Alert>
                </Box>
              ) : (
                <Box sx={{ p: 2.5 }}>
                  <Button
                    variant="outlined"
                    onClick={() => void handleSnapshot()}
                    disabled={snapshotLoading || inventoryLoading}
                    startIcon={snapshotLoading ? <CircularProgress size={16} /> : <Camera size={16} />}
                    sx={{ textTransform: "none", fontWeight: 700, borderRadius: 2 }}
                  >
                    {snapshotLoading ? "Saving snapshot…" : "Save snapshot & compare"}
                  </Button>

                  {snapshotError && (
                    <Alert severity="warning" sx={{ borderRadius: 2, mt: 2 }}>{snapshotError}</Alert>
                  )}
                  {snapshot?.message && (
                    <Typography variant="body2" sx={{ color: "#667085", mt: 2 }}>
                      {snapshot.message}
                    </Typography>
                  )}

                  {diff && (
                    <>
                      <Box sx={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 1.5, mt: 2 }}>
                        {[
                          { label: "Added", count: diff.added.length, icon: <ArrowUpRight size={17} />, color: "#027a48" },
                          { label: "Removed", count: diff.removed.length, icon: <ArrowDownRight size={17} />, color: "#b54708" },
                          { label: "Changed", count: diff.changed.length, icon: <Activity size={17} />, color: "#5269db" },
                          { label: "Unchanged", count: diff.unchanged_count, icon: <CheckCircle2 size={17} />, color: "#667085" },
                        ].map((item) => (
                          <Box key={item.label} sx={{ border: "1px solid #eaecf0", borderRadius: 2, p: 1.7 }}>
                            <Stack direction="row" spacing={0.8} sx={{ color: item.color, alignItems: "center" }}>
                              {item.icon}
                              <Typography variant="body2" sx={{ color: "#667085", fontWeight: 600 }}>{item.label}</Typography>
                            </Stack>
                            <Typography variant="h5" sx={{ mt: 0.8, fontWeight: 800 }}>{item.count}</Typography>
                          </Box>
                        ))}
                      </Box>

                      {diff.skipped_services.length > 0 && (
                        <Alert severity="info" sx={{ borderRadius: 2, mt: 2 }}>
                          Not compared (incomplete collection in one snapshot): {diff.skipped_services.join(", ")}
                        </Alert>
                      )}

                      {diffItems.map((item) => (
                        <Box
                          key={`${item.kind}-${item.resource.service}-${item.resource.resource_id}`}
                          sx={{ mt: 1.5, p: 1.5, bgcolor: "#fafbfc", borderRadius: 2 }}
                        >
                          <Typography variant="body2" sx={{ fontWeight: 700 }}>
                            {item.kind}: {item.resource.name || item.resource.resource_id}
                          </Typography>
                          <Typography variant="caption" sx={{ color: "#667085", fontFamily: "monospace", overflowWrap: "anywhere" }}>
                            {item.resource.service} · {item.resource.resource_type} · {item.resource.resource_id}
                          </Typography>
                          {Object.entries(item.changes ?? {}).map(([field, values]) => (
                            <Typography key={field} variant="caption" sx={{ display: "block", color: "#475467", mt: 0.5 }}>
                              {field}: {formatValue(values.previous)} → {formatValue(values.current)}
                            </Typography>
                          ))}
                        </Box>
                      ))}
                    </>
                  )}
                </Box>
              )}
            </Paper>
          </Box>

          <Paper elevation={0} sx={{ ...panelSx, minWidth: 0 }}>
            <Box sx={{ p: 2.5 }}>
              <Stack direction="row" spacing={2} sx={{ justifyContent: "space-between", alignItems: "flex-start" }}>
                <Box>
                  <Typography variant="h6" sx={{ fontWeight: 800 }}>Resource activity</Typography>
                  <Typography variant="body2" sx={{ color: "#667085", mt: 0.5 }}>
                    High-impact changes only: deletions, security and access changes, and resources created, started or stopped
                  </Typography>
                </Box>
                <Chip
                  icon={<Clock3 size={15} />}
                  label={`${resourceEvents.length} events`}
                  variant="outlined"
                  sx={{ fontWeight: 700, borderColor: "#e4e7ec", flexShrink: 0 }}
                />
              </Stack>
            </Box>
            <Divider sx={{ borderColor: "#edf0f5" }} />

            {activityError && (
              <Alert severity="error" sx={{ borderRadius: 0 }}>{activityError}</Alert>
            )}

            {activityLoading ? (
              <Stack spacing={1.5} sx={{ p: 2.5 }}><Skeleton height={90} /><Skeleton height={90} /></Stack>
            ) : resourceEvents.length === 0 && !activityError ? (
              <Box sx={{ px: 3, py: 5, textAlign: "center" }}>
                <Activity size={28} color="#98a2b3" />
                <Typography sx={{ fontWeight: 700, mt: 1 }}>
                  {windowDays
                    ? `No high-impact changes in the last ${windowDays} days`
                    : "No high-impact changes in this feed"}
                </Typography>
                <Typography variant="body2" sx={{ color: "#667085", mt: 0.5 }}>
                  Routine reads and minor changes are intentionally not shown here.
                </Typography>
              </Box>
            ) : (
              <Stack divider={<Divider flexItem sx={{ borderColor: "#edf0f5" }} />}>
                {resourceEvents.map((event, index) => {
                  const status = eventAssessment(event);
                  const service = (event.event_source || "").replace(".amazonaws.com", "");
                  const impact = event.impact_category ? IMPACT_LABELS[event.impact_category] : undefined;
                  return (
                    <Box key={event.event_id || `${event.event_name}-${event.timestamp ?? event.event_time}-${index}`} sx={{ p: 2.2 }}>
                      <Stack direction="row" spacing={1.5} sx={{ alignItems: "flex-start" }}>
                        <Box sx={{ mt: 0.2, p: 1, borderRadius: 2, bgcolor: "#f2f4f7", color: "#475467", display: "grid", placeItems: "center" }}>
                          {service.includes("s3") ? <Database size={18} /> : service.includes("ec2") ? <Server size={18} /> : <Activity size={18} />}
                        </Box>
                        <Box sx={{ flex: 1, minWidth: 0 }}>
                          <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start", justifyContent: "space-between" }}>
                            <Typography sx={{ fontWeight: 750, lineHeight: 1.45, overflowWrap: "anywhere" }}>
                              {event.event_name || "Resource event"}
                            </Typography>
                            <Tooltip
                              title={
                                event.action === "failed"
                                  ? "The request was refused (access denied); nothing changed"
                                  : "This is an event classification, not an impact rating"
                              }
                            >
                              <Chip size="small" label={actionLabel(event)} variant="outlined" sx={{ flexShrink: 0, fontWeight: 650, color: "#475467", borderColor: "#d0d5dd" }} />
                            </Tooltip>
                          </Stack>
                          <Typography variant="body2" sx={{ mt: 0.8, color: "#475467", overflowWrap: "anywhere" }}>
                            {event.resource_id || "Resource could not be identified"}
                          </Typography>
                          <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: "wrap", rowGap: 1 }}>
                            {impact && (
                              <Chip size="small" label={impact.label} sx={{ fontWeight: 700, bgcolor: impact.bg, color: impact.color }} />
                            )}
                            {event.resource_type && <Chip size="small" label={event.resource_type} sx={{ bgcolor: "#f8f9fc", color: "#475467", maxWidth: "100%" }} />}
                            {service && <Chip size="small" label={service} sx={{ bgcolor: "#f8f9fc", color: "#475467" }} />}
                            <Chip
                              size="small"
                              icon={status === "assessed" ? <CheckCircle2 size={14} /> : <CircleHelp size={14} />}
                              label={status === "assessed" ? "Assessed" : "Unassessed"}
                              sx={{
                                bgcolor: status === "assessed" ? "#ecfdf3" : "#f2f4f7",
                                color: status === "assessed" ? "#027a48" : "#475467",
                              }}
                            />
                          </Stack>
                          <Stack direction="row" spacing={1} sx={{ mt: 1.2, justifyContent: "space-between", alignItems: "center" }}>
                            <Typography variant="caption" sx={{ color: "#667085" }}>
                              {formatDate(event.timestamp ?? event.event_time)}
                            </Typography>
                            <Accordion
                              disableGutters
                              elevation={0}
                              sx={{
                                bgcolor: "transparent",
                                "&:before": { display: "none" },
                                "&.Mui-expanded": { my: 0 },
                              }}
                            >
                              <AccordionSummary
                                expandIcon={<ChevronDown size={15} />}
                                sx={{
                                  minHeight: "28px !important",
                                  px: 0.5,
                                  "& .MuiAccordionSummary-content": { my: "4px !important" },
                                }}
                              >
                                <Typography variant="caption" sx={{ color: "#5269db", fontWeight: 700 }}>
                                  Technical details
                                </Typography>
                              </AccordionSummary>
                              <AccordionDetails sx={{ px: 0, pb: 0 }}>
                                <Stack spacing={0.7} sx={{ bgcolor: "#f8f9fc", p: 1.5, borderRadius: 2 }}>
                                  <Typography variant="caption" sx={{ overflowWrap: "anywhere" }}>Event ID: {event.event_id || "Unavailable"}</Typography>
                                  <Typography variant="caption" sx={{ overflowWrap: "anywhere" }}>Actor: {event.actor || event.username || event.actor_arn || "Unavailable"}</Typography>
                                  <Typography variant="caption">Region: {event.aws_region || "Unavailable"}</Typography>
                                  <Typography variant="caption">Source IP: {event.source_ip || "Unavailable"}</Typography>
                                  {event.error_code && (
                                    <Typography variant="caption" sx={{ color: "#b42318" }}>Error: {event.error_code}</Typography>
                                  )}
                                  <Typography variant="caption" sx={{ color: "#667085" }}>
                                    Event details are evidence, not by themselves a determination of impact.
                                  </Typography>
                                </Stack>
                              </AccordionDetails>
                            </Accordion>
                          </Stack>
                        </Box>
                      </Stack>
                    </Box>
                  );
                })}
              </Stack>
            )}
            <Box sx={{ px: 2.5, py: 1.7, bgcolor: "#fcfcfd", borderTop: "1px solid #edf0f5" }}>
              <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                <ShieldCheck size={16} color="#027a48" />
                <Typography variant="caption" sx={{ color: "#667085" }}>
                  Advisory only · CloudGuard does not change AWS resources
                </Typography>
              </Stack>
            </Box>
          </Paper>

          <Box
            component="footer"
            sx={{
              display: "flex",
              flexWrap: "wrap",
              justifyContent: "space-between",
              gap: 1,
              mt: 4,
              pt: 2.5,
              borderTop: "1px solid #e4e7ec",
              color: "#667085",
            }}
          >
            <Typography variant="caption">© CloudGuard AI · Read-only cloud monitoring</Typography>
            <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
              <ShieldCheck size={14} />
              <Typography variant="caption">
                {source === "aws" ? "Live AWS source selected" : "Development demo source selected"}
              </Typography>
            </Stack>
          </Box>
        </Box>
      </Box>
    </Box>
  );
}

export default App;