import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert,
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Button,
  Chip,
  CircularProgress,
  Divider,
  FormControl,
  InputLabel,
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
  CheckCircle2,
  ChevronDown,
  CircleHelp,
  Clock3,
  Cloud,
  Database,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
} from "lucide-react";

import {
  getResourceChanges,
  getFindings,
  getSummary,
  getInventory,
  getInventoryChanges,
  type CloudTrailEvent,
  type Finding,
  type FindingsSummary,
  type Ec2Instance,
  type InventoryChanges,
  type DataSource,
} from "./api";

type AssessmentStatus = "assessed" | "unassessed" | "unknown";

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

function normalizeResource(resourceId?: string | null): string {
  if (!resourceId) return "";
  const value = resourceId.trim();
  const s3Arn = value.match(/^arn:[^:]+:s3:::(.+)$/i);
  if (s3Arn) return s3Arn[1].toLowerCase();
  return value.toLowerCase();
}

function deduplicateEvents(events: CloudTrailEvent[]): CloudTrailEvent[] {
  const seen = new Set<string>();
  return events.filter((event) => {
    const resource = normalizeResource(event.resource_id);
    const time = event.timestamp ?? event.event_time ?? "";
    // Prefer the stable CloudTrail event ID. The fallback handles duplicate
    // records that describe the same event using an ARN and a friendly name.
    const key = event.event_id
      ? `id:${event.event_id}`
      : [
          event.event_name?.toLowerCase() ?? "",
          event.event_source?.toLowerCase() ?? "",
          resource,
          event.action?.toLowerCase() ?? "",
          time,
        ].join("|");

    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function eventAssessment(event: CloudTrailEvent): AssessmentStatus {
  const record = event as CloudTrailEvent & {
    assessment?: unknown;
    rag_assessment?: unknown;
    assessment_status?: unknown;
  };
  if (
    record.assessment ||
    record.rag_assessment ||
    record.assessment_status === "assessed"
  ) {
    return "assessed";
  }
  return "unassessed";
}

function assessmentLabel(status: AssessmentStatus): string {
  if (status === "assessed") return "Assessed";
  if (status === "unknown") return "Assessment unavailable";
  return "Unassessed";
}

function actionLabel(event: CloudTrailEvent): string {
  if (event.action) {
    return event.action.charAt(0).toUpperCase() + event.action.slice(1).toLowerCase();
  }
  return "Recorded event";
}

function severityStyle(severity?: string | null) {
  const value = (severity ?? "").toLowerCase();
  if (value === "high" || value === "critical") {
    return { color: "#b42318", backgroundColor: "#fef3f2", borderColor: "#fecdca" };
  }
  if (value === "medium" || value === "moderate") {
    return { color: "#b54708", backgroundColor: "#fffaeb", borderColor: "#fedf89" };
  }
  if (value === "low") {
    return { color: "#027a48", backgroundColor: "#ecfdf3", borderColor: "#abefc6" };
  }
  return { color: "#475467", backgroundColor: "#f2f4f7", borderColor: "#e4e7ec" };
}

const pageSx = {
  minHeight: "100vh",
  bgcolor: "#f6f8fb",
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

function App() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [events, setEvents] = useState<CloudTrailEvent[]>([]);
  const [summary, setSummary] = useState<FindingsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [instances, setInstances] = useState<Ec2Instance[]>([]);
  const [source, setSource] = useState<DataSource>("aws");
  const [inventoryChanges, setInventoryChanges] = useState<InventoryChanges | null>(null);
  const [changesError, setChangesError] = useState<string | null>(null);

  const loadInventoryChanges = useCallback(async () => {
    try {
      const data = await getInventoryChanges();
      setInventoryChanges(data);
      setChangesError(null);
    } catch (err) {
      setChangesError(
        err instanceof Error ? err.message : "Unable to load inventory changes",
      );
    }
  }, []);

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [findingsData, summaryData, changesData, inventoryData] =
        await Promise.all([
          getFindings(source),
          getSummary(source),
          getResourceChanges(source),
          getInventory(source),
        ]);

      setFindings(findingsData.findings ?? []);
      setSummary(summaryData);
      setEvents(changesData.changes ?? []);
      setInstances(inventoryData.instances ?? []);

      if (source === "mock") {
        await loadInventoryChanges();
      } else {
        setInventoryChanges(null);
        setChangesError(null);
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : `Could not load ${source === "aws" ? "AWS" : "mock"} data. Check the backend and AWS access configuration.`,
      );
      setFindings([]);
      setEvents([]);
      setInstances([]);
      setSummary(null);
    } finally {
      setLoading(false);
    }
  }, [source, loadInventoryChanges]);

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  const safeFindings = findings ?? [];
  const safeInstances = instances ?? [];
  const resourceEvents = useMemo(
    () =>
      deduplicateEvents(events ?? []).sort((a, b) => {
        const aTime = new Date(a.timestamp ?? a.event_time ?? 0).getTime();
        const bTime = new Date(b.timestamp ?? b.event_time ?? 0).getTime();
        return bTime - aTime;
      }),
    [events],
  );

  const newInstances = inventoryChanges?.new_instances ?? [];
  const missingInstances = inventoryChanges?.missing_instances ?? [];
  const changedInstances = inventoryChanges?.changed_instances ?? [];
  const unchangedCount = inventoryChanges?.unchanged_count ?? 0;

  const metricCards = [
    {
      label: "Resources monitored",
      value: safeInstances.length,
      note: "EC2 instances currently returned",
      icon: <Server size={19} />,
      color: "#3159d9",
      background: "#edf2ff",
    },
    {
      label: "Resource changes",
      value: resourceEvents.length,
      note: "Unique events in this feed",
      icon: <Activity size={19} />,
      color: "#6941c6",
      background: "#f4f0ff",
    },
    {
      label: "Findings",
      value: summary?.total_findings ?? safeFindings.length,
      note: "Returned by the findings API",
      icon: <ShieldAlert size={19} />,
      color: "#b54708",
      background: "#fff4e5",
    },
    {
      label: "High severity",
      value: summary?.severity_counts?.high ?? 0,
      note: "Severity supplied by backend",
      icon: <TriangleAlert size={19} />,
      color: "#b42318",
      background: "#fff0ef",
    },
  ];

  const handleSourceChange = (event: SelectChangeEvent<DataSource>) => {
    setSource(event.target.value as DataSource);
  };

  return (
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
                Cloud resource visibility and risk insights
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
              onClick={() => void loadDashboard()}
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
                Understand what changed, review assessed findings, and decide what needs attention.
                CloudGuard provides recommendations only; it does not modify your AWS resources.
              </Typography>
            </Box>
            <Stack direction="row"  spacing={1} sx={{ bgcolor: "#fff", border: "1px solid #e4e7ec", borderRadius: 2, px: 1.5, py: 1,alignItems:"center" }}>
              <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: source === "aws" ? "#12b76a" : "#f79009" }} />
              <Typography variant="body2" sx={{ fontWeight: 700, color: "#344054" }}>
                {source === "aws" ? "AWS account source" : "Development demo source"}
              </Typography>
            </Stack>
          </Stack>
        </Paper>

        {error && (
          <Alert severity="error" sx={{ mb: 3, borderRadius: 2 }} onClose={() => setError("")}>
            {error}
          </Alert>
        )}

        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: { xs: "1fr", sm: "repeat(2, 1fr)", xl: "repeat(4, 1fr)" },
            gap: 2,
            mb: 3,
          }}
        >
          {metricCards.map((card) => (
            <Paper key={card.label} elevation={0} sx={{ ...panelSx, p: 2.5 }}>
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
                <Box>
                  <Typography variant="body2" sx={{ color: "#667085", fontWeight: 600 }}>
                    {card.label}
                  </Typography>
                  {loading ? (
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
              <Stack direction="row" sx={{justifyContent:"space-between", alignItems:"flex-start"}} spacing={2}>
                <Box>
                  <Typography variant="h6" sx={{ fontWeight: 800 }}>Resource inventory</Typography>
                  <Typography variant="body2" sx={{ color: "#667085", mt: 0.5 }}>
                    Current EC2 resources and their reported state
                  </Typography>
                </Box>
                <Chip icon={<Cloud size={15} />} label={`${safeInstances.length} instances`} variant="outlined" sx={{ fontWeight: 700, borderColor: "#e4e7ec" }} />
              </Stack>
            </Box>
            <Divider sx={{ borderColor: "#edf0f5" }} />
            {loading ? (
              <Stack spacing={1.5} sx={{ p: 2.5 }}>
                <Skeleton height={38} />
                <Skeleton height={38} />
                <Skeleton height={38} />
              </Stack>
            ) : safeInstances.length === 0 ? (
              <Box sx={{ px: 3, py: 5, textAlign: "center" }}>
                <Server size={28} color="#98a2b3" />
                <Typography sx={{ fontWeight: 700, mt: 1 }}>No EC2 instances returned</Typography>
                <Typography variant="body2" sx={{ color: "#667085", mt: 0.5 }}>
                  This source did not return any EC2 instances.
                </Typography>
              </Box>
            ) : (
              <TableContainer>
                <Table size="small" aria-label="EC2 inventory">
                  <TableHead>
                    <TableRow sx={{ bgcolor: "#fafbfc" }}>
                      {["Resource", "Type", "State", "Zone"].map((label) => (
                        <TableCell key={label} sx={{ color: "#667085", fontWeight: 700, fontSize: 12, borderColor: "#edf0f5" }}>{label}</TableCell>
                      ))}
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {safeInstances.map((instance) => (
                      <TableRow key={instance.instance_id} hover>
                        <TableCell sx={{ borderColor: "#edf0f5", py: 1.6 }}>
                          <Typography variant="body2" sx={{ fontWeight: 700 }}>
                            {instance.name || "Unnamed EC2 instance"}
                          </Typography>
                          <Typography variant="caption" sx={{ color: "#667085", fontFamily: "monospace" }}>
                            {instance.instance_id}
                          </Typography>
                        </TableCell>
                        <TableCell sx={{ borderColor: "#edf0f5", whiteSpace: "nowrap" }}>
                          {instance.instance_type || "Unknown"}
                        </TableCell>
                        <TableCell sx={{ borderColor: "#edf0f5" }}>
                          <Chip
                            size="small"
                            label={instance.state || "Unknown"}
                            sx={{
                              textTransform: "capitalize",
                              fontWeight: 700,
                              bgcolor: instance.state === "running" ? "#ecfdf3" : "#f2f4f7",
                              color: instance.state === "running" ? "#027a48" : "#475467",
                            }}
                          />
                        </TableCell>
                        <TableCell sx={{ borderColor: "#edf0f5", color: "#475467", whiteSpace: "nowrap" }}>
                          {instance.availability_zone || "—"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
            <Box sx={{ px: 2.5, py: 1.5, bgcolor: "#fcfcfd", borderTop: "1px solid #edf0f5" }}>
              <Typography variant="caption" sx={{ color: "#667085" }}>
                Inventory is a current-state view, not a record of when a resource changed.
              </Typography>
            </Box>
          </Paper>

          <Paper elevation={0} sx={{ ...panelSx, minWidth: 0 }}>
            <Box sx={{ p: 2.5 }}>
              <Stack direction="row"  spacing={1.2} sx={{alignItems:"center"}}>
                <Box sx={{ bgcolor: "#eef2ff", color: "#5269db", borderRadius: 2, p: 1, display: "grid", placeItems: "center" }}>
                  <Sparkles size={19} />
                </Box>
                <Box>
                  <Typography variant="h6" sx={{ fontWeight: 800 }}>Inventory changes</Typography>
                  <Typography variant="body2" sx={{ color: "#667085", mt: 0.3 }}>
                    Differences between saved snapshots
                  </Typography>
                </Box>
              </Stack>
            </Box>
            <Divider sx={{ borderColor: "#edf0f5" }} />
            {source === "aws" ? (
              <Box sx={{ p: 3 }}>
                <Alert severity="info" icon={<CircleHelp size={18} />} sx={{ borderRadius: 2 }}>
                  Live AWS snapshot history is not configured yet. This panel is available for demo snapshots only.
                </Alert>
              </Box>
            ) : changesError ? (
              <Box sx={{ p: 2.5 }}>
                <Alert severity="warning" sx={{ borderRadius: 2 }}>{changesError}</Alert>
              </Box>
            ) : !inventoryChanges ? (
              <Box sx={{ p: 2.5 }}><CircularProgress size={20} /></Box>
            ) : (
              <Box sx={{ p: 2.5 }}>
                {inventoryChanges.message && (
                  <Typography variant="body2" sx={{ color: "#667085", mb: 2 }}>
                    {inventoryChanges.message}
                  </Typography>
                )}
                <Box sx={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 1.5 }}>
                  {[
                    { label: "New", count: newInstances.length, icon: <ArrowUpRight size={17} />, color: "#027a48" },
                    { label: "Missing", count: missingInstances.length, icon: <ArrowDownRight size={17} />, color: "#b54708" },
                    { label: "Changed", count: changedInstances.length, icon: <Activity size={17} />, color: "#5269db" },
                    { label: "Unchanged", count: unchangedCount, icon: <CheckCircle2 size={17} />, color: "#667085" },
                  ].map((item) => (
                    <Box key={item.label} sx={{ border: "1px solid #eaecf0", borderRadius: 2, p: 1.7 }}>
                      <Stack direction="row" spacing={0.8} sx={{ color: item.color ,alignItems:"center" }}>
                        {item.icon}
                        <Typography variant="body2" sx={{ color: "#667085", fontWeight: 600 }}>{item.label}</Typography>
                      </Stack>
                      <Typography variant="h5" sx={{ mt: 0.8, fontWeight: 800 }}>{item.count}</Typography>
                    </Box>
                  ))}
                </Box>
                {[...newInstances.map((item) => ({ ...item, changeKind: "New" })), ...missingInstances.map((item) => ({ ...item, changeKind: "Missing" })), ...changedInstances.map((item) => ({ ...item, changeKind: "Changed" }))].map((item) => (
                  <Box key={`${item.changeKind}-${item.instance_id}`} sx={{ mt: 1.5, p: 1.5, bgcolor: "#fafbfc", borderRadius: 2 }}>
                    <Typography variant="body2" sx={{ fontWeight: 700 }}>{item.changeKind}: {item.name || item.instance_id}</Typography>
                    <Typography variant="caption" sx={{ color: "#667085", fontFamily: "monospace" }}>{item.instance_id}</Typography>
                    {"changes" in item && Object.entries(item.changes ?? {}).map(([field, values]) => (
                      <Typography key={field} variant="caption" sx={{ color: "#475467", mt: 0.5 }}>
                        {field}: {String(values.previous ?? "Unknown")} → {String(values.current ?? "Unknown")}
                      </Typography>
                    ))}
                  </Box>
                ))}
              </Box>
            )}
          </Paper>
        </Box>

        <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", xl: "minmax(0, 1.15fr) minmax(380px, .85fr)" }, gap: 3 }}>
          <Paper elevation={0} sx={{ ...panelSx, minWidth: 0 }}>
            <Box sx={{ p: 2.5 }}>
              <Stack direction="row" sx={{justifyContent:"space-between", alignItems:"flex-start"}} spacing={2}>
                <Box>
                  <Typography variant="h6" sx={{ fontWeight: 800 }}>Findings & recommendations</Typography>
                  <Typography variant="body2" sx={{ color: "#667085", mt: 0.5 }}>
                    Findings returned by CloudGuard's backend assessment
                  </Typography>
                </Box>
                <Chip label={`${safeFindings.length} findings`} variant="outlined" sx={{ fontWeight: 700, borderColor: "#e4e7ec" }} />
              </Stack>
            </Box>
            <Divider sx={{ borderColor: "#edf0f5" }} />
            {loading ? (
              <Stack spacing={1.5} sx={{ p: 2.5 }}><Skeleton height={72} /><Skeleton height={72} /></Stack>
            ) : safeFindings.length === 0 ? (
              <Box sx={{ px: 3, py: 5, textAlign: "center" }}>
                <ShieldCheck size={30} color="#12b76a" />
                <Typography sx={{ fontWeight: 700, mt: 1 }}>No findings returned</Typography>
                <Typography variant="body2" sx={{ color: "#667085", mt: 0.5 }}>
                  This does not necessarily mean every resource has been assessed.
                </Typography>
              </Box>
            ) : (
              <Stack divider={<Divider flexItem sx={{ borderColor: "#edf0f5" }} />}>
                {safeFindings.map((finding) => (
                  <Accordion
                    key={finding.finding_id}
                    disableGutters
                    elevation={0}
                    sx={{
                      "&:before": { display: "none" },
                      "&.Mui-expanded": { my: 0 },
                    }}
                  >
                    <AccordionSummary
                      expandIcon={<ChevronDown size={18} />}
                      sx={{ px: 2.5, py: 0.8, "& .MuiAccordionSummary-content": { my: 1.1 } }}
                    >
                      <Box sx={{ width: "100%", minWidth: 0, pr: 1 }}>
                        <Stack sx={{ flexDirection: { xs: "column", sm: "row" }, alignItems: { xs: "flex-start", sm: "center" }, gap: 1, mb: 0.5 }}>
                          <Typography sx={{ fontWeight: 750, color: "#172033" }}>{finding.title}</Typography>
                          <Chip
                            size="small"
                            label={finding.severity || "Unspecified"}
                            sx={{ fontWeight: 700, border: "1px solid", ...severityStyle(finding.severity) }}
                          />
                        </Stack>
                        <Typography variant="body2" sx={{ color: "#667085", overflowWrap: "anywhere" }}>
                          {finding.description}
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails sx={{ px: 2.5, pt: 0, pb: 2.5 }}>
                      <Stack spacing={1.5}>
                        <Box sx={{ bgcolor: "#f8f9fc", borderRadius: 2, p: 1.8 }}>
                          <Typography variant="caption" sx={{ color: "#667085", fontWeight: 800, textTransform: "uppercase", letterSpacing: ".6px" }}>
                            Recommended next step
                          </Typography>
                          <Typography variant="body2" sx={{ mt: 0.7, lineHeight: 1.7 }}>
                            {finding.recommendation || "No recommendation was supplied."}
                          </Typography>
                        </Box>
                        <Stack direction="row" spacing={1} sx={{alignItems:"flex-start"}}>
                          <Database size={16} color="#667085" />
                          <Box>
                            <Typography variant="caption" sx={{ color: "#667085" }}>Resource</Typography>
                            <Typography variant="body2" sx={{ fontFamily: "monospace", overflowWrap: "anywhere" }}>
                              {finding.resource_id || "Not identified"}
                            </Typography>
                          </Box>
                        </Stack>
                        {finding.category && (
                          <Typography variant="caption" sx={{ color: "#667085" }}>
                            Category: {finding.category}
                          </Typography>
                        )}
                      </Stack>
                    </AccordionDetails>
                  </Accordion>
                ))}
              </Stack>
            )}
          </Paper>

          <Paper elevation={0} sx={{ ...panelSx, minWidth: 0 }}>
            <Box sx={{ p: 2.5 }}>
              <Stack direction="row" sx={{justifyContent:"space-between", alignItems:"flex-start"}} spacing={2}>
                <Box>
                  <Typography variant="h6" sx={{ fontWeight: 800 }}>Resource activity</Typography>
                  <Typography variant="body2" sx={{ color: "#667085", mt: 0.5 }}>
                    Unique resource-related events from CloudTrail
                  </Typography>
                </Box>
                <Chip icon={<Clock3 size={15} />} label={`${resourceEvents.length} events`} variant="outlined" sx={{ fontWeight: 700, borderColor: "#e4e7ec" }} />
              </Stack>
            </Box>
            <Divider sx={{ borderColor: "#edf0f5" }} />
            {loading ? (
              <Stack spacing={1.5} sx={{ p: 2.5 }}><Skeleton height={90} /><Skeleton height={90} /></Stack>
            ) : resourceEvents.length === 0 ? (
              <Box sx={{ px: 3, py: 5, textAlign: "center" }}>
                <Activity size={28} color="#98a2b3" />
                <Typography sx={{ fontWeight: 700, mt: 1 }}>No resource changes in this feed</Typography>
                <Typography variant="body2" sx={{ color: "#667085", mt: 0.5 }}>
                  Routine read-only API calls are intentionally not shown here.
                </Typography>
              </Box>
            ) : (
              <Stack divider={<Divider flexItem sx={{ borderColor: "#edf0f5" }} />}>
                {resourceEvents.map((event, index) => {
                  const status = eventAssessment(event);
                  const service = (event.event_source || "").replace(".amazonaws.com", "");
                  return (
                    <Box key={event.event_id || `${event.event_name}-${event.timestamp ?? event.event_time}-${index}`} sx={{ p: 2.2 }}>
                      <Stack direction="row" spacing={1.5} sx={{alignItems:"flex-start"}}>
                        <Box sx={{ mt: 0.2, p: 1, borderRadius: 2, bgcolor: "#f2f4f7", color: "#475467", display: "grid", placeItems: "center" }}>
                          {service.includes("s3") ? <Database size={18} /> : service.includes("ec2") ? <Server size={18} /> : <Activity size={18} />}
                        </Box>
                        <Box sx={{ flex: 1, minWidth: 0 }}>
                          <Stack direction="row" sx={{alignItems:"flex-start" ,justifyContent:"space-between"}} spacing={1}>
                            <Typography sx={{ fontWeight: 750, lineHeight: 1.45, overflowWrap: "anywhere" }}>
                              {event.event_name || "Resource event"}
                            </Typography>
                            <Tooltip title="This is an event classification, not an impact rating">
                              <Chip size="small" label={actionLabel(event)} variant="outlined" sx={{ flexShrink: 0, fontWeight: 650, color: "#475467", borderColor: "#d0d5dd" }} />
                            </Tooltip>
                          </Stack>
                          <Typography variant="body2" sx={{ mt: 0.8, color: "#475467", overflowWrap: "anywhere" }}>
                            {event.resource_id || "Resource could not be identified"}
                          </Typography>
                          <Stack direction="row"  sx={{ mt: 1 ,flexWrap:"wrap"}}>
                            {event.resource_type && <Chip size="small" label={event.resource_type} sx={{ bgcolor: "#f8f9fc", color: "#475467", maxWidth: "100%" }} />}
                            {service && <Chip size="small" label={service} sx={{ bgcolor: "#f8f9fc", color: "#475467" }} />}
                            <Chip
                              size="small"
                              icon={status === "assessed" ? <CheckCircle2 size={14} /> : <CircleHelp size={14} />}
                              label={assessmentLabel(status)}
                              sx={{
                                bgcolor: status === "assessed" ? "#ecfdf3" : "#f2f4f7",
                                color: status === "assessed" ? "#027a48" : "#475467",
                              }}
                            />
                          </Stack>
                          <Stack direction="row"  spacing={1} sx={{ mt: 1.2 ,justifyContent:"space-between", alignItems:"center"}}>
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
              <Stack direction="row" spacing={1} sx={{alignItems:"center"}}>
                <ShieldCheck size={16} color="#027a48" />
                <Typography variant="caption" sx={{ color: "#667085" }}>
                  Advisory only · CloudGuard does not change AWS resources
                </Typography>
              </Stack>
            </Box>
          </Paper>
        </Box>

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
          <Stack direction="row" spacing={1}sx={{ alignItems:"center"}}>
            <ShieldCheck size={14} />
            <Typography variant="caption">{source === "aws" ? "Live AWS source selected" : "Development demo source selected"}</Typography>
          </Stack>
        </Box>
      </Box>
    </Box>
  );
}

export default App;
