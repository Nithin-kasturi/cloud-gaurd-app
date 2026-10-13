
import { useCallback, useEffect, useState } from "react";
import {
  getEvents,
  getFindings,
  getSummary,
  getInventory,
  type CloudTrailEvent,
  type Finding,
  type FindingsSummary,
  type Ec2Instance,
  getInventoryChanges,
  type InventoryChanges,
} from "./api";

import "./App.css";
function App() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [events, setEvents] = useState<CloudTrailEvent[]>([]);
  const [summary, setSummary] = useState<FindingsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [instances, setInstances] = useState<Ec2Instance[]>([]);
  const [inventoryChanges, setInventoryChanges] =
  useState<InventoryChanges | null>(null);

const [changesError, setChangesError] =
  useState<string | null>(null);
  const loadDashboard = useCallback(async () => {
    const [findingsData, summaryData, eventsData, inventoryData] =
  await Promise.all([
    getFindings(),
    getSummary(),
    getEvents(),
    getInventory("mock"),
  ]);

setFindings(findingsData.findings);
setSummary(summaryData);
setEvents(eventsData.events);
setInstances(inventoryData.instances);
    setLoading(true);
    setError("");

    try {
      const [findingsData, summaryData, eventsData] = await Promise.all([
        getFindings(),
        getSummary(),
        getEvents(),
      ]);

      setFindings(findingsData.findings);
      setSummary(summaryData);
      setEvents(eventsData.events);
    } catch {
      setError(
        "Could not load CloudGuard data. Check that the FastAPI backend is running.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDashboard();
    loadInventoryChanges();
  }, [loadDashboard]);
async function loadInventoryChanges() {
  try {
    const data = await getInventoryChanges();
    setInventoryChanges(data);
    setChangesError(null);
  } catch (error) {
    setChangesError(
      error instanceof Error
        ? error.message
        : "Unable to load inventory changes"
    );
  }
}
  const cards = [
    { label: "Total findings", value: summary?.total_findings ?? 0 },
    { label: "High severity", value: summary?.severity_counts.high ?? 0 },
    { label: "Medium severity", value: summary?.severity_counts.medium ?? 0 },
    { label: "Low severity", value: summary?.severity_counts.low ?? 0 },
  ];

  return (
    <main className="dashboard">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">C</div>
          <div>
            <h1>CloudGuard <span>AI</span></h1>
            <p>Cloud security and cost insights</p>
          </div>
        </div>
        <button className="refresh-button" onClick={loadDashboard}>
          ↻ Refresh
        </button>
      </header>

      <section className="welcome">
        <div>
          <p className="eyebrow">OVERVIEW</p>
          <h2>Your cloud, at a glance.</h2>
          <p className="muted">
            Review resource changes and actionable recommendations.
          </p>
        </div>
        <div className="source-badge">
          <span className="status-dot" />
          Mock data · Development
        </div>
      </section>

      {error && <div className="error-banner">{error}</div>}

      <section className="summary-grid">
        {cards.map((card, index) => (
          <article className="summary-card" key={card.label}>
            <div className={`card-icon icon-${index}`}>
              {["▤", "!", "◉", "✓"][index]}
            </div>
            <p>{card.label}</p>
            <strong>{loading ? "—" : card.value}</strong>
            <span className="card-foot">
              {index === 0 ? "Detected by CloudGuard" : "Current findings"}
            </span>
          </article>
        ))}
      </section>
      
<section className="panel inventory-panel">
  <div className="panel-heading">
    <div>
      <h3>EC2 Resources</h3>
      <p>Inventory across your connected cloud environment</p>
    </div>
    <span className="count-badge">
      {instances.length} instances
    </span>
  </div>

  <div className="table-scroll">
    <table>
      <thead>
        <tr>
          <th>Instance</th>
          <th>Type</th>
          <th>State</th>
          <th>Availability zone</th>
        </tr>
      </thead>
      <tbody>
        {instances.map((instance) => (
          <tr key={instance.instance_id}>
            <td>
              <strong>{instance.name || "Unnamed instance"}</strong>
              <span className="cell-subtitle">
                {instance.instance_id}
              </span>
            </td>
            <td>{instance.instance_type}</td>
            <td>
              <span
                className={`severity ${
                  instance.state === "running"
                    ? "severity-low"
                    : "severity-medium"
                }`}
              >
                {instance.state}
              </span>
            </td>
            <td>{instance.availability_zone || "Unknown"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
</section>

  
      <section className="content-grid">
        <article className="panel findings-panel">
          <div className="panel-heading">
            <div>
              <h3>Risk findings</h3>
              <p>Issues and recommended next steps</p>
            </div>
            <span className="count-badge">{findings.length} findings</span>
          </div>

<section className="inventory-changes">
  <h2>EC2 Inventory Changes</h2>

  {changesError && (
    <p className="changes-error">{changesError}</p>
  )}

  {!inventoryChanges && !changesError && (
    <p>Loading inventory changes...</p>
  )}

  {inventoryChanges && (
    <>
      {inventoryChanges.message && (
        <p>{inventoryChanges.message}</p>
      )}

      <div className="change-summary">
        <div className="change-card">
          <span>New Instances</span>
          <strong>
            {inventoryChanges.new_instances.length}
          </strong>
        </div>

        <div className="change-card">
          <span>Missing Instances</span>
          <strong>
            {inventoryChanges.missing_instances.length}
          </strong>
        </div>

        <div className="change-card">
          <span>Changed Instances</span>
          <strong>
            {inventoryChanges.changed_instances.length}
          </strong>
        </div>

        <div className="change-card">
          <span>Unchanged Instances</span>
          <strong>
            {inventoryChanges.unchanged_count}
          </strong>
        </div>
      </div>

      {inventoryChanges.new_instances.map((instance) => (
        <p key={`new-${instance.instance_id}`}>
          <strong>New:</strong> {instance.instance_id}
          {" — "}
          {instance.name ?? "Unnamed instance"}
        </p>
      ))}

      {inventoryChanges.missing_instances.map((instance) => (
        <p key={`missing-${instance.instance_id}`}>
          <strong>Missing from latest snapshot:</strong>{" "}
          {instance.instance_id}
        </p>
      ))}

      {inventoryChanges.changed_instances.map((instance) => (
        <div key={instance.instance_id}>
          <strong>{instance.instance_id}</strong>

          {Object.entries(instance.changes).map(
            ([field, values]) => (
              <p key={field}>
                {field}: {values.previous ?? "Unknown"}
                {" → "}
                {values.current ?? "Unknown"}
              </p>
            )
          )}
        </div>
      ))}

      {inventoryChanges.new_instances.length === 0 &&
        inventoryChanges.missing_instances.length === 0 &&
        inventoryChanges.changed_instances.length === 0 &&
        !inventoryChanges.message && (
          <p>No changes detected between the latest snapshots.</p>
        )}
    </>
  )}
</section>

          {loading ? (
            <p className="empty-state">Loading findings…</p>
          ) : findings.length === 0 ? (
            <p className="empty-state">No findings detected.</p>
          ) : (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Finding</th>
                    <th>Severity</th>
                    <th>Resource</th>
                    <th>Recommendation</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((finding) => (
                    <tr key={finding.finding_id}>
                      <td>
                        <strong>{finding.title}</strong>
                        <span className="cell-subtitle">
                          {finding.description}
                        </span>
                      </td>
                      <td>
                        <span
                          className={`severity severity-${finding.severity.toLowerCase()}`}
                        >
                          {finding.severity}
                        </span>
                      </td>
                      <td className="resource-id">
                        {finding.resource_id ?? "Not identified"}
                      </td>
                      <td>{finding.recommendation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </article>

        <article className="panel activity-panel">
          <div className="panel-heading">
            <div>
              <h3>Resource activity</h3>
              <p>Recent CloudTrail events</p>
            </div>
            <span className="activity-count">{events.length}</span>
          </div>

          {loading ? (
            <p className="empty-state">Loading activity…</p>
          ) : events.length === 0 ? (
            <p className="empty-state">No events available.</p>
          ) : (
            <div className="activity-list">
              {events.map((event) => (
                <div className="activity-item" key={event.event_id}>
                  <div className="activity-marker" />
                  <div className="activity-body">
                    <strong>{event.event_name}</strong>
                    <p>{event.resource_id ?? event.event_source}</p>
                    <span>
                      {event.event_time
                        ? new Date(event.event_time).toLocaleString()
                        : "Time unavailable"}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
          <p className="activity-note">
            Recommendations are advisory. CloudGuard does not modify resources.
          </p>
        </article>
      </section>

      <footer>
        CloudGuard AI · Read-only monitoring · Development environment
      </footer>
    </main>
  );
}

export default App;
