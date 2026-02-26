import { useState, useEffect, useRef } from "react";
import axios from "axios";
import toast, { Toaster } from "react-hot-toast";
import { PieChart, Pie, Cell, AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import "./App.css";

const API = "http://localhost:8000";
const WS  = "ws://localhost:8000/ws";

const SEVERITY_COLORS = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#22c55e",
};

const THREAT_COLORS = ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#8b5cf6"];

export default function App() {
  const [alerts, setAlerts]         = useState([]);
  const [summary, setSummary]       = useState(null);
  const [connected, setConnected]   = useState(false);
  const [trafficData, setTrafficData] = useState([]);
  const [activeTab, setActiveTab]   = useState("dashboard");
  const [filter, setFilter]         = useState("ALL");
  const wsRef     = useRef(null);
  const alertsRef = useRef(alerts);
  alertsRef.current = alerts;

  // ── Load initial alerts + summary ──
  useEffect(() => {
    fetchAlerts();
    fetchSummary();
    connectWebSocket();
    return () => wsRef.current?.close();
  }, []);

  const fetchAlerts = async () => {
    try {
      const res = await axios.get(`${API}/alerts/?limit=100`);
      setAlerts(res.data);
    } catch (err) {
      console.error("Failed to fetch alerts");
    }
  };

  const fetchSummary = async () => {
    try {
      const res = await axios.get(`${API}/alerts/stats/summary`);
      setSummary(res.data);
    } catch (err) {
      console.error("Failed to fetch summary");
    }
  };

  const connectWebSocket = () => {
    const ws = new WebSocket(WS);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      console.log("✅ WebSocket connected");
    };

    ws.onmessage = (event) => {
      const alert = JSON.parse(event.data);

      // Prepend new alert to list
      setAlerts(prev => [alert, ...prev].slice(0, 100));

      // Update traffic chart
      setTrafficData(prev => {
        const now = new Date().toLocaleTimeString();
        const updated = [...prev, { time: now, threats: 1 }].slice(-20);
        return updated;
      });

      // Toast notification for critical
      if (alert.severity === "CRITICAL") {
        toast.error(`🚨 ${alert.threat_type} from ${alert.src_ip}`, { duration: 3000 });
      } else if (alert.severity === "HIGH") {
        toast(`⚠️ ${alert.threat_type} from ${alert.src_ip}`, { duration: 2000 });
      }

      // Refresh summary
      fetchSummary();
    };

    ws.onclose = () => {
      setConnected(false);
      console.log("WebSocket closed — reconnecting in 3s...");
      setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = () => {
      ws.close();
    };
  };

  // Filter alerts
  const filteredAlerts = filter === "ALL"
    ? alerts
    : alerts.filter(a => a.severity === filter || a.threat_type === filter);

  // Pie chart data
  const pieData = summary?.breakdown?.map((b, i) => ({
    name:  b.type,
    value: b.count,
    color: THREAT_COLORS[i % THREAT_COLORS.length]
  })) || [];

  return (
    <div className="app">
      <Toaster position="top-right" />

      {/* ── HEADER ── */}
      <header className="header">
        <div className="header-left">
          <span className="logo">🛡️</span>
          <div>
            <h1 className="logo-title">CCNCS Threat Detection</h1>
            <p className="logo-sub">Intelligent Network Security Framework</p>
          </div>
        </div>
        <div className="header-right">
          <div className={`ws-status ${connected ? "connected" : "disconnected"}`}>
            <span className="ws-dot"></span>
            {connected ? "Live" : "Reconnecting..."}
          </div>
        </div>
      </header>

      {/* ── TABS ── */}
      <div className="tabs">
        <button className={`tab ${activeTab === "dashboard" ? "active" : ""}`} onClick={() => setActiveTab("dashboard")}>📊 Dashboard</button>
        <button className={`tab ${activeTab === "alerts" ? "active" : ""}`} onClick={() => setActiveTab("alerts")}>🚨 Live Alerts</button>
      </div>

      {/* ── DASHBOARD TAB ── */}
      {activeTab === "dashboard" && (
        <div className="dashboard">

          {/* Stats Cards */}
          <div className="stats-grid">
            <div className="stat-card total">
              <div className="stat-icon">📡</div>
              <div className="stat-number">{summary?.total_alerts ?? 0}</div>
              <div className="stat-label">Total Alerts</div>
            </div>
            <div className="stat-card critical">
              <div className="stat-icon">🔴</div>
              <div className="stat-number">{summary?.critical ?? 0}</div>
              <div className="stat-label">Critical</div>
            </div>
            <div className="stat-card high">
              <div className="stat-icon">🟠</div>
              <div className="stat-number">{summary?.high ?? 0}</div>
              <div className="stat-label">High</div>
            </div>
            <div className="stat-card medium">
              <div className="stat-icon">🟡</div>
              <div className="stat-number">{summary?.medium ?? 0}</div>
              <div className="stat-label">Medium</div>
            </div>
          </div>

          {/* Charts Row */}
          <div className="charts-row">

            {/* Live Threat Timeline */}
            <div className="chart-card wide">
              <h3 className="chart-title">📈 Live Threat Timeline</h3>
              {trafficData.length === 0 ? (
                <div className="chart-empty">Waiting for live threats...</div>
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={trafficData}>
                    <defs>
                      <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#888" }} />
                    <YAxis tick={{ fontSize: 10, fill: "#888" }} />
                    <Tooltip
                      contentStyle={{ background: "#1a1a2e", border: "1px solid #333", borderRadius: 8 }}
                      labelStyle={{ color: "#fff" }}
                    />
                    <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="url(#threatGrad)" strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>

            {/* Threat Distribution Pie */}
            <div className="chart-card">
              <h3 className="chart-title">🎯 Threat Distribution</h3>
              {pieData.length === 0 ? (
                <div className="chart-empty">No data yet...</div>
              ) : (
                <>
                  <ResponsiveContainer width="100%" height={180}>
                    <PieChart>
                      <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value">
                        {pieData.map((entry, i) => (
                          <Cell key={i} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ background: "#1a1a2e", border: "1px solid #333", borderRadius: 8 }}
                        labelStyle={{ color: "#fff" }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="pie-legend">
                    {pieData.map((d, i) => (
                      <div key={i} className="legend-item">
                        <span className="legend-dot" style={{ background: d.color }}></span>
                        <span className="legend-label">{d.name}</span>
                        <span className="legend-count">{d.value}</span>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>

          {/* Recent Alerts Preview */}
          <div className="recent-card">
            <h3 className="chart-title">⚡ Recent Threats</h3>
            <div className="alert-list">
              {alerts.slice(0, 8).map((alert, i) => (
                <AlertRow key={i} alert={alert} />
              ))}
              {alerts.length === 0 && <div className="chart-empty">No alerts yet — capture is running...</div>}
            </div>
          </div>

        </div>
      )}

      {/* ── ALERTS TAB ── */}
      {activeTab === "alerts" && (
        <div className="alerts-page">

          {/* Filter Bar */}
          <div className="filter-bar">
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "DDoS", "Port Scan", "Brute Force", "ML Anomaly"].map(f => (
              <button
                key={f}
                className={`filter-btn ${filter === f ? "active" : ""}`}
                onClick={() => setFilter(f)}
              >
                {f}
              </button>
            ))}
          </div>

          <div className="alert-count">{filteredAlerts.length} alerts</div>

          <div className="alert-list-full">
            {filteredAlerts.map((alert, i) => (
              <AlertRow key={i} alert={alert} detailed />
            ))}
            {filteredAlerts.length === 0 && (
              <div className="chart-empty">No alerts matching filter</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function AlertRow({ alert, detailed }) {
  const color = SEVERITY_COLORS[alert.severity] || "#888";
  return (
    <div className="alert-row" style={{ borderLeft: `3px solid ${color}` }}>
      <div className="alert-row-left">
        <span className="alert-type">{alert.threat_type}</span>
        <span className="alert-severity" style={{ color }}>{alert.severity}</span>
      </div>
      <div className="alert-row-mid">
        <span className="alert-ip">📍 {alert.src_ip || "Unknown"}</span>
        {detailed && <span className="alert-desc">{alert.description}</span>}
      </div>
      <div className="alert-row-right">
        <span className="alert-proto">{alert.protocol}</span>
        <span className="alert-time">
          {alert.created_at ? new Date(alert.created_at).toLocaleTimeString() : ""}
        </span>
      </div>
    </div>
  );
}
