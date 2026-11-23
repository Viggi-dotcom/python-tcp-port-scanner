"use client";

import React, { useState, useEffect, useMemo, useCallback } from "react";
import {
  Terminal,
  Shield,
  Play,
  Download,
  FileText,
  FileSpreadsheet,
  Server,
  Clock,
  Activity,
  Search,
  ChevronDown,
  ChevronRight,
  Copy,
  Check,
  Trash2,
  Plus,
  Cpu,
  Network,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Code2,
  RefreshCw,
  Layers,
  Radio,
} from "lucide-react";

interface LabTarget {
  id: number;
  name: string;
  host: string;
  environment: string;
  osProfile: string;
  defaultPorts: string;
  description: string;
  authorized: boolean;
}

interface ScanRecord {
  id: number;
  targetHost: string;
  targetLabel: string;
  portRange: string;
  timeoutMs: number;
  threads: number;
  grabBanner: boolean;
  status: string;
  openCount: number;
  closedCount: number;
  filteredCount: number;
  totalPortsScanned: number;
  durationMs: number;
  cliCommand: string;
  createdAt: string;
}

interface PortResult {
  id: number;
  scanId: number;
  port: number;
  protocol: string;
  state: "open" | "closed" | "filtered";
  service: string;
  banner: string | null;
  rawHex: string | null;
  latencyMs: number | null;
  securityNotes: string | null;
  riskLevel: "info" | "low" | "medium" | "high";
}

const PORT_PRESETS = [
  {
    label: "Lab Signature",
    ports: "21,22,80,443,3000,5432,6379,8080",
    desc: "Core local & container services",
  },
  {
    label: "VBox Vuln Audit",
    ports: "21,22,23,25,80,111,139,445,512,1524,2121,3306,5432,5900,6667,8180",
    desc: "Metasploitable2 & DVWA vector ports",
  },
  {
    label: "Web & App Stack",
    ports: "80,443,3000,8000,8080,8180,8443,9000",
    desc: "HTTP/HTTPS & proxy listeners",
  },
  {
    label: "DB & Cache",
    ports: "1433,3306,5432,6379,27017",
    desc: "PostgreSQL, MySQL, Redis, MSSQL, Mongo",
  },
  {
    label: "System 1-100",
    ports: "1-100",
    desc: "Sequential range 1 through 100",
  },
];

export default function PortScannerWorkbench() {
  const [activeTab, setActiveTab] = useState<
    "workbench" | "history" | "lab-cli"
  >("workbench");

  // Lab targets & scan history state
  const [targets, setTargets] = useState<LabTarget[]>([]);
  const [scansHistory, setScansHistory] = useState<ScanRecord[]>([]);
  const [currentScan, setCurrentScan] = useState<ScanRecord | null>(null);
  const [currentResults, setCurrentResults] = useState<PortResult[]>([]);
  const [isLoadingInitial, setIsLoadingInitial] = useState(true);

  // Scanner configuration form state
  const [targetHost, setTargetHost] = useState("127.0.0.1");
  const [targetLabel, setTargetLabel] = useState(
    "Localhost Loopback Node (lo0)"
  );
  const [portRange, setPortRange] = useState(
    "21,22,80,443,3000,5432,6379,8080"
  );
  const [timeoutMs, setTimeoutMs] = useState(400);
  const [threads, setThreads] = useState(20);
  const [grabBanner, setGrabBanner] = useState(true);

  // Execution & UI state
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const [showTerminal, setShowTerminal] = useState(true);

  // Table filtering & expansion state
  const [stateFilter, setStateFilter] = useState<
    "all" | "open" | "filtered" | "closed"
  >("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedPorts, setExpandedPorts] = useState<Record<number, boolean>>({
    21: true,
    22: true,
    80: true,
  });
  const [copiedCmd, setCopiedCmd] = useState(false);

  // Report preview state in History tab
  const [reportPreviewFormat, setReportPreviewFormat] = useState<"txt" | "csv">(
    "txt"
  );
  const [reportPreviewText, setReportPreviewText] = useState<string>("");
  const [loadingReport, setLoadingReport] = useState(false);
  const [copiedReport, setCopiedReport] = useState(false);

  // Python source code viewer state
  const [pythonSource, setPythonSource] = useState<string>("");
  const [copiedSource, setCopiedSource] = useState(false);

  // New Lab Target form state
  const [newTargetName, setNewTargetName] = useState("");
  const [newTargetHost, setNewTargetHost] = useState("192.168.56.110");
  const [newTargetEnv, setNewTargetEnv] = useState(
    "VirtualBox Host-Only (vboxnet0)"
  );
  const [newTargetOs, setNewTargetOs] = useState("Ubuntu 24.04 LTS Server");
  const [newTargetPorts, setNewTargetPorts] = useState(
    "22,80,443,3000,5432,8080"
  );
  const [newTargetDesc, setNewTargetDesc] = useState(
    "Custom VirtualBox security testing appliance in isolated host-only subnet."
  );
  const [targetFormError, setTargetFormError] = useState<string | null>(null);
  const [isCreatingTarget, setIsCreatingTarget] = useState(false);

  const buildTerminalStreamFromScan = useCallback(
    (scan: ScanRecord, results: PortResult[]) => {
      const lines: string[] = [
        `[PYPORTSCAN-LAB v2.4] Initializing Python 3.11 socket engine (AF_INET, SOCK_STREAM)...`,
        `$ ${scan.cliCommand}`,
        `[TARGET] Host: ${scan.targetHost} (${scan.targetLabel}) | RFC1918/Loopback Authorized`,
        `[CONFIG] Timeout: ${scan.timeoutMs}ms (sock.settimeout(${(
          scan.timeoutMs / 1000
        ).toFixed(2)}s)) | Pool: ThreadPoolExecutor(max_workers=${
          scan.threads
        }) | BannerGrab: ${scan.grabBanner ? "ENABLED" : "DISABLED"}`,
      ];

      const openRows = results.filter((r) => r.state === "open");
      const filteredRows = results.filter((r) => r.state === "filtered");

      for (const r of openRows) {
        lines.push(
          `[+] TCP ${scan.targetHost}:${r.port} -> STATE=OPEN (connect_ex errno=0, RTT=${
            r.latencyMs ?? 1
          }ms) | SERVICE=${r.service}`
        );
        if (r.banner) {
          lines.push(`    └─ BANNER: "${r.banner}"`);
        }
      }

      for (const r of filteredRows.slice(0, 6)) {
        lines.push(
          `[!] TCP ${scan.targetHost}:${r.port} -> STATE=FILTERED (socket.timeout > ${scan.timeoutMs}ms) | SERVICE=${r.service}`
        );
      }

      lines.push(
        `[COMPLETE] Probed ${scan.totalPortsScanned} TCP ports in ${scan.durationMs}ms => ${scan.openCount} OPEN, ${scan.closedCount} CLOSED, ${scan.filteredCount} FILTERED.`
      );
      return lines;
    },
    []
  );

  // Load initial data on mount
  const fetchInitialData = useCallback(async () => {
    setIsLoadingInitial(true);
    try {
      const [targetsRes, scansRes] = await Promise.all([
        fetch("/api/targets"),
        fetch("/api/scans"),
      ]);
      const targetsData = await targetsRes.json();
      const scansData = await scansRes.json();

      if (targetsData.targets) {
        setTargets(targetsData.targets);
      }
      if (scansData.scans) {
        setScansHistory(scansData.scans);
      }
      if (scansData.latestScan) {
        setCurrentScan(scansData.latestScan);
        setCurrentResults(scansData.latestResults || []);
        setTerminalLogs(
          buildTerminalStreamFromScan(
            scansData.latestScan,
            scansData.latestResults || []
          )
        );
      }
    } catch (err) {
      console.error("Failed to load initial workbench data:", err);
    } finally {
      setIsLoadingInitial(false);
    }
  }, [buildTerminalStreamFromScan]);

  useEffect(() => {
    fetchInitialData();
  }, [fetchInitialData]);

  // Fetch report preview when viewing History & Reports tab
  useEffect(() => {
    if (!currentScan) return;
    let cancelled = false;
    async function loadReport() {
      setLoadingReport(true);
      try {
        const res = await fetch(
          `/api/scans/${currentScan?.id}/export?format=${reportPreviewFormat}`
        );
        const text = await res.text();
        if (!cancelled) {
          setReportPreviewText(text);
        }
      } catch {
        if (!cancelled) {
          setReportPreviewText("Unable to load report preview.");
        }
      } finally {
        if (!cancelled) {
          setLoadingReport(false);
        }
      }
    }
    loadReport();
    return () => {
      cancelled = true;
    };
  }, [currentScan, reportPreviewFormat]);

  // Fetch Python source code when viewing Lab & CLI tab
  useEffect(() => {
    if (activeTab === "lab-cli" && !pythonSource) {
      fetch("/api/source")
        .then((r) => r.json())
        .then((d) => {
          if (d.content) setPythonSource(d.content);
        })
        .catch(() => {});
    }
  }, [activeTab, pythonSource]);

  const liveCliCommand = useMemo(() => {
    const bannerFlag = grabBanner ? " --banner" : " --no-banner";
    return `python3 scripts/scanner.py --host ${
      targetHost || "127.0.0.1"
    } --ports "${
      portRange || "1-1024"
    }" --timeout ${timeoutMs} --threads ${threads}${bannerFlag}`;
  }, [targetHost, portRange, timeoutMs, threads, grabBanner]);

  const handleSelectTargetPreset = (t: LabTarget) => {
    setTargetHost(t.host);
    setTargetLabel(t.name);
    setPortRange(t.defaultPorts);
    setScanError(null);
  };

  const handleExecuteScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setIsScanning(true);
    setScanError(null);
    setShowTerminal(true);

    setTerminalLogs([
      `[PYPORTSCAN-LAB] Spawning Python 3.11 subprocess...`,
      `$ ${liveCliCommand}`,
      `[SOCKET] Creating socket.socket(socket.AF_INET, socket.SOCK_STREAM) worker pool (${threads} threads)...`,
      `[PROBE] Dispatching TCP SYN probes to ${targetHost} across port spec "${portRange}"...`,
    ]);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          targetHost,
          targetLabel,
          portRange,
          timeoutMs,
          threads,
          grabBanner,
        }),
      });

      const data = await response.json();
      if (!response.ok || data.error) {
        setScanError(data.error || "Scan execution failed.");
        setTerminalLogs((prev) => [
          ...prev,
          `[ERROR] ${data.error || "Subprocess returned non-zero status."}`,
        ]);
        return;
      }

      const newScan: ScanRecord = data.scan;
      const newResults: PortResult[] = data.results || [];

      setCurrentScan(newScan);
      setCurrentResults(newResults);
      setScansHistory((prev) => [
        newScan,
        ...prev.filter((s) => s.id !== newScan.id),
      ]);
      setTerminalLogs(buildTerminalStreamFromScan(newScan, newResults));

      // Automatically expand the first 2 open ports for immediate banner/hex visibility
      const firstOpen = newResults
        .filter((r) => r.state === "open")
        .slice(0, 2);
      const nextExpanded: Record<number, boolean> = {};
      firstOpen.forEach((r) => {
        nextExpanded[r.port] = true;
      });
      setExpandedPorts(nextExpanded);
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : "Network error during scan.";
      setScanError(msg);
      setTerminalLogs((prev) => [...prev, `[FATAL] ${msg}`]);
    } finally {
      setIsScanning(false);
    }
  };

  const handleLoadHistoricalScan = async (scanId: number) => {
    try {
      const res = await fetch(`/api/scans/${scanId}`);
      const data = await res.json();
      if (data.scan) {
        setCurrentScan(data.scan);
        setCurrentResults(data.results || []);
        setTerminalLogs(
          buildTerminalStreamFromScan(data.scan, data.results || [])
        );
      }
    } catch (err) {
      console.error("Failed to load scan:", err);
    }
  };

  const handleDeleteScan = async (scanId: number, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      const res = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
      if (res.ok) {
        const remaining = scansHistory.filter((s) => s.id !== scanId);
        setScansHistory(remaining);
        if (currentScan?.id === scanId) {
          if (remaining.length > 0) {
            handleLoadHistoricalScan(remaining[0].id);
          } else {
            setCurrentScan(null);
            setCurrentResults([]);
          }
        }
      }
    } catch (err) {
      console.error("Failed to delete scan:", err);
    }
  };

  const handleCreateLabTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    setTargetFormError(null);
    setIsCreatingTarget(true);
    try {
      const res = await fetch("/api/targets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: newTargetName,
          host: newTargetHost,
          environment: newTargetEnv,
          osProfile: newTargetOs,
          defaultPorts: newTargetPorts,
          description: newTargetDesc,
        }),
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        setTargetFormError(data.error || "Failed to register lab target.");
        return;
      }
      setTargets((prev) => [...prev, data.target]);
      setNewTargetName("");
    } catch {
      setTargetFormError("Network error while saving target.");
    } finally {
      setIsCreatingTarget(false);
    }
  };

  const togglePortExpand = (port: number) => {
    setExpandedPorts((prev) => ({
      ...prev,
      [port]: !prev[port],
    }));
  };

  const filteredResults = useMemo(() => {
    return currentResults.filter((r) => {
      if (stateFilter !== "all" && r.state !== stateFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchPort = String(r.port).includes(q);
        const matchService = r.service.toLowerCase().includes(q);
        const matchBanner = (r.banner || "").toLowerCase().includes(q);
        const matchNotes = (r.securityNotes || "").toLowerCase().includes(q);
        return matchPort || matchService || matchBanner || matchNotes;
      }
      return true;
    });
  }, [currentResults, stateFilter, searchQuery]);

  const highRiskCount = useMemo(
    () =>
      currentResults.filter(
        (r) =>
          r.state === "open" &&
          (r.riskLevel === "high" || r.riskLevel === "medium")
      ).length,
    [currentResults]
  );

  const avgLatencyMs = useMemo(() => {
    const openPorts = currentResults.filter((r) => r.state === "open");
    if (openPorts.length === 0) return 1;
    const sum = openPorts.reduce((acc, r) => acc + (r.latencyMs ?? 1), 0);
    return Math.max(1, Math.round(sum / openPorts.length));
  }, [currentResults]);

  const copyToClipboard = (text: string, type: "cmd" | "report" | "source") => {
    navigator.clipboard.writeText(text);
    if (type === "cmd") {
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 2000);
    } else if (type === "report") {
      setCopiedReport(true);
      setTimeout(() => setCopiedReport(false), 2000);
    } else {
      setCopiedSource(true);
      setTimeout(() => setCopiedSource(false), 2000);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#090D16] text-[#F8FAFC]">
      {/* Top Status & Navigation Header */}
      <header className="sticky top-0 z-30 h-14 border-b border-slate-800/80 bg-[#090D16]/90 backdrop-blur-md px-4 lg:px-6 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-[#10B981]/15 border border-[#10B981]/40 flex items-center justify-center text-[#10B981]">
            <Terminal className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold tracking-tight text-sm md:text-base text-white">
                PYPORTSCAN<span className="text-[#10B981]">-LAB</span>
              </span>
              <span className="hidden sm:inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                Python 3.11 • socket / TCP-IP
              </span>
            </div>
          </div>
        </div>

        {/* Center Navigation Tabs */}
        <nav className="flex items-center gap-1 bg-[#111827] p-1 rounded-md border border-slate-800">
          <button
            type="button"
            onClick={() => setActiveTab("workbench")}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-all flex items-center gap-1.5 ${
              activeTab === "workbench"
                ? "bg-[#182232] text-[#10B981] border-b-2 border-[#10B981] shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Scanner Workbench</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("history")}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-all flex items-center gap-1.5 ${
              activeTab === "history"
                ? "bg-[#182232] text-[#10B981] border-b-2 border-[#10B981] shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Scan History & Reports</span>
            <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-slate-800 text-slate-300">
              {scansHistory.length}
            </span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("lab-cli")}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-all flex items-center gap-1.5 ${
              activeTab === "lab-cli"
                ? "bg-[#182232] text-[#10B981] border-b-2 border-[#10B981] shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Lab Nodes & Python CLI</span>
            <span className="sm:hidden">CLI</span>
          </button>
        </nav>

        {/* Right Telemetry Status Badges */}
        <div className="hidden xl:flex items-center gap-3 text-xs font-mono">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#111827] border border-slate-800 text-slate-300">
            <span className="w-2 h-2 rounded-full bg-[#10B981] animate-pulse" />
            <span>SOCKET ENGINE: READY</span>
          </div>
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#111827] border border-slate-800 text-[#06B6D4]">
            <Shield className="w-3.5 h-3.5" />
            <span>AUTHORIZED LAB MODE</span>
          </div>
        </div>
      </header>

      {/* Main Content Container */}
      <main className="flex-1 max-w-[1600px] w-full mx-auto p-4 lg:p-6">
        {activeTab === "workbench" && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            {/* LEFT COMMAND RAIL (4 Columns) */}
            <aside className="lg:col-span-4 flex flex-col gap-5">
              {/* Target & Socket Configuration Panel */}
              <div className="bg-[#111827] border border-slate-800 rounded-md p-5 shadow-lg">
                <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
                  <div className="flex items-center gap-2">
                    <Network className="w-4 h-4 text-[#10B981]" />
                    <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
                      TCP Probe Configuration
                    </h2>
                  </div>
                  <span className="text-[11px] font-mono text-[#06B6D4] bg-[#06B6D4]/10 px-2 py-0.5 rounded border border-[#06B6D4]/30">
                    AF_INET / SOCK_STREAM
                  </span>
                </div>

                {/* Authorized Lab Environment Preset Selector */}
                <div className="mb-4">
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                    Authorized Test System / VirtualBox Preset
                  </label>
                  <div className="grid grid-cols-1 gap-1.5 max-h-48 overflow-y-auto pr-1">
                    {targets.map((t) => {
                      const isSelected = targetHost === t.host;
                      return (
                        <button
                          key={t.id}
                          type="button"
                          onClick={() => handleSelectTargetPreset(t)}
                          className={`text-left px-3 py-2 rounded border transition-all flex items-center justify-between gap-2 ${
                            isSelected
                              ? "bg-[#182232] border-[#10B981]/60 text-white"
                              : "bg-[#090D16]/60 border-slate-800/90 text-slate-300 hover:border-slate-700"
                          }`}
                        >
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs font-semibold text-[#10B981]">
                                {t.host}
                              </span>
                              <span className="text-xs font-medium truncate">
                                {t.name}
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 truncate mt-0.5">
                              {t.environment} • {t.osProfile}
                            </p>
                          </div>
                          {isSelected && (
                            <span className="shrink-0 w-2 h-2 rounded-full bg-[#10B981]" />
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>

                <form onSubmit={handleExecuteScan} className="space-y-4">
                  {/* Target IP / Host Input */}
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <label
                        htmlFor="target-host-input"
                        className="text-xs font-semibold uppercase tracking-wider text-slate-400"
                      >
                        Target IP / Hostname
                      </label>
                      <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                        <Lock className="w-3 h-3" /> RFC1918 / Loopback
                      </span>
                    </div>
                    <input
                      id="target-host-input"
                      type="text"
                      value={targetHost}
                      onChange={(e) => setTargetHost(e.target.value)}
                      placeholder="127.0.0.1 or 192.168.56.101"
                      className="w-full h-10 px-3 py-2 rounded bg-[#090D16] border border-slate-700 font-mono text-sm text-white focus:outline-none focus:border-[#10B981] focus:ring-1 focus:ring-[#10B981]"
                    />
                  </div>

                  {/* Port Range Spec Input & Quick Chips */}
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <label
                        htmlFor="port-range-input"
                        className="text-xs font-semibold uppercase tracking-wider text-slate-400"
                      >
                        Port Range Specification
                      </label>
                      <span className="text-[10px] font-mono text-slate-400">
                        e.g. 1-1024 or 22,80,443
                      </span>
                    </div>
                    <input
                      id="port-range-input"
                      type="text"
                      value={portRange}
                      onChange={(e) => setPortRange(e.target.value)}
                      placeholder="21,22,80,443,3000,5432,8080"
                      className="w-full h-10 px-3 py-2 rounded bg-[#090D16] border border-slate-700 font-mono text-xs text-white focus:outline-none focus:border-[#10B981] focus:ring-1 focus:ring-[#10B981]"
                    />
                    {/* Quick Port Chips */}
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {PORT_PRESETS.map((preset) => (
                        <button
                          key={preset.label}
                          type="button"
                          onClick={() => setPortRange(preset.ports)}
                          title={preset.desc}
                          className={`px-2 py-1 rounded text-[11px] font-mono border transition-colors ${
                            portRange === preset.ports
                              ? "bg-[#10B981]/15 border-[#10B981] text-[#10B981]"
                              : "bg-[#090D16] border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700"
                          }`}
                        >
                          {preset.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Socket Timeout & Concurrent Threads */}
                  <div className="grid grid-cols-2 gap-3 pt-1">
                    <div className="bg-[#090D16]/90 p-3 rounded border border-slate-800">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[11px] font-semibold uppercase text-slate-400">
                          Timeout
                        </span>
                        <span className="text-xs font-mono font-bold text-[#06B6D4]">
                          {timeoutMs} ms
                        </span>
                      </div>
                      <input
                        type="range"
                        min={100}
                        max={2000}
                        step={50}
                        value={timeoutMs}
                        onChange={(e) => setTimeoutMs(Number(e.target.value))}
                        className="w-full accent-[#06B6D4] cursor-pointer"
                      />
                      <div className="flex justify-between text-[10px] font-mono text-slate-500 mt-0.5">
                        <span>100ms</span>
                        <span>2000ms</span>
                      </div>
                    </div>

                    <div className="bg-[#090D16]/90 p-3 rounded border border-slate-800">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[11px] font-semibold uppercase text-slate-400">
                          Threads
                        </span>
                        <span className="text-xs font-mono font-bold text-[#10B981]">
                          {threads} workers
                        </span>
                      </div>
                      <input
                        type="range"
                        min={1}
                        max={64}
                        step={1}
                        value={threads}
                        onChange={(e) => setThreads(Number(e.target.value))}
                        className="w-full accent-[#10B981] cursor-pointer"
                      />
                      <div className="flex justify-between text-[10px] font-mono text-slate-500 mt-0.5">
                        <span>1</span>
                        <span>64</span>
                      </div>
                    </div>
                  </div>

                  {/* Banner Grabbing Toggle */}
                  <div className="flex items-center justify-between p-3 rounded bg-[#090D16]/90 border border-slate-800">
                    <div>
                      <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                        <Radio className="w-3.5 h-3.5 text-[#10B981]" />
                        <span>Active TCP Banner Grabbing</span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5">
                        Send protocol probes & capture raw hex/ASCII headers
                      </p>
                    </div>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={grabBanner}
                      onClick={() => setGrabBanner(!grabBanner)}
                      className={`w-11 h-6 flex items-center rounded-full p-0.5 transition-colors ${
                        grabBanner ? "bg-[#10B981]" : "bg-slate-700"
                      }`}
                    >
                      <span
                        className={`bg-[#090D16] w-5 h-5 rounded-full shadow-md transform transition-transform ${
                          grabBanner ? "translate-x-5" : "translate-x-0"
                        }`}
                      />
                    </button>
                  </div>

                  {/* Live Python CLI Invocation Preview */}
                  <div className="bg-[#090D16] border border-slate-800 rounded p-3">
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                        Equivalent CLI Execution
                      </span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(liveCliCommand, "cmd")}
                        className="text-[11px] font-mono text-[#06B6D4] hover:underline flex items-center gap-1"
                      >
                        {copiedCmd ? (
                          <>
                            <Check className="w-3 h-3 text-[#10B981]" />
                            <span className="text-[#10B981]">Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Copy CLI</span>
                          </>
                        )}
                      </button>
                    </div>
                    <code className="block text-[11px] font-mono text-emerald-300/90 break-all leading-relaxed">
                      $ {liveCliCommand}
                    </code>
                  </div>

                  {scanError && (
                    <div className="p-3 rounded bg-red-950/50 border border-red-500/40 text-xs text-red-200 flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                      <span>{scanError}</span>
                    </div>
                  )}

                  {/* Execute Scan CTA */}
                  <button
                    type="submit"
                    disabled={isScanning}
                    className="w-full py-2.5 px-4 rounded bg-[#10B981] hover:bg-[#059669] disabled:opacity-60 text-[#052E16] font-bold text-sm tracking-wide transition-all flex items-center justify-center gap-2 shadow-lg shadow-[#10B981]/10 cursor-pointer"
                  >
                    {isScanning ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>PROBING TCP SOCKETS...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 fill-current" />
                        <span>EXECUTE PYTHON TCP SCAN</span>
                      </>
                    )}
                  </button>
                </form>
              </div>

              {/* Recent Scans Quick Switcher Card */}
              <div className="bg-[#111827] border border-slate-800 rounded-md p-4">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-[#06B6D4]" />
                    <span>Recent Telemetry Sessions</span>
                  </span>
                  <button
                    type="button"
                    onClick={() => setActiveTab("history")}
                    className="text-xs font-mono text-[#06B6D4] hover:underline"
                  >
                    View All ({scansHistory.length})
                  </button>
                </div>
                <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                  {scansHistory.slice(0, 5).map((s) => {
                    const active = currentScan?.id === s.id;
                    return (
                      <div
                        key={s.id}
                        onClick={() => handleLoadHistoricalScan(s.id)}
                        className={`p-2.5 rounded border text-xs cursor-pointer transition-all flex items-center justify-between gap-2 ${
                          active
                            ? "bg-[#182232] border-[#10B981]/50"
                            : "bg-[#090D16]/60 border-slate-800 hover:border-slate-700"
                        }`}
                      >
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-semibold text-white">
                              #{s.id} • {s.targetHost}
                            </span>
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-[#10B981]/15 text-[#10B981] border border-[#10B981]/30">
                              {s.openCount} OPEN
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-400 truncate mt-0.5">
                            {s.targetLabel} • {s.durationMs}ms
                          </div>
                        </div>
                        <ChevronRight className="w-4 h-4 text-slate-500 shrink-0" />
                      </div>
                    );
                  })}
                </div>
              </div>
            </aside>

            {/* RIGHT TELEMETRY CANVAS (8 Columns) */}
            <section className="lg:col-span-8 flex flex-col gap-5">
              {/* 4-Card KPI Telemetry Summary Strip */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                <div className="bg-[#111827] border border-slate-800 rounded-md p-4">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span className="uppercase font-semibold tracking-wider">
                      Target Host
                    </span>
                    <Server className="w-4 h-4 text-[#06B6D4]" />
                  </div>
                  <div className="font-mono text-lg sm:text-xl font-bold text-white truncate tabular-nums">
                    {currentScan?.targetHost || targetHost}
                  </div>
                  <div className="text-[11px] text-slate-400 truncate mt-1">
                    {currentScan?.targetLabel || targetLabel}
                  </div>
                </div>

                <div className="bg-[#111827] border border-slate-800 rounded-md p-4">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span className="uppercase font-semibold tracking-wider">
                      Open Ports
                    </span>
                    <CheckCircle2 className="w-4 h-4 text-[#10B981]" />
                  </div>
                  <div className="flex items-baseline gap-2">
                    <span className="font-mono text-2xl font-bold text-[#10B981] tabular-nums">
                      {currentScan?.openCount ?? 0}
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      / {currentScan?.totalPortsScanned ?? 0} probed
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    {highRiskCount > 0 ? (
                      <span className="text-amber-400 font-medium">
                        {highRiskCount} services require review
                      </span>
                    ) : (
                      <span>Active TCP listeners verified</span>
                    )}
                  </div>
                </div>

                <div className="bg-[#111827] border border-slate-800 rounded-md p-4">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span className="uppercase font-semibold tracking-wider">
                      Filtered / Closed
                    </span>
                    <Shield className="w-4 h-4 text-amber-400" />
                  </div>
                  <div className="flex items-baseline gap-2 font-mono tabular-nums">
                    <span className="text-xl font-bold text-amber-400">
                      {currentScan?.filteredCount ?? 0}
                    </span>
                    <span className="text-slate-500">/</span>
                    <span className="text-xl font-bold text-slate-400">
                      {currentScan?.closedCount ?? 0}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    Timeout drop vs TCP RST
                  </div>
                </div>

                <div className="bg-[#111827] border border-slate-800 rounded-md p-4">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span className="uppercase font-semibold tracking-wider">
                      Scan Telemetry
                    </span>
                    <Cpu className="w-4 h-4 text-[#06B6D4]" />
                  </div>
                  <div className="font-mono text-2xl font-bold text-white tabular-nums">
                    {currentScan?.durationMs ?? 0}
                    <span className="text-sm font-normal text-slate-400 ml-1">
                      ms
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 mt-1">
                    Avg RTT: ~{avgLatencyMs}ms • {currentScan?.threads ?? 20}{" "}
                    threads
                  </div>
                </div>
              </div>

              {/* Port Range Visual Spectrum Bar */}
              {currentResults.length > 0 && (
                <div className="bg-[#111827] border border-slate-800 rounded-md p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-2.5">
                    <div className="flex items-center gap-2">
                      <Layers className="w-4 h-4 text-[#06B6D4]" />
                      <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                        TCP Port State Spectrum ({currentResults.length} Ports)
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-[11px] font-mono">
                      <span className="flex items-center gap-1.5 text-[#10B981]">
                        <span className="w-2.5 h-2.5 rounded-xs bg-[#10B981]" />
                        OPEN ({currentScan?.openCount ?? 0})
                      </span>
                      <span className="flex items-center gap-1.5 text-amber-400">
                        <span className="w-2.5 h-2.5 rounded-xs bg-amber-400" />
                        FILTERED ({currentScan?.filteredCount ?? 0})
                      </span>
                      <span className="flex items-center gap-1.5 text-slate-400">
                        <span className="w-2.5 h-2.5 rounded-xs bg-slate-700" />
                        CLOSED ({currentScan?.closedCount ?? 0})
                      </span>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1 pt-1">
                    {currentResults.slice(0, 120).map((r) => {
                      const bgClass =
                        r.state === "open"
                          ? "bg-[#10B981] hover:bg-emerald-300 text-[#052E16]"
                          : r.state === "filtered"
                          ? "bg-amber-500/80 hover:bg-amber-400 text-slate-950"
                          : "bg-slate-800 hover:bg-slate-700 text-slate-400";
                      return (
                        <button
                          key={r.port}
                          type="button"
                          onClick={() => {
                            setStateFilter("all");
                            setExpandedPorts((prev) => ({
                              ...prev,
                              [r.port]: true,
                            }));
                            const el = document.getElementById(
                              `port-row-${r.port}`
                            );
                            if (el)
                              el.scrollIntoView({
                                behavior: "smooth",
                                block: "center",
                              });
                          }}
                          title={`Port ${r.port}/TCP (${r.service}) - ${r.state.toUpperCase()}`}
                          className={`px-1.5 py-0.5 rounded-xs font-mono text-[10px] font-semibold transition-all cursor-pointer ${bgClass}`}
                        >
                          {r.port}
                        </button>
                      );
                    })}
                    {currentResults.length > 120 && (
                      <span className="text-[11px] font-mono text-slate-400 px-2 py-0.5">
                        +{currentResults.length - 120} more ports
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Live Python Socket Terminal Stream */}
              <div className="bg-[#090D16] border border-slate-800 rounded-md overflow-hidden shadow-inner">
                <div className="bg-[#111827] px-4 py-2.5 border-b border-slate-800 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
                      <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                      <span className="w-2.5 h-2.5 rounded-full bg-cyan-500/80" />
                    </div>
                    <span className="text-xs font-mono font-semibold text-slate-300 ml-2">
                      python3 scripts/scanner.py // Live Socket Telemetry Stream
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    {currentScan && (
                      <>
                        <a
                          href={`/api/scans/${currentScan.id}/export?format=txt`}
                          download
                          className="px-2 py-1 rounded bg-[#182232] hover:bg-slate-700 text-slate-200 text-[11px] font-mono flex items-center gap-1 border border-slate-700"
                        >
                          <FileText className="w-3 h-3 text-[#06B6D4]" />
                          <span>.TXT Report</span>
                        </a>
                        <a
                          href={`/api/scans/${currentScan.id}/export?format=csv`}
                          download
                          className="px-2 py-1 rounded bg-[#182232] hover:bg-slate-700 text-slate-200 text-[11px] font-mono flex items-center gap-1 border border-slate-700"
                        >
                          <FileSpreadsheet className="w-3 h-3 text-[#10B981]" />
                          <span>.CSV Export</span>
                        </a>
                      </>
                    )}
                    <button
                      type="button"
                      onClick={() => setShowTerminal(!showTerminal)}
                      className="text-xs font-mono text-slate-400 hover:text-white px-1.5"
                    >
                      {showTerminal ? "Hide" : "Expand"}
                    </button>
                  </div>
                </div>
                {showTerminal && (
                  <div className="p-4 max-h-52 overflow-y-auto font-mono text-xs space-y-1.5 leading-relaxed">
                    {terminalLogs.map((line, idx) => {
                      const isOpenLine = line.includes("STATE=OPEN");
                      const isBannerLine = line.includes("BANNER:");
                      const isFilteredLine = line.includes("STATE=FILTERED");
                      const isCmdLine = line.startsWith("$");
                      const isErrLine =
                        line.includes("[ERROR]") || line.includes("[FATAL]");
                      return (
                        <div
                          key={idx}
                          className={
                            isErrLine
                              ? "text-red-400 font-semibold"
                              : isOpenLine
                              ? "text-[#10B981]"
                              : isBannerLine
                              ? "text-[#06B6D4] pl-2"
                              : isFilteredLine
                              ? "text-amber-400"
                              : isCmdLine
                              ? "text-white font-semibold"
                              : "text-slate-400"
                          }
                        >
                          {line}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Discovered Port & Service Banner Matrix Table */}
              <div className="bg-[#111827] border border-slate-800 rounded-md overflow-hidden">
                {/* Matrix Toolbar */}
                <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-1.5">
                    {(
                      [
                        {
                          id: "all",
                          label: `All (${currentResults.length})`,
                        },
                        {
                          id: "open",
                          label: `Open (${currentScan?.openCount ?? 0})`,
                        },
                        {
                          id: "filtered",
                          label: `Filtered (${
                            currentScan?.filteredCount ?? 0
                          })`,
                        },
                        {
                          id: "closed",
                          label: `Closed (${currentScan?.closedCount ?? 0})`,
                        },
                      ] as const
                    ).map((tab) => (
                      <button
                        key={tab.id}
                        type="button"
                        onClick={() => setStateFilter(tab.id)}
                        className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                          stateFilter === tab.id
                            ? "bg-[#10B981]/20 text-[#10B981] border border-[#10B981]/50 font-semibold"
                            : "bg-[#090D16] text-slate-400 border border-slate-800 hover:text-slate-200"
                        }`}
                      >
                        {tab.label}
                      </button>
                    ))}
                  </div>

                  <div className="flex items-center gap-2 flex-1 sm:flex-initial justify-end">
                    <div className="relative w-full sm:w-64">
                      <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                      <input
                        type="text"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="Filter port, service, banner..."
                        className="w-full h-8 pl-8 pr-3 rounded bg-[#090D16] border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-[#10B981]"
                      />
                    </div>
                  </div>
                </div>

                {/* Table Header & Rows */}
                {isLoadingInitial ? (
                  <div className="p-12 text-center font-mono text-sm text-slate-400">
                    Loading TCP port telemetry matrix...
                  </div>
                ) : filteredResults.length === 0 ? (
                  <div className="p-12 text-center">
                    <p className="font-mono text-sm text-slate-400">
                      No port records match the current filter criteria.
                    </p>
                    {stateFilter !== "all" && (
                      <button
                        type="button"
                        onClick={() => setStateFilter("all")}
                        className="mt-3 px-3 py-1.5 rounded bg-slate-800 text-xs font-mono text-[#10B981] hover:bg-slate-700"
                      >
                        Show All Scanned Ports
                      </button>
                    )}
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="border-b border-slate-800 bg-[#090D16]/60 text-[11px] font-mono uppercase text-slate-400">
                          <th className="py-2.5 px-4 w-28">Port / Proto</th>
                          <th className="py-2.5 px-3 w-28">State</th>
                          <th className="py-2.5 px-3 w-44">Service & Risk</th>
                          <th className="py-2.5 px-3 w-24">Latency</th>
                          <th className="py-2.5 px-4">
                            Captured Banner / Socket Response
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/70 text-xs font-mono">
                        {filteredResults.map((row) => {
                          const isExpanded = !!expandedPorts[row.port];
                          const stateBadge =
                            row.state === "open"
                              ? "bg-[#10B981]/15 text-[#10B981] border-[#10B981]/40"
                              : row.state === "filtered"
                              ? "bg-amber-500/15 text-amber-400 border-amber-500/40"
                              : "bg-slate-800/80 text-slate-400 border-slate-700";

                          const riskBadge =
                            row.riskLevel === "high"
                              ? "bg-red-500/20 text-red-300 border-red-500/40"
                              : row.riskLevel === "medium"
                              ? "bg-amber-500/20 text-amber-300 border-amber-500/40"
                              : row.riskLevel === "low"
                              ? "bg-cyan-500/15 text-cyan-300 border-cyan-500/30"
                              : "bg-slate-800 text-slate-400 border-slate-700";

                          return (
                            <React.Fragment key={row.port}>
                              <tr
                                id={`port-row-${row.port}`}
                                onClick={() => togglePortExpand(row.port)}
                                className={`cursor-pointer transition-colors ${
                                  isExpanded
                                    ? "bg-[#182232]/90"
                                    : "hover:bg-[#182232]/50"
                                }`}
                              >
                                <td className="py-3 px-4 font-bold text-white whitespace-nowrap">
                                  <div className="flex items-center gap-1.5">
                                    {isExpanded ? (
                                      <ChevronDown className="w-3.5 h-3.5 text-[#10B981]" />
                                    ) : (
                                      <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                                    )}
                                    <span>{row.port}</span>
                                    <span className="text-slate-500 font-normal">
                                      /{row.protocol}
                                    </span>
                                  </div>
                                </td>
                                <td className="py-3 px-3 whitespace-nowrap">
                                  <span
                                    className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold uppercase border ${stateBadge}`}
                                  >
                                    {row.state}
                                  </span>
                                </td>
                                <td className="py-3 px-3 whitespace-nowrap">
                                  <div className="flex items-center gap-2">
                                    <span className="text-slate-200 font-medium">
                                      {row.service}
                                    </span>
                                    {row.state === "open" && (
                                      <span
                                        className={`px-1.5 py-0.2 rounded text-[9px] uppercase border ${riskBadge}`}
                                      >
                                        {row.riskLevel}
                                      </span>
                                    )}
                                  </div>
                                </td>
                                <td className="py-3 px-3 whitespace-nowrap text-slate-300 tabular-nums">
                                  {row.latencyMs ?? 1} ms
                                </td>
                                <td className="py-3 px-4">
                                  {row.banner ? (
                                    <code className="text-[#06B6D4] break-all line-clamp-1">
                                      {row.banner}
                                    </code>
                                  ) : (
                                    <span className="text-slate-500">
                                      {row.state === "closed"
                                        ? "TCP RST (Connection Refused)"
                                        : "No SYN/ACK response within timeout"}
                                    </span>
                                  )}
                                </td>
                              </tr>

                              {/* Expandable Deep-Dive Banner & Hex Inspector */}
                              {isExpanded && (
                                <tr className="bg-[#090D16]/95 border-b border-slate-800">
                                  <td colSpan={5} className="p-4">
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                                      <div className="space-y-2.5">
                                        <div>
                                          <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                                            Captured Service Banner (ASCII)
                                          </div>
                                          <div className="p-2.5 rounded bg-[#111827] border border-slate-800 font-mono text-[#06B6D4] break-all">
                                            {row.banner ||
                                              "No application payload returned on socket."}
                                          </div>
                                        </div>

                                        <div>
                                          <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                                            Raw Socket Payload (Hexadecimal)
                                          </div>
                                          <div className="p-2.5 rounded bg-[#111827] border border-slate-800 font-mono text-[11px] text-slate-300 break-all leading-relaxed">
                                            {row.rawHex ||
                                              "00 00 00 00 (No payload bytes)"}
                                          </div>
                                        </div>
                                      </div>

                                      <div className="space-y-2.5">
                                        <div>
                                          <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                                            Network Security Assessment Advisory
                                          </div>
                                          <div className="p-2.5 rounded bg-[#111827] border border-slate-800 text-slate-200 font-sans leading-relaxed">
                                            {row.securityNotes ||
                                              "Standard TCP port telemetry verified."}
                                          </div>
                                        </div>

                                        <div>
                                          <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                                            Python Socket Probe Trace
                                          </div>
                                          <div className="p-2.5 rounded bg-[#111827] border border-slate-800 font-mono text-[11px] text-emerald-300/90">
                                            sock =
                                            socket.socket(socket.AF_INET,
                                            socket.SOCK_STREAM)
                                            <br />
                                            sock.settimeout(
                                            {(
                                              (currentScan?.timeoutMs ?? 400) /
                                              1000
                                            ).toFixed(2)}
                                            ) ; sock.connect_ex((&apos;
                                            {currentScan?.targetHost}&apos;,{" "}
                                            {row.port}))
                                          </div>
                                        </div>
                                      </div>
                                    </div>
                                  </td>
                                </tr>
                              )}
                            </React.Fragment>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </section>
          </div>
        )}

        {/* TAB 2: SCAN HISTORY & STRUCTURED TXT/CSV REPORTS */}
        {activeTab === "history" && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            {/* Left Column: Persisted PostgreSQL Scan Archive (5 Columns) */}
            <div className="lg:col-span-5 bg-[#111827] border border-slate-800 rounded-md p-5">
              <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
                <div>
                  <h2 className="text-base font-bold text-white">
                    Persisted Scan Archive
                  </h2>
                  <p className="text-xs text-slate-400">
                    Stored in PostgreSQL for historical security analysis
                  </p>
                </div>
                <span className="px-2 py-1 rounded text-xs font-mono bg-slate-800 text-[#10B981]">
                  {scansHistory.length} Sessions
                </span>
              </div>

              <div className="space-y-3 max-h-[620px] overflow-y-auto pr-1">
                {scansHistory.map((scan) => {
                  const isSelected = currentScan?.id === scan.id;
                  return (
                    <div
                      key={scan.id}
                      onClick={() => handleLoadHistoricalScan(scan.id)}
                      className={`p-3.5 rounded-md border transition-all cursor-pointer ${
                        isSelected
                          ? "bg-[#182232] border-[#10B981]"
                          : "bg-[#090D16]/70 border-slate-800 hover:border-slate-700"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-[#06B6D4]">
                            SCAN #{scan.id}
                          </span>
                          <span className="font-mono text-sm font-bold text-white">
                            {scan.targetHost}
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[#10B981]/15 text-[#10B981] border border-[#10B981]/30">
                            {scan.openCount} OPEN
                          </span>
                          <button
                            type="button"
                            onClick={(e) => handleDeleteScan(scan.id, e)}
                            title="Delete scan record"
                            className="p-1 rounded text-slate-500 hover:text-red-400 hover:bg-slate-800"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>

                      <div className="text-xs text-slate-300 mt-1">
                        {scan.targetLabel}
                      </div>

                      <div className="flex flex-wrap items-center justify-between gap-2 mt-2.5 pt-2 border-t border-slate-800/80 text-[11px] font-mono text-slate-400">
                        <span>
                          Ports: {scan.totalPortsScanned} ({scan.durationMs}ms)
                        </span>
                        <span>
                          {new Date(scan.createdAt).toLocaleString()}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Right Column: Live Structured Report Generator & Exporter (7 Columns) */}
            <div className="lg:col-span-7 bg-[#111827] border border-slate-800 rounded-md p-5 flex flex-col gap-4">
              <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
                <div>
                  <h2 className="text-base font-bold text-white flex items-center gap-2">
                    <FileText className="w-4 h-4 text-[#10B981]" />
                    <span>
                      Structured Security Assessment Report{" "}
                      {currentScan ? `(#${currentScan.id})` : ""}
                    </span>
                  </h2>
                  <p className="text-xs text-slate-400">
                    Exportable plain-text (.TXT) and RFC 4180 comma-separated
                    (.CSV) documentation
                  </p>
                </div>

                {currentScan && (
                  <div className="flex items-center gap-2">
                    <div className="flex bg-[#090D16] p-0.5 rounded border border-slate-800">
                      <button
                        type="button"
                        onClick={() => setReportPreviewFormat("txt")}
                        className={`px-2.5 py-1 rounded text-xs font-mono ${
                          reportPreviewFormat === "txt"
                            ? "bg-[#182232] text-[#10B981] font-semibold"
                            : "text-slate-400"
                        }`}
                      >
                        TXT Format
                      </button>
                      <button
                        type="button"
                        onClick={() => setReportPreviewFormat("csv")}
                        className={`px-2.5 py-1 rounded text-xs font-mono ${
                          reportPreviewFormat === "csv"
                            ? "bg-[#182232] text-[#10B981] font-semibold"
                            : "text-slate-400"
                        }`}
                      >
                        CSV Format
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={() =>
                        copyToClipboard(reportPreviewText, "report")
                      }
                      className="px-2.5 py-1.5 rounded bg-[#182232] hover:bg-slate-700 border border-slate-700 text-xs font-mono text-slate-200 flex items-center gap-1"
                    >
                      {copiedReport ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-[#10B981]" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy</span>
                        </>
                      )}
                    </button>

                    <a
                      href={`/api/scans/${currentScan.id}/export?format=txt`}
                      download
                      className="px-3 py-1.5 rounded bg-[#06B6D4]/20 hover:bg-[#06B6D4]/30 border border-[#06B6D4]/40 text-xs font-mono text-[#06B6D4] flex items-center gap-1.5"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download .TXT</span>
                    </a>

                    <a
                      href={`/api/scans/${currentScan.id}/export?format=csv`}
                      download
                      className="px-3 py-1.5 rounded bg-[#10B981] hover:bg-[#059669] text-[#052E16] font-bold text-xs font-mono flex items-center gap-1.5"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download .CSV</span>
                    </a>
                  </div>
                )}
              </div>

              <div className="bg-[#090D16] border border-slate-800 rounded p-4 font-mono text-xs text-slate-200 overflow-x-auto max-h-[540px] overflow-y-auto">
                {loadingReport ? (
                  <div className="text-slate-400 py-8 text-center">
                    Generating structured report preview...
                  </div>
                ) : (
                  <pre className="leading-relaxed whitespace-pre">
                    {reportPreviewText}
                  </pre>
                )}
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: LAB NODES & PYTHON CLI SOURCE */}
        {activeTab === "lab-cli" && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            {/* Left Column: Authorized VirtualBox Lab Node Registry (5 Columns) */}
            <div className="lg:col-span-5 flex flex-col gap-5">
              <div className="bg-[#111827] border border-slate-800 rounded-md p-5">
                <div className="pb-3 mb-4 border-b border-slate-800">
                  <h2 className="text-base font-bold text-white flex items-center gap-2">
                    <Server className="w-4 h-4 text-[#10B981]" />
                    <span>Register Authorized Lab Node</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Add custom VirtualBox Host-Only (`vboxnet0`), NAT, or local
                    test targets within RFC1918 private subnets.
                  </p>
                </div>

                <form onSubmit={handleCreateLabTarget} className="space-y-3">
                  <div>
                    <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                      Lab Node Name
                    </label>
                    <input
                      type="text"
                      required
                      value={newTargetName}
                      onChange={(e) => setNewTargetName(e.target.value)}
                      placeholder="e.g. OWASP Broken Web Apps VM"
                      className="w-full h-9 px-3 rounded bg-[#090D16] border border-slate-700 text-xs text-white focus:outline-none focus:border-[#10B981]"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                        Private IP / Host
                      </label>
                      <input
                        type="text"
                        required
                        value={newTargetHost}
                        onChange={(e) => setNewTargetHost(e.target.value)}
                        placeholder="192.168.56.110"
                        className="w-full h-9 px-3 rounded bg-[#090D16] border border-slate-700 font-mono text-xs text-white focus:outline-none focus:border-[#10B981]"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                        Lab Network Interface
                      </label>
                      <input
                        type="text"
                        value={newTargetEnv}
                        onChange={(e) => setNewTargetEnv(e.target.value)}
                        className="w-full h-9 px-3 rounded bg-[#090D16] border border-slate-700 text-xs text-white focus:outline-none focus:border-[#10B981]"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                        OS / Service Profile
                      </label>
                      <input
                        type="text"
                        value={newTargetOs}
                        onChange={(e) => setNewTargetOs(e.target.value)}
                        className="w-full h-9 px-3 rounded bg-[#090D16] border border-slate-700 text-xs text-white focus:outline-none focus:border-[#10B981]"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                        Default Port Spec
                      </label>
                      <input
                        type="text"
                        value={newTargetPorts}
                        onChange={(e) => setNewTargetPorts(e.target.value)}
                        className="w-full h-9 px-3 rounded bg-[#090D16] border border-slate-700 font-mono text-xs text-white focus:outline-none focus:border-[#10B981]"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold uppercase text-slate-400 mb-1">
                      Security Assessment Notes
                    </label>
                    <input
                      type="text"
                      value={newTargetDesc}
                      onChange={(e) => setNewTargetDesc(e.target.value)}
                      className="w-full h-9 px-3 rounded bg-[#090D16] border border-slate-700 text-xs text-white focus:outline-none focus:border-[#10B981]"
                    />
                  </div>

                  {targetFormError && (
                    <div className="p-2.5 rounded bg-red-950/60 border border-red-500/40 text-xs text-red-200">
                      {targetFormError}
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={isCreatingTarget}
                    className="w-full py-2 px-4 rounded bg-[#10B981] hover:bg-[#059669] text-[#052E16] font-bold text-xs uppercase tracking-wider flex items-center justify-center gap-1.5 cursor-pointer"
                  >
                    <Plus className="w-4 h-4" />
                    <span>Add Authorized Lab Target</span>
                  </button>
                </form>
              </div>

              {/* CLI Usage Guide */}
              <div className="bg-[#111827] border border-slate-800 rounded-md p-5 space-y-3">
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-[#06B6D4]" />
                  <span>Standalone CLI Reference</span>
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Run <code className="text-[#10B981]">scripts/scanner.py</code>{" "}
                  directly from any terminal on your host machine or Kali Linux
                  VirtualBox VM:
                </p>
                <div className="space-y-2 font-mono text-[11px]">
                  <div className="p-2.5 rounded bg-[#090D16] border border-slate-800 text-slate-300">
                    <div className="text-slate-500 mb-1">
                      # Scan localhost with banner grabbing &amp; text output
                    </div>
                    <span className="text-[#10B981]">
                      python3 scripts/scanner.py --host 127.0.0.1 --ports
                      &quot;21,22,80,5432,8080&quot; --banner --format text
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-[#090D16] border border-slate-800 text-slate-300">
                    <div className="text-slate-500 mb-1">
                      # Scan VirtualBox Host-Only VM and export CSV + TXT files
                    </div>
                    <span className="text-[#06B6D4]">
                      python3 scripts/scanner.py --host 192.168.56.101 --ports
                      1-1024 --timeout 400 --threads 25 --banner --csv-out
                      audit.csv --txt-out audit.txt
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Right Column: Live Python Scanner Source Code Viewer (7 Columns) */}
            <div className="lg:col-span-7 bg-[#111827] border border-slate-800 rounded-md p-5">
              <div className="flex flex-wrap items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-800">
                <div>
                  <h2 className="text-base font-bold text-white flex items-center gap-2">
                    <Code2 className="w-4 h-4 text-[#10B981]" />
                    <span>scripts/scanner.py — Python Socket Source</span>
                  </h2>
                  <p className="text-xs text-slate-400">
                    Built with Python standard library{" "}
                    <code className="text-slate-300">socket</code>,{" "}
                    <code className="text-slate-300">concurrent.futures</code>,{" "}
                    <code className="text-slate-300">argparse</code>, and{" "}
                    <code className="text-slate-300">csv</code>
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => copyToClipboard(pythonSource, "source")}
                    className="px-3 py-1.5 rounded bg-[#182232] hover:bg-slate-700 border border-slate-700 text-xs font-mono text-slate-200 flex items-center gap-1.5"
                  >
                    {copiedSource ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-[#10B981]" />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy Source</span>
                      </>
                    )}
                  </button>
                  <a
                    href="/api/source?download=1"
                    download="scanner.py"
                    className="px-3 py-1.5 rounded bg-[#10B981] hover:bg-[#059669] text-[#052E16] font-bold text-xs font-mono flex items-center gap-1.5"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download scanner.py</span>
                  </a>
                </div>
              </div>

              <div className="bg-[#090D16] border border-slate-800 rounded p-4 font-mono text-xs text-slate-200 overflow-x-auto max-h-[600px] overflow-y-auto">
                <pre className="leading-relaxed">{pythonSource}</pre>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
