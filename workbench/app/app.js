// NexusForensics Mobile™ | Interactive Client Controller
document.addEventListener("DOMContentLoaded", () => {

    // Tab Navigation
    const navButtons = document.querySelectorAll(".nav-btn");
    const tabPanes = document.querySelectorAll(".tab-pane");

    window.switchTab = function(tabId) {
        navButtons.forEach(btn => {
            btn.classList.toggle("active", btn.getAttribute("data-tab") === tabId);
        });
        tabPanes.forEach(pane => {
            pane.classList.toggle("active", pane.id === tabId);
        });

        // Trigger context refresh
        if (tabId === "tab-evidence") {
            loadEvidence();
            loadChainOfCustody();
        } else if (tabId === "tab-timeline") {
            loadTimeline();
        } else if (tabId === "tab-threats") {
            loadThreats();
        } else if (tabId === "tab-devices") {
            loadDevices();
        } else if (tabId === "tab-sqlite") {
            refreshSqliteArtifacts();
        } else if (tabId === "tab-replay") {
            loadReplay();
        } else if (tabId === "tab-graph") {
            loadGraph();
        } else if (tabId === "tab-findings") {
            loadFindings();
        }
    };


    navButtons.forEach(btn => {
        btn.addEventListener("click", () => switchTab(btn.getAttribute("data-tab")));
    });

    // Utilities
    function escapeHtml(str) {
        if (!str) return "";
        return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    // 1. Status & Overview Loading
    async function loadStatus() {
        try {
            const res = await fetch("/api/status");
            const data = await res.json();

            document.getElementById("statArtifacts").textContent = data.total_artifacts || 0;
            document.getElementById("statTimeline").textContent = data.total_timeline_events || 0;
            document.getElementById("statFindings").textContent = data.total_findings || 0;
            document.getElementById("statDevices").textContent = data.connected_android_devices || 0;

            if (data.case) {
                document.getElementById("headerCaseId").textContent = data.case.case_id;
                document.getElementById("caseTitle").textContent = data.case.title;
                document.getElementById("caseExaminer").textContent = data.case.examiner;
                document.getElementById("caseOrg").textContent = data.case.organization;
                document.getElementById("caseNotes").textContent = data.case.notes || "None provided";
            }

            if (data.evidence_storage_path) {
                document.getElementById("caseStoragePath").textContent = data.evidence_storage_path;
            }
        } catch (e) {
            console.warn("Status load error:", e);
        }
    }

    // 2. Evidence & Chain of Custody
    async function loadEvidence() {
        try {
            const res = await fetch("/api/artifacts");
            const data = await res.json();
            const list = data.artifacts || [];
            const tbody = document.getElementById("evidenceTableBody");

            if (list.length === 0) {
                tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#94a3b8; padding:20px;">No evidence artifacts ingested yet.</td></tr>`;
                return;
            }

            tbody.innerHTML = list.map(art => `
                <tr>
                    <td><code style="color:#00d2ff; font-family:var(--font-mono); font-size:0.75rem;">${escapeHtml(art.artifact_id)}</code></td>
                    <td style="font-weight:600;">${escapeHtml(art.file_name)}</td>
                    <td><span class="badge-version">${escapeHtml(art.origin)}</span></td>
                    <td style="font-family:var(--font-mono); font-size:0.75rem;">${(art.file_size_bytes / 1024).toFixed(1)} KB</td>
                    <td><code style="font-size:0.72rem; color:#94a3b8; word-break:break-all;" title="${art.sha256}">${art.sha256.substring(0, 16)}...</code></td>
                    <td><span class="score-badge grade-secure">${art.integrity_status}</span></td>
                    <td>
                        ${art.mime_type.includes("sqlite") ? `<button class="btn-secondary" style="padding:2px 8px; font-size:0.72rem;" onclick="selectAndInspectSqlite('${art.artifact_id}')">Inspect DB</button>` : `<span style="color:#94a3b8; font-size:0.72rem;">Indexed</span>`}
                    </td>
                </tr>
            `).join("");
        } catch (e) {
            console.warn("Evidence load error:", e);
        }
    }

    async function loadChainOfCustody() {
        try {
            const res = await fetch("/api/coc");
            const data = await res.json();
            const list = data.records || [];
            const tbody = document.getElementById("cocTableBody");

            if (list.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:#94a3b8; padding:20px;">No Chain of Custody entries recorded.</td></tr>`;
                return;
            }

            tbody.innerHTML = list.map(r => `
                <tr>
                    <td><code style="color:#00d2ff; font-family:var(--font-mono); font-size:0.72rem;">${r.record_id}</code></td>
                    <td style="font-family:var(--font-mono); font-size:0.75rem; color:#cbd5e1;">${new Date(r.timestamp * 1000).toISOString().replace("T", " ").substring(0, 19)} UTC</td>
                    <td><span class="score-badge grade-nist">${r.action}</span></td>
                    <td style="color:#00f59b; font-weight:600;">${escapeHtml(r.examiner)}</td>
                    <td><code style="font-size:0.72rem;">${escapeHtml(r.artifact_id)}</code></td>
                    <td style="font-size:0.8rem; color:#cbd5e1;">${escapeHtml(r.details)}</td>
                </tr>
            `).join("");
        } catch (e) {
            console.warn("CoC load error:", e);
        }
    }

    // 3. Quick Ingest NexusProxy-Mobile
    const btnQuickIngestNexusProxy = document.getElementById("btnQuickIngestNexusProxy");
    if (btnQuickIngestNexusProxy) {
        btnQuickIngestNexusProxy.addEventListener("click", async () => {
            btnQuickIngestNexusProxy.disabled = true;
            btnQuickIngestNexusProxy.textContent = "Ingesting & Verifying SHA-256 Manifest...";

            try {
                const res = await fetch("/api/ingest/nexusproxy", { method: "POST" });
                const data = await res.json();
                if (res.ok) {
                    alert(`✓ NexusProxy Evidence Ingested Successfully!\n\nArtifact: ${data.artifact.file_name}\nFiles Verified: ${data.verification.verified_files}\nTimeline Events Added: ${data.timeline_events_ingested}\nIoCs Detected: ${data.ioc_findings.length}`);
                    loadStatus();
                    loadEvidence();
                    loadChainOfCustody();
                } else {
                    alert("Ingest Error: " + data.detail);
                }
            } catch (e) {
                alert("Network error: " + e.message);
            } finally {
                btnQuickIngestNexusProxy.disabled = false;
                btnQuickIngestNexusProxy.textContent = "⚡ Ingest NexusProxy-Mobile Package";
            }
        });
    }

    // Path Ingest
    const btnIngestPath = document.getElementById("btnIngestPath");
    const inputFilePath = document.getElementById("inputFilePath");
    if (btnIngestPath && inputFilePath) {
        btnIngestPath.addEventListener("click", async () => {
            const path = inputFilePath.value.trim();
            if (!path) {
                alert("Please enter a valid file path.");
                return;
            }
            btnIngestPath.disabled = true;
            try {
                const res = await fetch("/api/ingest/file", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ file_path: path, origin: "Local Disk" })
                });
                const data = await res.json();
                if (res.ok) {
                    alert(`✓ Ingested: ${data.artifact.file_name} (${data.artifact.sha256.substring(0, 16)}...)`);
                    inputFilePath.value = "";
                    loadStatus();
                    loadEvidence();
                    loadChainOfCustody();
                } else {
                    alert("Error: " + data.detail);
                }
            } catch (e) {
                alert("Error: " + e.message);
            } finally {
                btnIngestPath.disabled = false;
            }
        });
    }

    // Upload Ingest
    const btnUploadFile = document.getElementById("btnUploadFile");
    const inputFileUpload = document.getElementById("inputFileUpload");
    if (btnUploadFile && inputFileUpload) {
        btnUploadFile.addEventListener("click", async () => {
            if (!inputFileUpload.files || inputFileUpload.files.length === 0) {
                alert("Please choose a file to upload.");
                return;
            }
            const file = inputFileUpload.files[0];
            const formData = new FormData();
            formData.append("file", file);

            btnUploadFile.disabled = true;
            btnUploadFile.textContent = "Uploading & Hashing...";
            try {
                const res = await fetch("/api/ingest/upload", {
                    method: "POST",
                    body: formData
                });
                const data = await res.json();
                if (res.ok) {
                    alert(`✓ Uploaded and hashed: ${data.artifact.file_name}`);
                    inputFileUpload.value = "";
                    loadStatus();
                    loadEvidence();
                    loadChainOfCustody();
                } else {
                    alert("Upload Error: " + data.detail);
                }
            } catch (e) {
                alert("Upload Network Error: " + e.message);
            } finally {
                btnUploadFile.disabled = false;
                btnUploadFile.textContent = "Upload & Hash";
            }
        });
    }

    // 4. SQLite Inspector Logic
    async function refreshSqliteArtifacts() {
        const select = document.getElementById("sqliteArtifactSelect");
        if (!select) return;
        try {
            const res = await fetch("/api/artifacts");
            const data = await res.json();
            const dbs = (data.artifacts || []).filter(a => a.mime_type.includes("sqlite") || a.file_name.endsWith(".db") || a.file_name.endsWith(".sqlite"));

            select.innerHTML = '<option value="">Select Ingested SQLite Database...</option>' +
                dbs.map(d => `<option value="${d.artifact_id}">${escapeHtml(d.file_name)} (${(d.file_size_bytes/1024).toFixed(1)} KB)</option>`).join("");
        } catch (e) {
            console.warn("SQLite artifacts error:", e);
        }
    }

    window.selectAndInspectSqlite = function(artId) {
        switchTab("tab-sqlite");
        const select = document.getElementById("sqliteArtifactSelect");
        if (select) {
            select.value = artId;
            document.getElementById("btnInspectSqlite").click();
        }
    };

    let activeInspectedArtifactId = null;
    const btnInspectSqlite = document.getElementById("btnInspectSqlite");
    if (btnInspectSqlite) {
        btnInspectSqlite.addEventListener("click", async () => {
            const select = document.getElementById("sqliteArtifactSelect");
            const artId = select.value;
            if (!artId) {
                alert("Please select an ingested SQLite database first.");
                return;
            }
            activeInspectedArtifactId = artId;
            btnInspectSqlite.disabled = true;
            btnInspectSqlite.textContent = "Carving Schema...";

            try {
                const res = await fetch("/api/sqlite/inspect", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ artifact_id: artId })
                });
                const data = await res.json();
                if (res.ok) {
                    const insp = data.inspection;
                    const metaDiv = document.getElementById("sqliteDbMetadata");
                    metaDiv.style.display = "flex";
                    document.getElementById("metaWal").textContent = insp.has_wal ? "YES (Active Journal)" : "NO";
                    document.getElementById("metaFreelist").textContent = insp.freelist_pages;
                    document.getElementById("metaPageSize").textContent = `${insp.page_size} bytes`;
                    document.getElementById("metaTableCount").textContent = insp.table_count;

                    // Render tables list
                    const listContainer = document.getElementById("sqliteTablesList");
                    const tables = insp.tables || [];
                    if (tables.length === 0) {
                        listContainer.innerHTML = '<span style="color:#94a3b8;">No user tables found in database.</span>';
                    } else {
                        listContainer.innerHTML = tables.map(t => `
                            <div style="background:#0c1424; padding:6px 10px; border-radius:4px; cursor:pointer; display:flex; justify-content:space-between; align-items:center;" onclick="loadSqliteTable('${escapeHtml(t.table_name)}')">
                                <span style="color:#00d2ff; font-weight:600;">${escapeHtml(t.table_name)}</span>
                                <span style="font-size:0.72rem; color:#94a3b8; font-family:var(--font-mono);">${t.row_count} rows</span>
                            </div>
                        `).join("");

                        // Auto-load first table
                        if (tables.length > 0) {
                            loadSqliteTable(tables[0].table_name);
                        }
                    }
                } else {
                    alert("Inspection Error: " + data.detail);
                }
            } catch (e) {
                alert("Network error: " + e.message);
            } finally {
                btnInspectSqlite.disabled = false;
                btnInspectSqlite.textContent = "🔍 Inspect Database";
            }
        });
    }

    window.loadSqliteTable = async function(tableName) {
        if (!activeInspectedArtifactId) return;
        document.getElementById("activeTableName").textContent = tableName;
        document.getElementById("activeTableRowCount").textContent = "Querying...";

        try {
            const res = await fetch("/api/sqlite/query", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ artifact_id: activeInspectedArtifactId, table_name: tableName, limit: 50, offset: 0 })
            });
            const data = await res.json();
            if (res.ok) {
                const q = data.query_result;
                document.getElementById("activeTableRowCount").textContent = `Showing ${q.rows.length} of ${q.total_rows} rows`;

                // Render header
                const headerRow = document.getElementById("sqliteDataHeader");
                headerRow.innerHTML = (q.columns || []).map(c => `<th>${escapeHtml(c)}</th>`).join("");

                // Render rows
                const body = document.getElementById("sqliteDataBody");
                if (q.rows.length === 0) {
                    body.innerHTML = `<tr><td colspan="${q.columns.length}" style="text-align:center; color:#94a3b8; padding:20px;">Table is empty.</td></tr>`;
                } else {
                    body.innerHTML = q.rows.map(r => `
                        <tr>
                            ${q.columns.map(c => `<td style="font-family:var(--font-mono); font-size:0.75rem;">${escapeHtml(String(r[c] !== null && r[c] !== undefined ? r[c] : 'NULL'))}</td>`).join("")}
                        </tr>
                    `).join("");
                }
            }
        } catch (e) {
            console.warn("Table query error:", e);
        }
    };

    // 5. Timeline Logic
    async function loadTimeline() {
        const cat = document.getElementById("timelineCategorySelect").value;
        const search = document.getElementById("timelineSearchInput").value.trim();
        const container = document.getElementById("timelineContainer");

        try {
            let url = "/api/timeline?limit=150";
            if (cat) url += `&category=${encodeURIComponent(cat)}`;
            if (search) url += `&search=${encodeURIComponent(search)}`;

            const res = await fetch(url);
            const data = await res.json();
            const events = data.events || [];

            if (events.length === 0) {
                container.innerHTML = `<div style="text-align:center; color:#94a3b8; padding:30px;">No matching timeline events found.</div>`;
                return;
            }

            container.innerHTML = events.map(ev => {
                const catClass = `cat-${ev.category.toLowerCase()}`;
                return `
                    <div class="timeline-item ${catClass}">
                        <div class="timeline-header">
                            <span style="font-weight:700; color:#f8fafc;">${escapeHtml(ev.summary)}</span>
                            <span class="timeline-time">${escapeHtml(ev.timestamp_utc)}</span>
                        </div>
                        <div style="font-size:0.75rem; color:#94a3b8; display:flex; gap:10px; margin-top:2px;">
                            <span>Category: <strong style="color:#cbd5e1;">${ev.category}</strong></span>
                            <span>Source: <code style="color:#00d2ff;">${escapeHtml(ev.source_artifact)}</code></span>
                        </div>
                    </div>
                `;
            }).join("");
        } catch (e) {
            console.warn("Timeline error:", e);
        }
    }

    const btnRefreshTimeline = document.getElementById("btnRefreshTimeline");
    if (btnRefreshTimeline) btnRefreshTimeline.addEventListener("click", loadTimeline);
    const timelineCategorySelect = document.getElementById("timelineCategorySelect");
    if (timelineCategorySelect) timelineCategorySelect.addEventListener("change", loadTimeline);
    const timelineSearchInput = document.getElementById("timelineSearchInput");
    if (timelineSearchInput) {
        timelineSearchInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") loadTimeline();
        });
    }

    // 6. Threat & IoC Guard
    async function loadThreats() {
        try {
            const res = await fetch("/api/ioc/findings");
            const data = await res.json();
            const findings = data.findings || [];
            const container = document.getElementById("threatsContainer");
            const badge = document.getElementById("threatsCountBadge");

            badge.textContent = `${findings.length} FINDINGS`;

            if (findings.length === 0) {
                container.innerHTML = `<div style="text-align:center; color:#94a3b8; padding:30px;">No security threats or stalkerware IoCs detected. Evidence is clean.</div>`;
                return;
            }

            container.innerHTML = findings.map(f => {
                const sev = (f.severity || "info").toLowerCase();
                return `
                    <div class="threat-card sev-${sev}">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                            <span style="font-weight:700; font-size:0.95rem; color:#f8fafc;">${escapeHtml(f.title)}</span>
                            <div style="display:flex; gap:6px; align-items:center;">
                                <span class="threat-tag tag-${sev}">${f.severity.toUpperCase()}</span>
                                <span class="badge-version">${escapeHtml(f.mitre_attack_id || 'MITRE')}</span>
                            </div>
                        </div>
                        <p style="font-size:0.82rem; color:#cbd5e1; margin-bottom:6px;">${escapeHtml(f.description)}</p>
                        <div style="font-size:0.75rem; background:#080d16; padding:6px 10px; border-radius:4px; margin-bottom:6px; font-family:var(--font-mono); color:#94a3b8;">
                            Evidence: ${escapeHtml(f.evidence)}
                        </div>
                        <div style="font-size:0.78rem; color:#00f59b;">
                            <strong>Remediation:</strong> ${escapeHtml(f.remediation)}
                        </div>
                    </div>
                `;
            }).join("");
        } catch (e) {
            console.warn("Threats load error:", e);
        }
    }

    // 7. Live ADB Devices
    async function loadDevices() {
        const container = document.getElementById("devicesContainer");
        try {
            const res = await fetch("/api/devices");
            const data = await res.json();
            const devs = data.devices || [];

            if (devs.length === 0) {
                container.innerHTML = `
                    <div style="text-align:center; color:#94a3b8; padding:30px; grid-column:1/-1;">
                        <span style="font-size:2rem; display:block; margin-bottom:8px;">📱</span>
                        <strong>No connected Android testbeds detected via ADB.</strong><br>
                        Connect an Android device with USB debugging enabled or launch an Android emulator.
                    </div>
                `;
                return;
            }

            container.innerHTML = devs.map(d => `
                <div class="tactical-card" style="margin-bottom:0;">
                    <div class="card-header">
                        <span style="font-weight:700; color:#00d2ff;">${escapeHtml(d.model)}</span>
                        <span class="score-badge grade-secure">${d.state.toUpperCase()}</span>
                    </div>
                    <div style="font-size:0.8rem; color:#cbd5e1; display:flex; flex-direction:column; gap:4px;">
                        <div><strong>Serial:</strong> <code>${escapeHtml(d.serial)}</code></div>
                        <div><strong>OS Version:</strong> Android ${escapeHtml(d.os_version)} (SDK ${d.sdk_level})</div>
                        <div><strong>Security Patch:</strong> ${escapeHtml(d.security_patch)}</div>
                        <div><strong>Manufacturer:</strong> ${escapeHtml(d.manufacturer)}</div>
                    </div>
                </div>
            `).join("");
        } catch (e) {
            console.warn("Devices error:", e);
        }
    }

    const btnRefreshDevices = document.getElementById("btnRefreshDevices");
    if (btnRefreshDevices) btnRefreshDevices.addEventListener("click", loadDevices);

    // 8. Dossier Export
    const btnExportDossier = document.getElementById("btnExportDossier");
    if (btnExportDossier) {
        btnExportDossier.addEventListener("click", async () => {
            btnExportDossier.disabled = true;
            btnExportDossier.textContent = "Compiling NIST Dossier...";
            try {
                const res = await fetch("/api/report/export", { method: "POST" });
                const data = await res.json();
                const resDiv = document.getElementById("dossierExportResult");
                resDiv.innerHTML = `
                    <div style="color:#00f59b; font-weight:700; margin-bottom:8px; font-size:1rem;">✓ NIST SP 800-86 Forensic Dossier Exported</div>
                    <div><strong>Report File:</strong> <code>${escapeHtml(data.report_file)}</code></div>
                    <div><strong>Total Artifacts Sealed:</strong> ${data.dossier.integrity_seal.total_artifacts}</div>
                    <div><strong>Chain of Custody Events:</strong> ${data.dossier.integrity_seal.chain_of_custody_steps}</div>
                    <div><strong>Timeline Events Correlated:</strong> ${data.dossier.timeline_events.length}</div>
                    <div><strong>Cryptographic Evidentiary SHA-256 Digest:</strong></div>
                    <code style="color:#00d2ff; background:#0c1424; padding:4px 8px; border-radius:4px; display:inline-block; margin-top:4px; word-break:break-all;">${data.sha256}</code>
                `;
            } catch (e) {
                alert("Export error: " + e.message);
            } finally {
                btnExportDossier.disabled = false;
                btnExportDossier.textContent = "📦 Compile & Export Dossier";
            }
        });
    }

    // 9. Behavioral Replay Terminal ("Digital Witness")
    let replaySnapshots = [];
    let currentReplayIndex = 0;
    let replayTimer = null;

    async function loadReplay() {
        try {
            const res = await fetch("/api/v1/replay?limit=100");
            const data = await res.json();
            replaySnapshots = data.snapshots || [];
            const scrubber = document.getElementById("replayScrubber");
            if (!scrubber) return;

            if (replaySnapshots.length === 0) {
                document.getElementById("replayTimestamp").textContent = "No Telemetry Recorded";
                document.getElementById("replaySnapshotIndex").textContent = "Snapshot 0 of 0";
                document.getElementById("sensorLock").innerHTML = '<span class="state-badge state-locked">UNKNOWN</span>';
                document.getElementById("sensorBattery").textContent = "-- %";
                document.getElementById("sensorNetwork").innerHTML = '<span class="state-badge">OFFLINE</span>';
                document.getElementById("sensorApp").textContent = "None";
                document.getElementById("sensorMotion").textContent = "UNKNOWN";
                document.getElementById("sensorConfidence").textContent = "-- %";
                document.getElementById("replayEventsList").innerHTML = '<div style="text-align:center; color:#94a3b8; padding:16px; background:#080d16; border-radius:6px; font-size:0.8rem;">No behavioral snapshots extracted yet.</div>';
                scrubber.max = 0;
                scrubber.value = 0;
                return;
            }

            scrubber.max = replaySnapshots.length - 1;
            if (currentReplayIndex >= replaySnapshots.length) currentReplayIndex = 0;
            scrubber.value = currentReplayIndex;
            renderSnapshot(currentReplayIndex);
        } catch (e) {
            console.warn("Replay load error:", e);
        }
    }

    function renderSnapshot(idx) {
        if (!replaySnapshots || replaySnapshots.length === 0 || !replaySnapshots[idx]) return;
        const s = replaySnapshots[idx];
        currentReplayIndex = idx;
        const scrubber = document.getElementById("replayScrubber");
        if (scrubber) scrubber.value = idx;

        document.getElementById("replayTimestamp").textContent = `${s.timestamp} UTC`;
        document.getElementById("replaySnapshotIndex").textContent = `Snapshot ${idx + 1} of ${replaySnapshots.length}`;

        // Lock status
        const lockEl = document.getElementById("sensorLock");
        if (s.lock_state === "UNLOCKED") {
            lockEl.innerHTML = '<span class="state-badge state-unlocked">UNLOCKED (HUMAN ENGAGED)</span>';
        } else if (s.lock_state === "LOCKED") {
            lockEl.innerHTML = '<span class="state-badge state-locked">LOCKED (KEYGUARD ACTIVE)</span>';
        } else {
            lockEl.innerHTML = '<span class="state-badge">UNKNOWN</span>';
        }

        // Battery
        document.getElementById("sensorBattery").textContent = s.battery_level !== null ? `${s.battery_level}%` : "N/A";
        document.getElementById("sensorCharging").textContent = s.is_charging ? "⚡ Connected to AC / USB Power" : "Discharging (Battery)";

        // Network
        const netEl = document.getElementById("sensorNetwork");
        if (s.network_state === "WIFI") {
            netEl.innerHTML = '<span class="state-badge state-online">WI-FI</span>';
        } else if (s.network_state === "CELLULAR") {
            netEl.innerHTML = '<span class="state-badge state-online">CELLULAR 5G/LTE</span>';
        } else {
            netEl.innerHTML = '<span class="state-badge state-locked">OFFLINE</span>';
        }
        document.getElementById("sensorSsid").textContent = s.connected_ssid ? `SSID: ${s.connected_ssid}` : "No Active SSID";

        // Foreground App
        document.getElementById("sensorApp").textContent = s.foreground_app || "SpringBoard / System UI";

        // Motion
        document.getElementById("sensorMotion").textContent = s.motion_state;

        // Confidence
        const confEl = document.getElementById("sensorConfidence");
        confEl.textContent = `${s.confidence}%`;
        confEl.style.color = s.confidence >= 80 ? "var(--accent-green)" : (s.confidence >= 50 ? "var(--accent-amber)" : "var(--accent-red)");

        // Events list
        const evList = document.getElementById("replayEventsList");
        if (s.corroborating_events && s.corroborating_events.length > 0) {
            evList.innerHTML = s.corroborating_events.map(ev => `
                <div style="background:#080d16; border-left:3px solid var(--accent-cyan); padding:8px 12px; border-radius:0 4px 4px 0; font-size:0.8rem;">
                    <span style="font-family:var(--font-mono); color:#00d2ff;">[${escapeHtml(s.timestamp)}]</span>
                    <span style="color:#f8fafc; margin-left:6px;">${escapeHtml(ev)}</span>
                </div>
            `).join("");
        } else {
            evList.innerHTML = '<div style="text-align:center; color:#94a3b8; padding:12px; background:#080d16; border-radius:6px; font-size:0.8rem;">No direct event triggered at this second (state preserved).</div>';
        }
    }

    // Scrubber Controls
    const replayScrubber = document.getElementById("replayScrubber");
    if (replayScrubber) {
        replayScrubber.addEventListener("input", (e) => {
            renderSnapshot(parseInt(e.target.value, 10));
        });
    }

    const btnReplayPrev = document.getElementById("btnReplayPrev");
    if (btnReplayPrev) {
        btnReplayPrev.addEventListener("click", () => {
            if (currentReplayIndex > 0) renderSnapshot(currentReplayIndex - 1);
        });
    }

    const btnReplayNext = document.getElementById("btnReplayNext");
    if (btnReplayNext) {
        btnReplayNext.addEventListener("click", () => {
            if (currentReplayIndex < replaySnapshots.length - 1) renderSnapshot(currentReplayIndex + 1);
        });
    }

    const btnReplayPlay = document.getElementById("btnReplayPlay");
    if (btnReplayPlay) {
        btnReplayPlay.addEventListener("click", () => {
            if (replayTimer) {
                clearInterval(replayTimer);
                replayTimer = null;
                btnReplayPlay.textContent = "▶ Play";
                btnReplayPlay.classList.remove("btn-secondary");
                btnReplayPlay.classList.add("btn-primary");
            } else {
                btnReplayPlay.textContent = "⏸ Pause";
                btnReplayPlay.classList.remove("btn-primary");
                btnReplayPlay.classList.add("btn-secondary");
                replayTimer = setInterval(() => {
                    if (currentReplayIndex < replaySnapshots.length - 1) {
                        renderSnapshot(currentReplayIndex + 1);
                    } else {
                        renderSnapshot(0);
                    }
                }, 1000);
            }
        });
    }

    const btnRefreshReplay = document.getElementById("btnRefreshReplay");
    if (btnRefreshReplay) btnRefreshReplay.addEventListener("click", loadReplay);

    // 10. Temporal Graph Correlation Explorer
    async function loadGraph() {
        const container = document.getElementById("graphRelationsContainer");
        const filter = document.getElementById("graphFilterSelect").value;
        try {
            const res = await fetch("/api/v1/warehouse/query", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    sql: "SELECT r.relationship_id, r.source_event_id, r.target_event_id, r.relationship_type, r.weight, r.rationale, e1.description as src_desc, e1.category as src_cat, e1.timestamp as src_time, e2.description as tgt_desc, e2.category as tgt_cat, e2.timestamp as tgt_time FROM forensic.relationships r LEFT JOIN forensic.events e1 ON r.source_event_id=e1.event_id LEFT JOIN forensic.events e2 ON r.target_event_id=e2.event_id ORDER BY r.created_at DESC;"
                })
            });
            const data = await res.json();
            let rows = (data.result && data.result.rows) ? data.result.rows : [];

            if (filter) {
                rows = rows.filter(r => r.relationship_type === filter);
            }

            const countEl = document.getElementById("metaGraphCount");
            const supEl = document.getElementById("metaGraphSupports");
            const conEl = document.getElementById("metaGraphContradicts");
            if (countEl) {
                document.getElementById("graphSummaryMetrics").style.display = "flex";
                countEl.textContent = rows.length;
                supEl.textContent = rows.filter(r => r.relationship_type === "supports" || r.relationship_type === "used_app").length;
                conEl.textContent = rows.filter(r => r.relationship_type === "contradicts").length;
            }

            if (rows.length === 0) {
                container.innerHTML = '<div style="text-align:center; color:#94a3b8; padding:30px;">No temporal relationships matching the filter. Click "Run Correlation Engine" to re-scan.</div>';
                return;
            }

            container.innerHTML = rows.map(r => {
                const typeClass = `edge-${r.relationship_type.replace('_', '')}`;
                return `
                    <div class="graph-edge-row">
                        <div class="node-box">
                            <div class="node-title">${escapeHtml(r.src_desc || r.source_event_id)}</div>
                            <div class="node-meta">${escapeHtml(r.src_time || '')} • <span style="color:#00d2ff;">${r.src_cat || 'EVENT'}</span></div>
                        </div>
                        <div class="edge-connector">
                            <span class="edge-pill ${typeClass}">${escapeHtml(r.relationship_type)}</span>
                            <span style="font-size:0.68rem; color:#94a3b8;">Weight: ${r.weight}</span>
                        </div>
                        <div class="node-box">
                            <div class="node-title">${escapeHtml(r.tgt_desc || r.target_event_id)}</div>
                            <div class="node-meta">${escapeHtml(r.tgt_time || '')} • <span style="color:#00d2ff;">${r.tgt_cat || 'EVENT'}</span></div>
                        </div>
                    </div>
                `;
            }).join("");
        } catch (e) {
            console.warn("Graph load error:", e);
        }
    }

    const btnRunCorrelation = document.getElementById("btnRunCorrelation");
    if (btnRunCorrelation) {
        btnRunCorrelation.addEventListener("click", async () => {
            btnRunCorrelation.disabled = true;
            btnRunCorrelation.textContent = "Analyzing Temporal Windows...";
            try {
                const res = await fetch("/api/v1/correlation/run", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ window_seconds: 120.0 })
                });
                const data = await res.json();
                if (res.ok) {
                    alert(`✓ Temporal Correlation Completed!\nDiscovered ${data.relationships_discovered} causal/corroborative relationships across evidence.`);
                    loadGraph();
                } else {
                    alert("Correlation Error: " + data.detail);
                }
            } catch (e) {
                alert("Network error: " + e.message);
            } finally {
                btnRunCorrelation.disabled = false;
                btnRunCorrelation.textContent = "⚡ Run Correlation Engine";
            }
        });
    }

    const graphFilterSelect = document.getElementById("graphFilterSelect");
    if (graphFilterSelect) graphFilterSelect.addEventListener("change", () => loadGraph());

    // 11. Explainable Findings & Court Defense
    let activeFindingsList = [];

    async function loadFindings() {
        const container = document.getElementById("findingsContainer");
        try {
            const res = await fetch("/api/v1/findings");
            const data = await res.json();
            activeFindingsList = data.findings || [];

            if (activeFindingsList.length === 0) {
                container.innerHTML = '<div style="text-align:center; color:#94a3b8; padding:30px;">No findings synthesized yet. Click "Synthesize Findings" to compute evidence scoring.</div>';
                return;
            }

            container.innerHTML = activeFindingsList.map(f => {
                const conf = f.confidence;
                const confColor = conf >= 80 ? "#00f59b" : (conf >= 50 ? "#f59e0b" : "#ef4444");
                return `
                    <div class="finding-item-card" onclick="openFindingProof('${escapeHtml(f.finding_id)}')">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                            <span style="font-weight:700; font-size:1rem; color:#f8fafc;">${escapeHtml(f.title)}</span>
                            <div style="display:flex; gap:8px; align-items:center;">
                                <span class="score-badge" style="background:rgba(0,210,255,0.1); color:#00d2ff; font-family:var(--font-mono);">${escapeHtml(f.finding_type.toUpperCase())}</span>
                                <span class="score-badge" style="background:#0c1424; color:${confColor}; border:1px solid ${confColor}; font-weight:800;">CONFIDENCE: ${conf}%</span>
                            </div>
                        </div>
                        <p style="font-size:0.85rem; color:#cbd5e1; margin-bottom:8px;">${escapeHtml(f.description)}</p>
                        <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.75rem; color:#94a3b8;">
                            <span>Created: <code>${escapeHtml(f.created_at)}</code></span>
                            <span style="color:#00d2ff; font-weight:600;">🔍 View Mathematical Proof & Court Testimony &rarr;</span>
                        </div>
                    </div>
                `;
            }).join("");
        } catch (e) {
            console.warn("Findings load error:", e);
        }
    }

    const btnGenerateFindings = document.getElementById("btnGenerateFindings");
    if (btnGenerateFindings) {
        btnGenerateFindings.addEventListener("click", async () => {
            btnGenerateFindings.disabled = true;
            btnGenerateFindings.textContent = "Synthesizing Findings...";
            try {
                const res = await fetch("/api/v1/findings/generate", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
                const data = await res.json();
                if (res.ok) {
                    alert(`✓ Findings Synthesized!\nTotal findings evaluated: ${data.total_findings}`);
                    loadFindings();
                } else {
                    alert("Synthesis Error: " + data.detail);
                }
            } catch (e) {
                alert("Network error: " + e.message);
            } finally {
                btnGenerateFindings.disabled = false;
                btnGenerateFindings.textContent = "🔬 Synthesize Findings";
            }
        });
    }

    window.openFindingProof = async function(findingId) {
        const modal = document.getElementById("proofModal");
        const finding = activeFindingsList.find(f => f.finding_id === findingId);
        if (!finding) return;

        document.getElementById("modalFindingTitle").textContent = finding.title;
        document.getElementById("modalFindingScore").textContent = `${finding.confidence}%`;
        document.getElementById("modalFindingScore").style.color = finding.confidence >= 80 ? "#00f59b" : (finding.confidence >= 50 ? "#f59e0b" : "#ef4444");
        document.getElementById("modalFindingType").textContent = finding.finding_type.toUpperCase();

        // Fetch factors from warehouse
        try {
            const res = await fetch("/api/v1/warehouse/query", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ sql: `SELECT * FROM forensic.confidence_factors WHERE finding_id = '${findingId}';` })
            });
            const data = await res.json();
            const factors = (data.result && data.result.rows) ? data.result.rows : [];

            const listEl = document.getElementById("modalFactorsList");
            if (factors.length === 0) {
                listEl.innerHTML = '<div style="color:#94a3b8; font-size:0.8rem;">Direct empirical observation (Baseline confidence 100%).</div>';
            } else {
                listEl.innerHTML = factors.map(fact => {
                    const isPos = fact.score >= 0;
                    return `
                        <div style="background:#050911; border:1px solid var(--border-color); padding:10px 14px; border-radius:6px; display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <div style="font-weight:600; font-size:0.82rem; color:#f8fafc;">${escapeHtml(fact.explanation)}</div>
                                <div style="font-size:0.7rem; color:#94a3b8; font-family:var(--font-mono); margin-top:2px;">Factor Type: ${escapeHtml(fact.factor_type)}</div>
                            </div>
                            <span class="${isPos ? 'score-pill-pos' : 'score-pill-neg'}">${isPos ? '+' : ''}${fact.score} pts</span>
                        </div>
                    `;
                }).join("");
            }

            // Court Testimony
            const testimonyEl = document.getElementById("modalCourtTestimony");
            testimonyEl.innerHTML = `
                "Based on the empirical forensic acquisition, the finding entitled <strong>${escapeHtml(finding.title)}</strong> carries a validated confidence rating of <strong>${finding.confidence}%</strong>. Multiple independent hardware and logical artifact sources corroborate this conclusion, with zero unexplained contradictions observed across system timestamps in compliance with NIST SP 800-86."
            `;

            modal.classList.remove("hidden");
        } catch (e) {
            console.warn("Factors load error:", e);
        }
    };

    window.closeProofModal = function() {
        const modal = document.getElementById("proofModal");
        if (modal) modal.classList.add("hidden");
    };

    // 12. DuckDB Columnar Warehouse Terminal
    window.setPresetQuery = function(sql) {
        const editor = document.getElementById("sqlQueryInput");
        if (editor) editor.value = sql;
    };

    const btnExecuteSql = document.getElementById("btnExecuteSql");
    if (btnExecuteSql) {
        btnExecuteSql.addEventListener("click", async () => {
            const editor = document.getElementById("sqlQueryInput");
            const sql = editor ? editor.value.trim() : "";
            if (!sql) return;

            btnExecuteSql.disabled = true;
            btnExecuteSql.textContent = "Executing...";
            const metricsEl = document.getElementById("sqlExecutionMetrics");
            metricsEl.textContent = "Running query against DuckDB warehouse...";

            const t0 = performance.now();
            try {
                const res = await fetch("/api/v1/warehouse/query", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ sql: sql, limit: 100 })
                });
                const t1 = performance.now();
                const elapsed = (t1 - t0).toFixed(2);
                const data = await res.json();

                if (res.ok) {
                    const qRes = data.result;
                    metricsEl.innerHTML = `<span style="color:#00f59b;">✓ Query OK</span>: Returned <strong>${qRes.rows.length}</strong> rows in <strong>${elapsed} ms</strong>.`;

                    // Render table
                    const thead = document.getElementById("warehouseDataHeader");
                    thead.innerHTML = (qRes.columns || []).map(c => `<th>${escapeHtml(c)}</th>`).join("");

                    const tbody = document.getElementById("warehouseDataBody");
                    if (qRes.rows.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="100%" style="text-align:center; color:#94a3b8; padding:20px;">Query returned zero rows.</td></tr>';
                    } else {
                        tbody.innerHTML = qRes.rows.map(r => `
                            <tr>
                                ${qRes.columns.map(c => `<td style="font-family:var(--font-mono); font-size:0.75rem;">${escapeHtml(String(r[c] !== null && r[c] !== undefined ? r[c] : 'NULL'))}</td>`).join("")}
                            </tr>
                        `).join("");
                    }
                } else {
                    metricsEl.innerHTML = `<span style="color:#ef4444;">Query Error</span>: ${escapeHtml(data.detail)}`;
                }
            } catch (e) {
                metricsEl.innerHTML = `<span style="color:#ef4444;">Network Error</span>: ${escapeHtml(e.message)}`;
            } finally {
                btnExecuteSql.disabled = false;
                btnExecuteSql.textContent = "▶ Run Columnar Query";
            }
        });
    }

    // Initial Load
    loadStatus();
});

