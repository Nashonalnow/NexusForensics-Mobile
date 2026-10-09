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

    // Initial Load
    loadStatus();
});
