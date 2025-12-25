(() => {
  // ---------- helpers ----------
  const $ = (id) => document.getElementById(id);

  const STATE = {
    results: [],
    runs: [],
    page: 1,
    pageSize: 20,
  };

  // scan ui state
  let scanRunning = false;
  let scanES = null; // single SSE connection
  let scanWatchdog = null; // таймаут если прогресс не приходит

  // ---------- toast ----------
  function toast(msg, type = "info", timeout = 2500) {
    const box = $("toast");
    if (!box) return;

    box.textContent = msg;
    box.classList.remove("hidden");
    box.dataset.type = type;

    setTimeout(() => box.classList.add("hidden"), timeout);
  }

  async function api(path, opts) {
    const res = await fetch(path, opts);
    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      throw new Error(txt || res.statusText);
    }
    const ct = res.headers.get("content-type") || "";
    if (!ct.includes("application/json")) return null;
    return res.json();
  }

  function fmt(ts) {
    if (!ts) return "—";
    try {
      return new Date(ts).toLocaleString();
    } catch {
      return String(ts);
    }
  }

  function escapeHtml(str) {
    return String(str ?? "").replace(/[&<>"']/g, (s) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[s]));
  }

  function ipToNum(ip) {
    const p = String(ip || "").split(".").map((x) => parseInt(x, 10));
    if (p.length !== 4 || p.some((x) => Number.isNaN(x))) return 0;
    return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
  }

  // ---------- filtering/rendering ----------
  function getFilteredSortedResults() {
    const q = ($("q")?.value || "").trim().toLowerCase();
    const svc = ($("svc")?.value || "").trim().toLowerCase();
    const sort = ($("sort")?.value || "lastSeenDesc").trim();

    let items = STATE.results.slice();

    if (svc) {
      items = items.filter((r) => String(r.service || "").toLowerCase() === svc);
    }

    if (q) {
      items = items.filter((r) => {
        const hay = `${r.ip}:${r.port} ${(r.service || "")} ${(r.banner || "")}`.toLowerCase();
        return hay.includes(q);
      });
    }

    items.sort((a, b) => {
      const aLS = Date.parse(a.last_seen || a.lastSeen || 0) || 0;
      const bLS = Date.parse(b.last_seen || b.lastSeen || 0) || 0;

      if (sort === "lastSeenAsc") return aLS - bLS;
      if (sort === "ipAsc") return ipToNum(a.ip) - ipToNum(b.ip);
      if (sort === "portAsc") return (a.port || 0) - (b.port || 0);

      // default lastSeenDesc
      return bLS - aLS;
    });

    return items;
  }

  function rebuildServiceOptions() {
    const svcSel = $("svc");
    if (!svcSel) return;

    const current = (svcSel.value || "").toLowerCase();

    const services = Array.from(
      new Set(
        STATE.results.map((r) => String((r.service || "unknown")).trim().toLowerCase())
      )
    ).sort();

    svcSel.innerHTML =
      `<option value="">All services</option>` +
      services.map((s) => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`).join("");

    svcSel.value = services.includes(current) ? current : "";
  }

  function renderResults() {
    const tbody = $("tbl");
    const count = $("count");
    const pageEl = $("page");
    const prevBtn = $("prev");
    const nextBtn = $("next");
    if (!tbody) return;

    const items = getFilteredSortedResults();
    const total = items.length;
    const totalPages = Math.max(1, Math.ceil(total / STATE.pageSize));

    if (STATE.page > totalPages) STATE.page = totalPages;
    if (STATE.page < 1) STATE.page = 1;

    const start = (STATE.page - 1) * STATE.pageSize;
    const pageItems = items.slice(start, start + STATE.pageSize);

    tbody.innerHTML = "";

    if (pageItems.length === 0) {
      tbody.innerHTML =
        `<tr><td colspan="6" style="padding:12px;color:#94a3b8">No findings</td></tr>`;
    } else {
      tbody.innerHTML = pageItems
        .map((x) => `
          <tr>
            <td>${escapeHtml(x.ip)}</td>
            <td>${escapeHtml(String(x.port))}/${escapeHtml(String(x.proto || "tcp"))}</td>
            <td>${escapeHtml(x.service || "unknown")}</td>
            <td>${escapeHtml(fmt(x.first_seen))}</td>
            <td>${escapeHtml(fmt(x.last_seen))}</td>
            <td title="${escapeHtml(String(x.banner || ""))}">
              ${escapeHtml(x.banner || "—")}
            </td>
          </tr>
        `)
        .join("");
    }

    if (count) count.textContent = `Showing ${pageItems.length} of ${total}`;
    if (pageEl) pageEl.textContent = `Page ${STATE.page} / ${totalPages}`;

    if (prevBtn) prevBtn.disabled = STATE.page <= 1;
    if (nextBtn) nextBtn.disabled = STATE.page >= totalPages;
  }

  function renderRuns() {
    const tbody = $("runs");
    if (!tbody) return;

    tbody.innerHTML = STATE.runs
      .map((r) => `
        <tr>
          <td>${escapeHtml(fmt(r.started_at))}</td>
          <td>${escapeHtml(r.engine)}</td>
          <td>${escapeHtml(String(r.found))}</td>
          <td>${escapeHtml(String(r.new_found))}</td>
          <td>${escapeHtml(String(r.ports_spec || ""))}</td>
          <td>${escapeHtml(r.notes || "—")}</td>
        </tr>
      `)
      .join("");

    const last = STATE.runs[0];
    if (last) {
      $("statLastScan").textContent = fmt(last.started_at);
      $("statLastScanMeta").textContent =
        `${last.engine} • found ${last.found} • new ${last.new_found}`;
    } else {
      $("statLastScan").textContent = "—";
      $("statLastScanMeta").textContent = "—";
    }
  }

  // ---------- data loading ----------
  async function refreshAll() {
    const st = await api("/api/stats");
    if (st) {
      $("statFindings").textContent = st.total_findings ?? "—";
      $("statHosts").textContent = st.unique_hosts ?? "—";
    }

    const res = await api("/api/results");
    STATE.results = Array.isArray(res) ? res : [];

    const runs = await api("/api/scans");
    STATE.runs = Array.isArray(runs) ? runs : [];

    rebuildServiceOptions();
    STATE.page = 1;
    renderResults();
    renderRuns();
  }

  // ---------- modal / progress ----------
  function appendLog(line) {
    const el = $("scanLog");
    if (!el) return;
    el.textContent += line + "\n";
    el.scrollTop = el.scrollHeight;
  }

  function setProgress(percent, message) {
    const bar = $("scanBar");
    const msg = $("scanMsg");
    if (bar) bar.style.width = `${Math.max(0, Math.min(100, percent))}%`;
    if (msg) msg.textContent = message || "";
  }

  function openScanModal() {
    const m = $("scanModal");
    if (!m) return;
    m.classList.remove("hidden");
    m.style.display = "flex"; // оставляем твой “жёсткий” вариант
  }

  function closeScanModal() {
    const m = $("scanModal");
    if (!m) return;

    m.style.display = "none";
    m.classList.add("hidden");

    scanRunning = false;

    if ($("scanLog")) $("scanLog").textContent = "";
    setProgress(0, "");

    if (scanES) {
      scanES.close();
      scanES = null;
    }

    if (scanWatchdog) {
      clearTimeout(scanWatchdog);
      scanWatchdog = null;
    }
  }

  function kickWatchdog() {
    if (scanWatchdog) clearTimeout(scanWatchdog);
    // если 20 секунд нет ни одного события — считаем что повисло
    scanWatchdog = setTimeout(() => {
      if (!scanRunning) return;
      toast("No progress events from server (scan stuck?)", "error", 4000);
      appendLog("[watchdog] no progress for 20s, closing");
      closeScanModal();
    }, 20000);
  }

  function startProgressStream() {
    if (scanES) {
      scanES.close();
      scanES = null;
    }

    scanES = new EventSource("/api/scan/stream");

    kickWatchdog();

    scanES.onmessage = (e) => {
      let p;
      try {
        p = JSON.parse(e.data);
      } catch {
        return;
      }

      if (!scanRunning) return;

      kickWatchdog();

      const percent = Number(p.percent ?? 0);
      const message = String(p.message ?? "");

      setProgress(percent, message);
      appendLog(`[${new Date().toLocaleTimeString()}] ${percent}% ${message}`);

      const msgLower = message.toLowerCase();
      const done =
        percent >= 100 ||
        msgLower.includes("scan finished") ||
        msgLower.includes("finished") ||
        msgLower.includes("done") ||
        msgLower.includes("cancel") ||
        msgLower.includes("failed") ||
        msgLower.includes("error");

      if (done) {
        scanRunning = false;

        if (scanES) {
          scanES.close();
          scanES = null;
        }

        if (scanWatchdog) {
          clearTimeout(scanWatchdog);
          scanWatchdog = null;
        }

        setTimeout(async () => {
          closeScanModal();
          await refreshAll().catch(() => {});
        }, 400);
      }
    };

    scanES.onerror = () => {
      if (scanRunning) {
        toast("Progress stream disconnected", "error");
        appendLog("[stream] disconnected");
        closeScanModal();
      }
    };
  }

  async function cancelScan() {
    try {
      await fetch("/api/scan/cancel", { method: "POST" });
      appendLog("[action] cancel requested");
      toast("Cancel requested", "info");
      closeScanModal();
    } catch (e) {
      toast(`Cancel failed: ${e.message}`, "error");
    }
  }

  // ---------- unified scan starter ----------
  async function startAsyncScan(fetchFn) {
    if (scanRunning) return;

    scanRunning = true;
    openScanModal();
    setProgress(3, "Starting...");
    appendLog(`[${new Date().toLocaleTimeString()}] 3% Starting...`);

    startProgressStream();

    try {
      const res = await fetchFn();
      if (!res.ok) {
        const txt = await res.text().catch(() => "");
        throw new Error(txt || "scan start failed");
      }
      toast("Scan started", "ok");
    } catch (e) {
      scanRunning = false;
      closeScanModal();
      toast(`Scan start failed: ${e.message}`, "error");
    }
  }

  // ---------- actions ----------
  async function runFullScan() {
    // ВАЖНО: /api/scan у тебя сейчас может быть синхронным или асинхронным.
    // Для WebUI мы работаем как с ASYNC: запускаем SSE и сразу стартуем.
    const btn = $("btnScan");
    const prevText = btn?.textContent || "Run scan";
    if (btn) { btn.disabled = true; btn.textContent = "Starting..."; }

    await startAsyncScan(() =>
      fetch("/api/scan", { method: "POST" })
    );

    if (btn) { btn.disabled = false; btn.textContent = prevText; }
  }

  async function runFastScan() {
    const target = ($("scanTarget")?.value || "").trim();
    const ports = ($("scanPorts")?.value || "").trim() || "auto";

    if (!target) {
      toast("Target is required", "error");
      return;
    }

    await startAsyncScan(() =>
      fetch("/api/scan/custom", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targets: [target], ports }),
      })
    );
  }

  // ---------- wiring ----------
  function bindUI() {
    $("btnRefresh")?.addEventListener("click", () =>
      refreshAll().catch((e) => toast(e.message, "error"))
    );

    $("btnScan")?.addEventListener("click", () => runFullScan());
    $("btnFastScan")?.addEventListener("click", () => runFastScan());

    ["q", "svc", "sort"].forEach((id) => {
      $(id)?.addEventListener("input", () => {
        STATE.page = 1;
        renderResults();
      });
      $(id)?.addEventListener("change", () => {
        STATE.page = 1;
        renderResults();
      });
    });

    $("prev")?.addEventListener("click", () => {
      if (STATE.page > 1) {
        STATE.page--;
        renderResults();
      }
    });

    $("next")?.addEventListener("click", () => {
      STATE.page++;
      renderResults();
    });
  }

  // expose for inline onclick in index.html
  window.closeScanModal = closeScanModal;
  window.cancelScan = cancelScan;
  window.refresh = () => refreshAll().catch((e) => toast(e.message, "error"));

  // ---------- init ----------
  document.addEventListener("DOMContentLoaded", async () => {
    closeScanModal();
    bindUI();

    try {
      await refreshAll();
    } catch (e) {
      toast(e.message, "error");
    }
  });
})();
