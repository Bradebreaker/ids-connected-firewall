/**
 * static/js/traffic.js — Live Traffic Analyzer Client Logic
 * Provides real-time streaming, Wireshark-inspired 7-layer packet inspection,
 * display filtering, capture export, rolling throughput statistics, and
 * backend traffic generator integration.
 */

document.addEventListener('DOMContentLoaded', () => {
    if (!IDS.requireAuth()) return;

    // ── State ────────────────────────────────────────────────────────
    const MAX_PACKETS = 1000;
    const packetBuffer = [];
    let isPaused = false;
    let autoScroll = true;
    let activeQuickFilter = 'all';
    let textFilter = '';
    let selectedPacket = null;

    // Rolling rate calculation window (last 2000ms)
    const rollingEvents = []; // { time: number, bytes: number }

    // ── DOM References ───────────────────────────────────────────────
    const tableBody = document.getElementById('packetTableBody');
    const tableContainer = document.getElementById('packetTableContainer');
    const filterInput = document.getElementById('trafficFilterInput');
    const btnPause = document.getElementById('btnPauseResume');
    const btnClear = document.getElementById('btnClearTable');
    const btnAutoScroll = document.getElementById('btnAutoScroll');
    const btnExport = document.getElementById('btnExportCapture');
    const quickPills = document.querySelectorAll('.quick-pill');

    const ratePacketsEl = document.getElementById('ratePackets');
    const rateBytesEl = document.getElementById('rateBytes');
    const totalPacketsEl = document.getElementById('totalPacketsCount');
    const threatPacketsEl = document.getElementById('threatPacketsCount');
    const wsDot = document.getElementById('wsDot');
    const wsStatus = document.getElementById('wsStatus');

    // Quick Generator toolbar DOM
    const btnGenNormal = document.getElementById('btnGenNormal');
    const btnGenPortScan = document.getElementById('btnGenPortScan');
    const btnGenBurst = document.getElementById('btnGenBurst');
    const btnResetTraffic = document.getElementById('btnResetTraffic');
    const genStatusBadge = document.getElementById('genStatusBadge');
    const genStatusDetail = document.getElementById('genStatusDetail');

    // Reset Modal DOM
    const resetModal = document.getElementById('resetModalBackdrop');
    const btnCancelReset = document.getElementById('btnCancelReset');
    const btnConfirmReset = document.getElementById('btnConfirmReset');

    // Inspector DOM
    const drawer = document.getElementById('packetDetailDrawer');
    const detailHeader = document.getElementById('detailHeader');
    const detailThreatBadge = document.getElementById('detailThreatBadge');
    const inspectorTree = document.getElementById('inspectorTreeContent');
    const payloadDecodedView = document.getElementById('payloadDecodedView');
    const hexDumpView = document.getElementById('hexDumpView');
    const securityAnalysisContent = document.getElementById('securityAnalysisContent');
    const tabs = document.querySelectorAll('.inspector-tab');

    // ── Helper: Safe HTML Escaping ───────────────────────────────────
    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // ── Helper: Packet Normalization ─────────────────────────────────
    function normalizePacket(pkt) {
        const proto = (pkt.protocol || 'TCP').toUpperCase();
        const srcIp = pkt.source_ip || pkt.src || '—';
        const dstIp = pkt.destination_ip || pkt.dest_ip || pkt.dst || '192.168.1.10';
        const sport = pkt.source_port !== undefined && pkt.source_port !== null ? pkt.source_port : (pkt.sport || '—');
        const dport = pkt.destination_port !== undefined && pkt.destination_port !== null ? pkt.destination_port : (pkt.dport || '—');
        const length = pkt.packet_length || pkt.packet_size || 60;
        const flags = pkt.tcp_flags || (proto === 'TCP' ? 'PA' : 'N/A');

        // Threat level must be NORMAL, SUSPICIOUS, or MALICIOUS
        let threatLvl = pkt.threat_level ? pkt.threat_level.toUpperCase() : 'NORMAL';
        if (threatLvl !== 'MALICIOUS' && threatLvl !== 'SUSPICIOUS') {
            if (pkt.threat_type) {
                threatLvl = 'MALICIOUS';
            } else {
                threatLvl = 'NORMAL';
            }
        }

        // Ethernet layer
        const ethSrc = pkt.eth_src || (pkt.ethernet && pkt.ethernet.src) || '52:54:00:12:34:56';
        const ethDst = pkt.eth_dst || (pkt.ethernet && pkt.ethernet.dst) || '00:0c:29:4f:8e:35';
        const ethType = pkt.eth_type || (pkt.ethernet && pkt.ethernet.type) || 'IPv4 (0x0800)';

        // IP layer
        const ipVer = pkt.ip_version || (pkt.ip && pkt.ip.version) || 4;
        const ipHl = pkt.ip_header_length || (pkt.ip && pkt.ip.ihl) || 20;
        const ipTtl = pkt.ip_ttl !== undefined ? pkt.ip_ttl : ((pkt.ip && pkt.ip.ttl) || 64);

        // Transport layer
        const tcpSeq = pkt.tcp_seq !== undefined ? pkt.tcp_seq : ((pkt.transport && pkt.transport.seq) || (proto === 'TCP' ? 1000 : null));
        const tcpAck = pkt.tcp_ack !== undefined ? pkt.tcp_ack : ((pkt.transport && pkt.transport.ack) || (proto === 'TCP' ? 0 : null));
        const tcpWin = pkt.tcp_window !== undefined ? pkt.tcp_window : ((pkt.transport && pkt.transport.window) || (proto === 'TCP' ? 65535 : null));

        return {
            packet_number: pkt.packet_number || (packetBuffer.length + 1),
            timestamp: typeof pkt.timestamp === 'number' ? pkt.timestamp : (Date.now() / 1000),
            source_ip: srcIp,
            destination_ip: dstIp,
            dest_ip: dstIp,
            source_port: sport,
            destination_port: dport,
            dest_port: dport,
            protocol: proto,
            packet_length: length,
            packet_size: length,
            tcp_flags: flags,
            payload: pkt.payload || '',
            raw_summary: pkt.raw_summary || `${proto} ${srcIp}:${sport} → ${dstIp}:${dport} [${flags}]`,
            info: pkt.info || pkt.raw_summary || `${proto} packet ${srcIp} → ${dstIp}`,
            threat_level: threatLvl,
            threat_type: pkt.threat_type || null,
            threat_detail: pkt.threat_detail || null,
            alert_id: pkt.alert_id || null,
            eth_src: ethSrc,
            eth_dst: ethDst,
            eth_type: ethType,
            ethernet: { src: ethSrc, dst: ethDst, type: ethType },
            ip_version: ipVer,
            ip_header_length: ipHl,
            ip_ttl: ipTtl,
            ip: { version: ipVer, ihl: ipHl, ttl: ipTtl, src: srcIp, dst: dstIp, proto: proto },
            tcp_seq: tcpSeq,
            tcp_ack: tcpAck,
            tcp_window: tcpWin,
            transport: { sport: sport, dport: dport, seq: tcpSeq, ack: tcpAck, flags: flags, window: tcpWin },
            hex_dump: pkt.hex_dump || '0000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|'
        };
    }

    // ── Metric Counters Update ───────────────────────────────────────
    function updateMetricsSummary() {
        totalPacketsEl.textContent = packetBuffer.length;
        
        // Threats = SUSPICIOUS + MALICIOUS
        const threatCount = packetBuffer.reduce((acc, p) => {
            return (p.threat_level === 'SUSPICIOUS' || p.threat_level === 'MALICIOUS') ? acc + 1 : acc;
        }, 0);

        threatPacketsEl.textContent = threatCount;
    }

    // ── Rolling Rate and Throughput Ticker ───────────────────────────
    setInterval(() => {
        const now = Date.now();
        // Discard events older than 2000ms
        while (rollingEvents.length > 0 && now - rollingEvents[0].time > 2000) {
            rollingEvents.shift();
        }

        if (rollingEvents.length === 0) {
            ratePacketsEl.textContent = '0';
            rateBytesEl.textContent = '0';
            return;
        }

        // Rate = count over 2 seconds
        const rate = (rollingEvents.length / 2.0).toFixed(0);
        ratePacketsEl.textContent = rate;

        // Throughput = sum of bytes over 2 seconds
        const totalBytes = rollingEvents.reduce((sum, ev) => sum + ev.bytes, 0);
        const bytesPerSec = totalBytes / 2.0;

        if (bytesPerSec >= 1024 * 1024) {
            rateBytesEl.textContent = `${(bytesPerSec / (1024 * 1024)).toFixed(1)} M`;
        } else if (bytesPerSec >= 1024) {
            rateBytesEl.textContent = `${(bytesPerSec / 1024).toFixed(1)} K`;
        } else {
            rateBytesEl.textContent = `${bytesPerSec.toFixed(0)}`;
        }
    }, 500);

    // ── WebSocket Lifecycle ──────────────────────────────────────────
    const wsClient = IDS.createWebSocket(
        (msg) => {
            if (msg.type === 'traffic' && msg.data) {
                handleIncomingPacket(msg.data, true);
            } else if (msg.type === 'new_alert' && msg.data) {
                handleAlertCorrelation(msg.data);
            }
        },
        (status) => {
            if (!wsDot || !wsStatus) return;
            wsStatus.textContent = status;
            if (status === 'CONNECTED') {
                wsDot.style.background = '#10b981';
                wsStatus.style.color = '#10b981';
            } else if (status === 'RECONNECTING' || status === 'CONNECTING') {
                wsDot.style.background = '#f59e0b';
                wsStatus.style.color = '#f59e0b';
            } else {
                wsDot.style.background = '#ef4444';
                wsStatus.style.color = '#ef4444';
            }
        }
    );

    // ── Handle Alert Correlation ────────────────────────────────────
    function handleAlertCorrelation(alertData) {
        if (!alertData) return;
        const alertId = alertData.id;
        const srcIp = alertData.source_ip;
        const alertType = alertData.alert_type;

        // Correlate with recent matching packets from that source IP
        let correlated = false;
        for (let i = packetBuffer.length - 1; i >= 0; i--) {
            const p = packetBuffer[i];
            if (p.source_ip === srcIp) {
                p.alert_id = alertId;
                p.threat_level = 'MALICIOUS';
                p.threat_type = alertType;
                p.threat_detail = alertData.description || p.threat_detail;
                correlated = true;
                break; // Correlate triggering packet
            }
        }

        updateMetricsSummary();

        // If drawer open and inspecting correlated packet, update view
        if (selectedPacket && selectedPacket.source_ip === srcIp) {
            selectedPacket.alert_id = alertId;
            selectedPacket.threat_level = 'MALICIOUS';
            selectedPacket.threat_type = alertType;
            renderInspectorSecurityTab(selectedPacket);
        }
    }

    // ── Process Incoming Live Packet ─────────────────────────────────
    function handleIncomingPacket(rawPkt, isLive = true) {
        const normalized = normalizePacket(rawPkt);

        if (isLive) {
            rollingEvents.push({ time: Date.now(), bytes: normalized.packet_length });
        }

        packetBuffer.push(normalized);
        if (packetBuffer.length > MAX_PACKETS) {
            packetBuffer.shift();
        }

        updateMetricsSummary();

        if (isPaused) return;

        const evalResult = evaluateFilter(normalized);
        if (!evalResult.isError && evalResult.match) {
            renderPacketRow(normalized);
        }
    }

    // ── Filter Evaluation Engine ─────────────────────────────────────
    function evaluateFilter(pkt) {
        // 1. Quick pill filtering
        if (activeQuickFilter !== 'all') {
            if (activeQuickFilter === 'tcp' && pkt.protocol !== 'TCP') return { match: false, isError: false };
            if (activeQuickFilter === 'udp' && pkt.protocol !== 'UDP') return { match: false, isError: false };
            if (activeQuickFilter === 'icmp' && pkt.protocol !== 'ICMP') return { match: false, isError: false };
            if (activeQuickFilter === 'http') {
                const isHttpPort = (pkt.dest_port === 80 || pkt.source_port === 80 || pkt.dest_port === 8080 || pkt.source_port === 8080);
                const hasHttpInfo = pkt.info && pkt.info.toUpperCase().includes('HTTP');
                if (!isHttpPort && !hasHttpInfo) return { match: false, isError: false };
            }
            if (activeQuickFilter === 'dns') {
                const isDnsPort = (pkt.dest_port === 53 || pkt.source_port === 53);
                const hasDnsInfo = pkt.info && pkt.info.toUpperCase().includes('DNS');
                if (!isDnsPort && !hasDnsInfo) return { match: false, isError: false };
            }
            if (activeQuickFilter === 'suspicious' && pkt.threat_level !== 'SUSPICIOUS') return { match: false, isError: false };
            if (activeQuickFilter === 'malicious' && pkt.threat_level !== 'MALICIOUS') return { match: false, isError: false };
        }

        // 2. Custom text expression
        if (!textFilter || !textFilter.trim()) {
            return { match: true, isError: false };
        }

        const q = textFilter.trim().toLowerCase();

        // Wireshark comparison expressions (with '==')
        if (q.includes('==')) {
            const parts = q.split('==');
            if (parts.length !== 2) {
                return { match: false, isError: true, errorMsg: 'Invalid syntax for == comparison' };
            }
            const key = parts[0].trim();
            const val = parts[1].trim();

            if (!val) {
                return { match: false, isError: true, errorMsg: `Missing comparison value after '==' for ${key}` };
            }

            if (key === 'tcp.port' || key === 'udp.port' || key === 'port') {
                const portNum = parseInt(val, 10);
                if (isNaN(portNum)) return { match: false, isError: true, errorMsg: 'Port must be a valid integer' };
                const matched = (Number(pkt.source_port) === portNum || Number(pkt.dest_port) === portNum);
                return { match: matched, isError: false };
            }
            if (key === 'ip.addr' || key === 'ip') {
                const matched = (pkt.source_ip.toLowerCase().includes(val) || pkt.dest_ip.toLowerCase().includes(val));
                return { match: matched, isError: false };
            }
            if (key === 'source' || key === 'src' || key === 'ip.src') {
                return { match: pkt.source_ip.toLowerCase().includes(val), isError: false };
            }
            if (key === 'destination' || key === 'dst' || key === 'ip.dst') {
                return { match: pkt.dest_ip.toLowerCase().includes(val), isError: false };
            }
            if (key === 'eth.src' || key === 'eth.dst') {
                const matched = (pkt.eth_src.toLowerCase().includes(val) || pkt.eth_dst.toLowerCase().includes(val));
                return { match: matched, isError: false };
            }
            if (key === 'protocol' || key === 'proto') {
                return { match: pkt.protocol.toLowerCase() === val, isError: false };
            }
            if (key === 'threat' || key === 'threat.level') {
                return { match: pkt.threat_level.toLowerCase() === val, isError: false };
            }

            // Unsupported key with ==
            return { match: false, isError: true, errorMsg: `Unsupported filter field '${key}'` };
        }

        // Direct protocol/threat keywords
        if (q === 'tcp') return { match: pkt.protocol === 'TCP', isError: false };
        if (q === 'udp') return { match: pkt.protocol === 'UDP', isError: false };
        if (q === 'icmp') return { match: pkt.protocol === 'ICMP', isError: false };
        if (q === 'http') return { match: (pkt.dest_port === 80 || pkt.source_port === 80 || (pkt.info && pkt.info.includes('HTTP'))), isError: false };
        if (q === 'dns') return { match: (pkt.dest_port === 53 || pkt.source_port === 53), isError: false };
        if (q === 'suspicious') return { match: pkt.threat_level === 'SUSPICIOUS', isError: false };
        if (q === 'malicious') return { match: pkt.threat_level === 'MALICIOUS', isError: false };
        if (q === 'normal') return { match: pkt.threat_level === 'NORMAL', isError: false };

        // General substring search across all core attributes
        const matched = (
            pkt.source_ip.toLowerCase().includes(q) ||
            pkt.dest_ip.toLowerCase().includes(q) ||
            String(pkt.source_port).includes(q) ||
            String(pkt.dest_port).includes(q) ||
            pkt.protocol.toLowerCase().includes(q) ||
            pkt.info.toLowerCase().includes(q) ||
            pkt.threat_level.toLowerCase().includes(q) ||
            (pkt.threat_type && pkt.threat_type.toLowerCase().includes(q)) ||
            (pkt.payload && pkt.payload.toLowerCase().includes(q))
        );
        return { match: matched, isError: false };
    }

    // ── Table Rendering ──────────────────────────────────────────────
    function removeEmptyPlaceholders() {
        const placeholders = tableBody.querySelectorAll('.empty-placeholder-row, #emptyRow');
        placeholders.forEach(el => el.remove());
    }

    function renderPacketRow(pkt) {
        removeEmptyPlaceholders();

        const tr = document.createElement('tr');
        tr.dataset.pktNo = pkt.packet_number;

        let threatClass = 'threat-normal';
        let threatIcon = '●';
        if (pkt.threat_level === 'SUSPICIOUS') {
            threatClass = 'threat-suspicious';
            threatIcon = '▲';
        } else if (pkt.threat_level === 'MALICIOUS') {
            threatClass = 'threat-malicious';
            threatIcon = '✖';
        }

        // Format arrival time: HH:MM:SS.mmm
        let timeStr = '—';
        try {
            const dateObj = new Date(pkt.timestamp * 1000);
            timeStr = dateObj.toISOString().substring(11, 23);
        } catch (e) {
            timeStr = String(pkt.timestamp);
        }

        const alertBadge = pkt.alert_id 
            ? `<span style="font-size:0.7rem; margin-left:4px; padding:1px 5px; border-radius:4px; background:rgba(239,68,68,0.25); color:#fca5a5;" title="Associated Alert #${pkt.alert_id}">#${pkt.alert_id}</span>`
            : '';

        tr.innerHTML = `
            <td style="color:#64748b;">${pkt.packet_number}</td>
            <td style="color:#94a3b8; font-family:'JetBrains Mono',monospace;">${timeStr}</td>
            <td style="color:#38bdf8; font-weight:500;">${escapeHtml(pkt.source_ip)}</td>
            <td style="color:#cbd5e1;">${escapeHtml(pkt.dest_ip)}</td>
            <td><span class="badge" style="background:rgba(255,255,255,0.06);">${pkt.protocol}</span></td>
            <td>${pkt.source_port}</td>
            <td>${pkt.dest_port}</td>
            <td>${pkt.packet_length}</td>
            <td style="color:#f59e0b;">${escapeHtml(pkt.tcp_flags || '—')}</td>
            <td style="color:#e2e8f0; max-width:280px; overflow:hidden; text-overflow:ellipsis;" title="${escapeHtml(pkt.info)}">${escapeHtml(pkt.info)}</td>
            <td class="${threatClass}">${threatIcon} ${pkt.threat_level}${alertBadge}</td>
        `;

        tr.addEventListener('click', () => {
            selectPacket(pkt, tr);
        });

        tableBody.appendChild(tr);

        // Keep DOM table size bounded
        while (tableBody.children.length > MAX_PACKETS) {
            tableBody.removeChild(tableBody.firstChild);
        }

        if (autoScroll) {
            tableContainer.scrollTop = tableContainer.scrollHeight;
        }
    }

    // ── Filter Application & Empty State Handler ─────────────────────
    function applyCurrentFilters() {
        tableBody.innerHTML = '';

        // Validate custom syntax first
        if (textFilter && textFilter.trim()) {
            // Test syntax with a dummy packet
            const testPkt = packetBuffer[0] || normalizePacket({ source_ip: '127.0.0.1' });
            const testResult = evaluateFilter(testPkt);
            if (testResult.isError) {
                tableBody.innerHTML = `
                    <tr class="empty-placeholder-row">
                        <td colspan="11" style="text-align:center; padding:40px 20px; color:#f59e0b;">
                            <div style="font-size:1.6rem; margin-bottom:8px;">⚠️</div>
                            <div style="font-size:0.95rem; font-weight:600; color:#fbbf24;">Unsupported filter expression: "${escapeHtml(textFilter)}"</div>
                            <div style="font-size:0.8rem; color:#94a3b8; margin-top:6px;">
                                Supported syntax: <code>tcp</code>, <code>udp</code>, <code>icmp</code>, <code>suspicious</code>, <code>malicious</code>, <code>tcp.port == 80</code>, <code>ip.addr == 192.168.1.1</code>, <code>source == 203.0.113.50</code>, <code>destination == ...</code>
                            </div>
                        </td>
                    </tr>
                `;
                return;
            }
        }

        const matching = packetBuffer.filter(p => evaluateFilter(p).match);

        if (matching.length === 0) {
            if (packetBuffer.length === 0) {
                tableBody.innerHTML = `
                    <tr class="empty-placeholder-row">
                        <td colspan="11" style="text-align:center; padding:60px 20px; color:#64748b;">
                            <div style="font-size:1.8rem; margin-bottom:8px;">📡</div>
                            <div style="font-size:1rem; font-weight:600; color:#94a3b8;">Listening for live network traffic...</div>
                            <div style="font-size:0.85rem; margin-top:4px;">No packets captured yet. Click <strong>Generate Normal Traffic</strong> or <strong>Port Scan</strong> above to inject traffic.</div>
                        </td>
                    </tr>
                `;
            } else {
                tableBody.innerHTML = `
                    <tr class="empty-placeholder-row">
                        <td colspan="11" style="text-align:center; padding:40px 20px; color:#64748b;">
                            <div style="font-size:1.4rem; margin-bottom:6px;">🔍</div>
                            <div style="font-size:0.95rem; font-weight:600; color:#94a3b8;">No packets match the current filter.</div>
                            <div style="font-size:0.8rem; color:#64748b; margin-top:4px;">Showing 0 of ${packetBuffer.length} captured packets. Click 'ALL' or clear the search filter to show all.</div>
                        </td>
                    </tr>
                `;
            }
            return;
        }

        matching.forEach(renderPacketRow);
    }

    // ── 7-Layer Packet Detail Inspector ──────────────────────────────
    function selectPacket(pkt, trElement) {
        selectedPacket = pkt;

        document.querySelectorAll('#packetTableBody tr').forEach(r => r.classList.remove('selected'));
        if (trElement) trElement.classList.add('selected');

        drawer.style.display = 'flex';
        detailHeader.textContent = `Packet #${pkt.packet_number} Deep Inspection — [${pkt.protocol}] ${pkt.source_ip}:${pkt.source_port} → ${pkt.dest_ip}:${pkt.dest_port}`;

        detailThreatBadge.className = `badge ${pkt.threat_level === 'MALICIOUS' ? 'badge-high' : (pkt.threat_level === 'SUSPICIOUS' ? 'badge-medium' : 'badge-low')}`;
        detailThreatBadge.textContent = pkt.threat_level;

        // Layer 1-4: Tree view
        const timeIso = new Date(pkt.timestamp * 1000).toISOString();
        inspectorTree.innerHTML = `
            <div class="tree-node">
                <strong>▶ FRAME:</strong> Arrival Time: <code>${timeIso}</code>, Epoch: <code>${pkt.timestamp}</code>, Wire Length: <code>${pkt.packet_length} bytes</code>, Packet #: <code>${pkt.packet_number}</code>
            </div>
            <div class="tree-node">
                <strong>▶ ETHERNET II:</strong> Src MAC: <code>${escapeHtml(pkt.eth_src)}</code>, Dst MAC: <code>${escapeHtml(pkt.eth_dst)}</code>, Type: <code>${escapeHtml(pkt.eth_type)}</code>
            </div>
            <div class="tree-node">
                <strong>▶ INTERNET PROTOCOL v${pkt.ip_version}:</strong> Src IP: <code>${escapeHtml(pkt.source_ip)}</code>, Dst IP: <code>${escapeHtml(pkt.dest_ip)}</code>, IHL: <code>${pkt.ip_header_length} bytes</code>, TTL: <code>${pkt.ip_ttl}</code>, Protocol: <code>${pkt.protocol}</code>
            </div>
            <div class="tree-node">
                <strong>▶ TRANSPORT (${pkt.protocol}):</strong> Src Port: <code>${pkt.source_port}</code>, Dst Port: <code>${pkt.dest_port}</code>, Seq: <code>${pkt.tcp_seq !== null ? pkt.tcp_seq : 'N/A'}</code>, Ack: <code>${pkt.tcp_ack !== null ? pkt.tcp_ack : 'N/A'}</code>, Flags: <code>[${escapeHtml(pkt.tcp_flags || 'NONE')}]</code>, Window: <code>${pkt.tcp_window !== null ? pkt.tcp_window : 'N/A'}</code>
            </div>
            <div class="tree-node">
                <strong>▶ APPLICATION LAYER:</strong> Length: <code>${pkt.payload ? pkt.payload.length : 0} bytes</code>
            </div>
        `;

        // Layer 5: Decoded Payload
        payloadDecodedView.textContent = pkt.payload ? pkt.payload : '(No application layer text payload detected in frame)';

        // Layer 6: Hex Dump View
        hexDumpView.textContent = pkt.hex_dump || '0000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|';

        // Layer 7: Security Analysis
        renderInspectorSecurityTab(pkt);
    }

    function renderInspectorSecurityTab(pkt) {
        let threatColor = '#10b981';
        if (pkt.threat_level === 'SUSPICIOUS') threatColor = '#f59e0b';
        if (pkt.threat_level === 'MALICIOUS') threatColor = '#ef4444';

        // Alert Correlation Section
        let alertSection = '';
        if (pkt.alert_id) {
            alertSection = `
                <div style="margin-top:12px; padding:10px 14px; background:rgba(239,68,68,0.12); border:1px solid rgba(239,68,68,0.35); border-radius:6px; display:flex; align-items:center; justify-content:space-between;">
                    <div>
                        <span style="font-weight:700; color:#fca5a5;">🛡️ Correlated Alert #<strong>${pkt.alert_id}</strong></span>
                        <div style="font-size:0.78rem; color:#f8fafc; margin-top:2px;">Threshold breached. Correlated security event logged in IDS Alert database.</div>
                    </div>
                    <a href="/alerts.html?id=${pkt.alert_id}" class="btn btn-primary" style="padding:4px 10px; font-size:0.78rem; text-decoration:none;">
                        View Alert Details →
                    </a>
                </div>
            `;
        } else {
            alertSection = `
                <div style="margin-top:10px; font-size:0.8rem; color:#94a3b8;">
                    <strong>Associated Alert:</strong> No associated alert (Threshold not breached or nominal baseline packet)
                </div>
            `;
        }

        // Threat Intelligence Knowledge Link
        let intelLink = '';
        if (pkt.threat_type) {
            const slug = IDS.getAttackSlug(pkt.threat_type);
            intelLink = `
                <div style="margin-top:10px;">
                    <a href="/attacks/${slug}.html" class="btn btn-secondary" style="font-size:0.78rem; padding:4px 10px; text-decoration:none;">
                        ⚔️ View ${escapeHtml(pkt.threat_type)} Threat Intelligence →
                    </a>
                </div>
            `;
        }

        securityAnalysisContent.innerHTML = `
            <div><strong>Classification:</strong> <span style="color:${threatColor}; font-weight:700;">● ${pkt.threat_level}</span></div>
            <div style="margin-top:4px;"><strong>Threat Vector:</strong> ${escapeHtml(pkt.threat_type || 'None detected (Standard traffic)')}</div>
            <div style="margin-top:4px;"><strong>Defensive Assessment:</strong> ${escapeHtml(pkt.threat_detail || 'Packet matches known nominal traffic baseline. No signature or volumetric thresholds breached.')}</div>
            ${alertSection}
            ${intelLink}
        `;
    }

    // ── Status Area State Machine ───────────────────────────────────
    function setGenStatus(state, detail = '') {
        if (!genStatusBadge) return;
        genStatusBadge.textContent = state;

        if (state === 'GENERATING') {
            genStatusBadge.className = 'badge';
            genStatusBadge.style.background = 'rgba(56,189,248,0.2)';
            genStatusBadge.style.color = '#38bdf8';
            genStatusBadge.style.border = '1px solid rgba(56,189,248,0.4)';
        } else if (state === 'SUCCESS') {
            genStatusBadge.className = 'badge';
            genStatusBadge.style.background = 'rgba(16,185,129,0.2)';
            genStatusBadge.style.color = '#34d399';
            genStatusBadge.style.border = '1px solid rgba(16,185,129,0.4)';
        } else if (state === 'PARTIAL') {
            genStatusBadge.className = 'badge';
            genStatusBadge.style.background = 'rgba(245,158,11,0.2)';
            genStatusBadge.style.color = '#fbbf24';
            genStatusBadge.style.border = '1px solid rgba(245,158,11,0.4)';
        } else if (state === 'FAILED') {
            genStatusBadge.className = 'badge';
            genStatusBadge.style.background = 'rgba(239,68,68,0.2)';
            genStatusBadge.style.color = '#f87171';
            genStatusBadge.style.border = '1px solid rgba(239,68,68,0.4)';
        } else {
            // READY / IDLE
            genStatusBadge.className = 'badge';
            genStatusBadge.style.background = 'rgba(255,255,255,0.06)';
            genStatusBadge.style.color = '#94a3b8';
            genStatusBadge.style.border = '1px solid rgba(255,255,255,0.1)';
        }

        if (genStatusDetail) {
            genStatusDetail.textContent = detail;
        }
    }

    function setGeneratorButtonsDisabled(disabled) {
        if (btnGenNormal) btnGenNormal.disabled = disabled;
        if (btnGenPortScan) btnGenPortScan.disabled = disabled;
        if (btnGenBurst) btnGenBurst.disabled = disabled;
        if (btnResetTraffic) btnResetTraffic.disabled = disabled;
    }

    // ── Page Hydration (Fetch Recent Buffer on Page Load) ────────────
    async function hydrateRecentTraffic() {
        try {
            const res = await IDS.apiFetch('/api/traffic/recent?limit=300');
            if (!res || !res.ok) {
                console.warn('[TRAFFIC] Recent buffer endpoint returned HTTP', res ? res.status : 'ERR');
                return;
            }
            const data = await res.json();
            if (data && Array.isArray(data.packets) && data.packets.length > 0) {
                data.packets.forEach(p => {
                    const normalized = normalizePacket(p);
                    packetBuffer.push(normalized);
                });
                updateMetricsSummary();
                applyCurrentFilters();
            }
        } catch (e) {
            console.warn('[TRAFFIC] Could not hydrate recent traffic:', e);
        }
    }

    // ── Quick Traffic Generator Toolbar Handlers ─────────────────────
    async function triggerTrafficGeneration(mode, attackType = null) {
        const modeLabel = mode === 'specific' ? (attackType === 'port_scan' ? 'Port Scan' : attackType) : (mode === 'normal' ? 'Normal Traffic' : 'Attack Burst');
        
        // 1. Enter GENERATING state
        setGenStatus('GENERATING', `Injecting ${modeLabel} packets into pipeline...`);
        setGeneratorButtonsDisabled(true);

        try {
            const payload = { mode };
            if (attackType) payload.attack_type = attackType;

            const res = await IDS.apiFetch('/api/generate-traffic', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            // Handle HTTP-level failures
            if (!res || !res.ok) {
                let errDetail = `HTTP ${res ? res.status : 'Network error'}`;
                try {
                    const errBody = await res.json();
                    if (errBody && errBody.detail) errDetail = errBody.detail;
                } catch (_) {}
                throw new Error(errDetail);
            }

            // Parse response JSON
            const data = await res.json();

            if (data && (data.status === 'ok' || data.packets_generated > 0)) {
                const count = data.packets_generated || 0;
                const typeName = data.attack_type ? IDS.formatAttackName(data.attack_type) : (data.mode === 'normal' ? 'Normal Traffic' : 'Attack Vector');

                if (data.status === 'partial' || data.partial_success) {
                    setGenStatus('PARTIAL', `Generated ${count} pkts | ${data.detail || 'Partial execution'}`);
                } else {
                    setGenStatus('SUCCESS', `✓ Generated ${count} packets (${typeName})`);
                }

                // Smooth transition back to READY after 4s
                setTimeout(() => {
                    if (genStatusBadge && (genStatusBadge.textContent.includes('SUCCESS') || genStatusBadge.textContent.includes('PARTIAL'))) {
                        setGenStatus('READY', `Idle | Last: ${count} pkts (${typeName})`);
                    }
                }, 4000);
            } else {
                setGenStatus('FAILED', `API returned incomplete status: ${JSON.stringify(data)}`);
            }
        } catch (e) {
            console.error('[TRAFFIC] Generator error:', e);
            setGenStatus('FAILED', `⚠ Traffic generation failed: ${e.message}`);
        } finally {
            setGeneratorButtonsDisabled(false);
        }
    }

    if (btnGenNormal) {
        btnGenNormal.addEventListener('click', () => triggerTrafficGeneration('normal'));
    }
    if (btnGenPortScan) {
        btnGenPortScan.addEventListener('click', () => triggerTrafficGeneration('specific', 'port_scan'));
    }
    if (btnGenBurst) {
        btnGenBurst.addEventListener('click', () => triggerTrafficGeneration('burst'));
    }

    // ── Safe Demonstration Reset Handler ─────────────────────────────
    if (btnResetTraffic) {
        btnResetTraffic.addEventListener('click', () => {
            if (resetModal) resetModal.style.display = 'flex';
        });
    }

    if (btnCancelReset) {
        btnCancelReset.addEventListener('click', () => {
            if (resetModal) resetModal.style.display = 'none';
        });
    }

    if (btnConfirmReset) {
        btnConfirmReset.addEventListener('click', async () => {
            if (resetModal) resetModal.style.display = 'none';
            await executeTrafficDemonstrationReset();
        });
    }

    async function executeTrafficDemonstrationReset() {
        setGenStatus('GENERATING', 'Resetting traffic demonstration session...');

        try {
            // 1. Reset backend in-memory recent buffer (does NOT touch SQLite or iptables)
            await IDS.apiFetch('/api/traffic/reset', { method: 'POST' });
        } catch (e) {
            console.warn('[TRAFFIC] Reset API call note:', e);
        }

        // 2. Clear client packet buffers & rolling stats
        packetBuffer.length = 0;
        rollingEvents.length = 0;
        ratePacketsEl.textContent = '0';
        rateBytesEl.textContent = '0';
        totalPacketsEl.textContent = '0';
        threatPacketsEl.textContent = '0';

        // 3. Reset filters strictly back to ALL
        activeQuickFilter = 'all';
        quickPills.forEach(p => p.classList.remove('active'));
        const allPill = document.querySelector('.quick-pill[data-filter="all"]');
        if (allPill) allPill.classList.add('active');
        if (filterInput) filterInput.value = '';
        textFilter = '';

        // 4. Close inspector drawer if open
        if (drawer) drawer.style.display = 'none';
        selectedPacket = null;

        // 5. Reset table display to initial state
        tableBody.innerHTML = `
            <tr class="empty-placeholder-row">
                <td colspan="11" style="text-align:center; padding:60px 20px; color:#64748b;">
                    <div style="font-size:1.8rem; margin-bottom:8px;">📡</div>
                    <div style="font-size:1rem; font-weight:600; color:#94a3b8;">Listening for live network traffic...</div>
                    <div style="font-size:0.85rem; margin-top:4px;">Traffic demonstration state reset. Click <strong>Generate Normal Traffic</strong> or <strong>Port Scan</strong> to start a new test stream.</div>
                </td>
            </tr>
        `;

        // 6. Ensure buttons are re-enabled
        setGeneratorButtonsDisabled(false);
        setGenStatus('READY', 'Session reset complete. Ready.');

        IDS.showToast('Traffic demonstration state reset successfully.', 'info');
    }

    // ── Filter Controls Event Listeners ──────────────────────────────
    filterInput.addEventListener('input', (e) => {
        textFilter = e.target.value;
        applyCurrentFilters();
    });

    quickPills.forEach(pill => {
        pill.addEventListener('click', () => {
            quickPills.forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            activeQuickFilter = pill.dataset.filter;
            applyCurrentFilters();
        });
    });

    // ── Table Controls ───────────────────────────────────────────────
    btnPause.addEventListener('click', () => {
        isPaused = !isPaused;
        btnPause.textContent = isPaused ? '▶ Resume' : '⏸ Pause';
        btnPause.className = isPaused ? 'btn btn-secondary' : 'btn btn-primary';
        if (!isPaused) applyCurrentFilters();
    });

    btnClearTable.addEventListener('click', () => {
        packetBuffer.length = 0;
        tableBody.innerHTML = `
            <tr class="empty-placeholder-row">
                <td colspan="11" style="text-align:center; padding:40px 20px; color:#64748b;">
                    <div style="font-size:1.4rem; margin-bottom:6px;">🗑</div>
                    <div style="font-size:0.95rem; font-weight:600; color:#94a3b8;">Visible buffer cleared. Awaiting new network packets...</div>
                </td>
            </tr>
        `;
        drawer.style.display = 'none';
        updateMetricsSummary();
    });

    btnAutoScroll.addEventListener('click', () => {
        autoScroll = !autoScroll;
        btnAutoScroll.textContent = autoScroll ? '⬇ Auto-scroll: ON' : '⬇ Auto-scroll: OFF';
        btnAutoScroll.style.color = autoScroll ? 'var(--cyan)' : '#94a3b8';
    });

    btnExport.addEventListener('click', () => {
        if (packetBuffer.length === 0) {
            IDS.showToast('No packets captured to export.', 'warning');
            return;
        }

        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const hours = String(now.getHours()).padStart(2, '0');
        const minutes = String(now.getMinutes()).padStart(2, '0');
        const seconds = String(now.getSeconds()).padStart(2, '0');
        const fileName = `IDS_Traffic_${year}-${month}-${day}_${hours}-${minutes}-${seconds}.json`;

        // Safely format packets for export
        const exportData = {
            export_timestamp: now.toISOString(),
            total_packets: packetBuffer.length,
            packets: packetBuffer.map(p => ({
                packet_number: p.packet_number,
                timestamp: p.timestamp,
                source: p.source_ip,
                destination: p.dest_ip,
                protocol: p.protocol,
                ports: {
                    source: p.source_port,
                    destination: p.dest_port
                },
                length: p.packet_length,
                flags: p.tcp_flags,
                info: p.info,
                threat: {
                    level: p.threat_level,
                    type: p.threat_type,
                    detail: p.threat_detail,
                    alert_id: p.alert_id
                },
                payload_metadata: {
                    length: p.payload ? p.payload.length : 0,
                    preview: p.payload ? p.payload.substring(0, 100) : ''
                },
                ethernet: p.ethernet,
                ip: p.ip,
                transport: p.transport,
                hex_dump: p.hex_dump
            }))
        };

        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData, null, 2));
        const dlAnchor = document.createElement('a');
        dlAnchor.setAttribute("href", dataStr);
        dlAnchor.setAttribute("download", fileName);
        document.body.appendChild(dlAnchor);
        dlAnchor.click();
        dlAnchor.remove();

        IDS.showToast(`Exported ${packetBuffer.length} packets to ${fileName}`, 'success');
    });

    // ── Inspector Tabs ───────────────────────────────────────────────
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            const target = tab.dataset.tab;

            document.querySelectorAll('.inspector-content').forEach(c => c.style.display = 'none');
            if (target === 'tree') document.getElementById('tabTree').style.display = 'block';
            else if (target === 'payload') document.getElementById('tabPayload').style.display = 'block';
            else if (target === 'hex') document.getElementById('tabHex').style.display = 'block';
            else if (target === 'security') document.getElementById('tabSecurity').style.display = 'block';
        });
    });

    // ── Initialize Hydration ─────────────────────────────────────────
    hydrateRecentTraffic();
});
