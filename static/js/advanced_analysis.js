
window.AdvancedApp = {
    map: null,
    network: null,
    heatmapChart: null,

    // ================= Globe.gl (3D Earth) =================
    initGlobe(elementId, peerData) {
        if (this.map) {
            this.map = null;
        }

        const container = document.getElementById(elementId);
        if (!container) return;
        container.innerHTML = '';

        const isDark = document.documentElement.classList.contains('dark');

        // Theme Config
        const theme = {
            globeImg: isDark ? '//unpkg.com/three-globe/example/img/earth-night.jpg' : '//unpkg.com/three-globe/example/img/earth-day.jpg',
            bgImg: isDark ? '//unpkg.com/three-globe/example/img/night-sky.png' : null, // Null = transparent for light mode
            atmosphere: isDark ? '#3a228a' : '#ffffff',
            atmosphereAlt: isDark ? 0.25 : 0.15,
            pointColorOnline: '#10b981',
            pointColorOffline: isDark ? '#64748b' : '#94a3b8',
            textColor: isDark ? '#e2e8f0' : '#1e293b',
            cardBg: isDark ? 'rgba(15,23,42,0.9)' : 'rgba(255,255,255,0.9)'
        };

        const globe = Globe()
            .globeImageUrl(theme.globeImg)
            .backgroundColor('rgba(0,0,0,0)') // Transparent background to let CSS show through
            .atmosphereColor(theme.atmosphere)
            .atmosphereAltitude(theme.atmosphereAlt)
            .width(container.offsetWidth)
            .height(container.offsetHeight);

        if (theme.bgImg) {
            globe.backgroundImageUrl(theme.bgImg);
        }

        globe(container);

        // --- Data Processing ---
        const pointsData = peerData.filter(p => p.lat && p.lon).map(p => ({
            lat: parseFloat(p.lat),
            lng: parseFloat(p.lon),
            size: 0.5 + (p.rx_rate + p.tx_rate) / 10,
            color: p.is_online ? theme.pointColorOnline : theme.pointColorOffline,
            name: p.alias || 'Client',
            ip: p.endpoint,
            is_online: p.is_online
        }));

        globe
            .pointsData(pointsData)
            .pointAltitude(0.01)
            .pointColor('color')
            .pointRadius('size')
            .pointResolution(16)
            .pointLabel(d => `
                <div style="background: ${theme.cardBg}; color: ${theme.textColor}; padding: 8px 12px; border-radius: 8px; border: 1px solid rgba(128,128,128,0.1); font-family: sans-serif; font-size: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
                    <strong style="color: ${d.color}; font-size: 14px;">${d.name}</strong><br>
                    <span style="opacity: 0.7;">${d.ip}</span><br>
                    <span style="display:inline-block; width:6px; height:6px; background:${d.color}; border-radius:50%; margin-right:4px;"></span>
                    ${d.is_online ? 'Online' : 'Offline'}
                </div>
            `);

        // Rings for Online Peers
        const ringsData = pointsData.filter(p => p.is_online);
        globe
            .ringsData(ringsData)
            .ringColor(() => theme.pointColorOnline)
            .ringMaxRadius(5)
            .ringPropagationSpeed(2)
            .ringRepeatPeriod(1000);

        // Auto-rotate
        globe.controls().autoRotate = true;
        globe.controls().autoRotateSpeed = 0.5;
        globe.pointOfView({ altitude: 2.5 });

        // Handle resize
        window.addEventListener('resize', () => {
            if (container) {
                globe.width(container.offsetWidth);
                globe.height(container.offsetHeight);
            }
        });

        this.map = globe;
    },

    // ================= Network Topology (Vis.js) =================
    initTopology(elementId, peerData) {
        if (this.network) {
            this.network.destroy();
            this.network = null;
        }

        const container = document.getElementById(elementId);
        if (!container) return;

        // Server Node (Center)
        const nodes = new vis.DataSet([
            {
                id: 'server',
                label: 'WG Server',
                color: { background: '#3b82f6', border: '#2563eb' },
                size: 40,
                shape: 'hexagon',
                font: { color: '#fff', size: 14, face: 'Inter' },
                shadow: true,
                title: 'WireGuard Server'
            }
        ]);

        const edges = new vis.DataSet([]);

        // Helper to format bytes
        const fmtBytes = (b) => {
            if (!b) return '0 B';
            const i = Math.floor(Math.log(b) / Math.log(1024));
            return (b / Math.pow(1024, i)).toFixed(1) + ' ' + ['B', 'KB', 'MB', 'GB', 'TB'][i];
        };

        // Helper to format rate
        const fmtRate = (v) => v ? v.toFixed(2) + ' Mbps' : '0 Mbps';

        peerData.forEach(p => {
            const isOnline = p.is_online;
            const rxRate = p.rx_rate || 0;
            const txRate = p.tx_rate || 0;
            const totalRate = rxRate + txRate;

            // Node Color & Shape
            let color = isOnline ? '#10b981' : '#64748b'; // Green or Gray
            if (isOnline && totalRate > 50) color = '#f59e0b'; // High traffic (Amber)
            if (isOnline && totalRate > 100) color = '#ef4444'; // Very high traffic (Red)

            const label = p.alias || p.public_key.substring(0, 4);

            // Rich Tooltip (Glass Card)
            const tooltipContent = document.createElement('div');
            tooltipContent.className = 'glass-card p-3 rounded-xl text-xs font-sans shadow-xl backdrop-blur-md bg-white/80 dark:bg-slate-900/80 border border-white/20 dark:border-white/10 text-slate-700 dark:text-slate-200';
            tooltipContent.style.minWidth = '200px';
            tooltipContent.innerHTML = `
                <div class="flex items-center gap-2 mb-2 border-b border-slate-200 dark:border-white/10 pb-2">
                    <div class="w-2 h-2 rounded-full ${isOnline ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]' : 'bg-slate-400'}"></div>
                    <div class="font-bold text-sm text-slate-800 dark:text-white">${p.alias || '未命名'}</div>
                </div>
                <div class="grid grid-cols-2 gap-y-1 gap-x-3 mb-1">
                    <div class="text-slate-500">IP:</div>
                    <div class="font-mono text-right truncate">${p.allowed_ips ? p.allowed_ips[0] : '-'}</div>
                    
                    <div class="text-slate-500">地区:</div>
                    <div class="text-right truncate">${p.city || '-'}, ${p.country_code || '-'}</div>
                    
                    <div class="col-span-2 my-1 h-[1px] bg-slate-100 dark:bg-white/5"></div>
                    
                    <div class="text-emerald-600 dark:text-emerald-400 flex items-center gap-1"><i data-lucide="arrow-down" class="w-3 h-3"></i>下载:</div>
                    <div class="font-mono text-right font-bold text-emerald-600 dark:text-emerald-400">${fmtRate(rxRate)}</div>
                    
                    <div class="text-blue-600 dark:text-blue-400 flex items-center gap-1"><i data-lucide="arrow-up" class="w-3 h-3"></i>上传:</div>
                    <div class="font-mono text-right font-bold text-blue-600 dark:text-blue-400">${fmtRate(txRate)}</div>
                    
                    <div class="text-slate-500">总流量:</div>
                    <div class="font-mono text-right">${fmtBytes(p.total_rx + p.total_tx)}</div>
                </div>
                <div class="text-[10px] text-slate-400 font-mono mt-2 text-center bg-slate-50 dark:bg-slate-800/50 rounded py-1">
                    ${p.public_key.substring(0, 16)}...
                </div>
            `;

            nodes.add({
                id: p.public_key,
                label: label,
                color: {
                    background: color,
                    border: isOnline ? '#fff' : '#cbd5e1',
                    highlight: { border: '#3b82f6', background: color }
                },
                size: isOnline ? 20 + Math.min(totalRate, 30) : 15,
                shape: 'dot',
                font: { color: document.documentElement.classList.contains('dark') ? '#94a3b8' : '#64748b', size: 12, face: 'Inter', strokeWidth: 0, strokeColor: '#fff' },
                title: tooltipContent,
                shadow: { enabled: true, color: 'rgba(0,0,0,0.1)', size: 10, x: 5, y: 5 }
            });

            // Edge Style
            edges.add({
                from: 'server',
                to: p.public_key,
                color: { color: isOnline ? '#94a3b8' : '#e2e8f0', opacity: isOnline ? 0.4 : 0.1, highlight: '#3b82f6' },
                width: isOnline ? 1 + Math.min(totalRate / 5, 8) : 1,
                dashes: !isOnline,
                smooth: { type: 'continuous', roundness: 0.5 }
            });
        });

        const data = { nodes: nodes, edges: edges };
        const options = {
            nodes: { borderWidth: 2, shadow: true },
            edges: { selectionWidth: 2, hoverWidth: 2 },
            physics: {
                stabilization: true,
                forceAtlas2Based: {
                    gravitationalConstant: -100,
                    centralGravity: 0.005,
                    springLength: 200,
                    springConstant: 0.05,
                    damping: 0.4
                },
                solver: 'forceAtlas2Based'
            },
            interaction: { hover: true, tooltipDelay: 100, zoomView: true }
        };

        this.network = new vis.Network(container, data, options);

        // Fit to center
        setTimeout(() => this.network.fit({ animation: { duration: 1000, easingFunction: 'easeInOutQuad' } }), 500);
    },

    // ================= Traffic Heatmap (Canvas) =================
    // data: 7x24 array (7 days, 24 hours), values are Mbps
    initHeatmap(elementId, data) {
        const canvas = document.getElementById(elementId);
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const width = canvas.width = canvas.parentElement.offsetWidth;
        const height = canvas.height = 300;

        ctx.clearRect(0, 0, width, height);

        const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        const hours = 24;

        const cellWidth = (width - 40) / hours;
        const cellHeight = (height - 30) / days.length;

        // Find max value for normalization
        let maxVal = 0;
        for (let d = 0; d < 7; d++) {
            for (let h = 0; h < 24; h++) {
                if (data[d] && data[d][h] > maxVal) maxVal = data[d][h];
            }
        }
        if (maxVal === 0) maxVal = 1;

        // Draw Heatmap
        for (let d = 0; d < 7; d++) {
            // Draw Day Label
            ctx.fillStyle = '#94a3b8';
            ctx.font = '12px sans-serif';
            ctx.fillText(days[d], 5, 25 + d * cellHeight + cellHeight / 2);

            for (let h = 0; h < 24; h++) {
                const val = (data[d] && data[d][h]) || 0;
                const intensity = val / maxVal;

                // Color map: Low (Blue) -> High (Red)
                // Use HSL for simplicity: Blue(240) -> Cyan(180) -> Green(120) -> Yellow(60) -> Red(0)
                // We want Low=Cold, High=Hot.
                // 0.0 -> 240 (Blue)
                // 1.0 -> 0 (Red)
                // But let's stick to a single hue gradient (Blue) for cleaner look in dark mode
                // Alpha based on intensity

                ctx.fillStyle = `rgba(59, 130, 246, ${0.1 + intensity * 0.9})`;
                ctx.fillRect(40 + h * cellWidth, 25 + d * cellHeight, cellWidth - 2, cellHeight - 2);

                // Tooltip logic would go here (complex for canvas), skip for now
            }
        }

        // Draw Hour Labels
        for (let h = 0; h < 24; h += 2) {
            ctx.fillStyle = '#94a3b8';
            ctx.fillText(h, 40 + h * cellWidth + cellWidth / 2 - 5, 20);
        }
    }
};
