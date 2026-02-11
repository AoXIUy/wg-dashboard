
window.AdvancedApp = {
    map: null,
    network: null,
    heatmapChart: null,

    // ================= World Map (Leaflet) =================
    initMap(elementId, peerData) {
        if (this.map) {
            this.map.remove();
            this.map = null;
        }

        const container = document.getElementById(elementId);
        if (!container) return;

        // Dark/Midnight theme tiles
        const tiles = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
            subdomains: 'abcd',
            maxZoom: 19
        });

        this.map = L.map(elementId, {
            center: [20, 0],
            zoom: 2,
            layers: [tiles]
        });

        const bounds = [];

        peerData.forEach(p => {
            if (p.lat && p.lon) {
                const marker = L.circleMarker([p.lat, p.lon], {
                    radius: 5,
                    fillColor: p.is_online ? '#10b981' : '#64748b',
                    color: '#fff',
                    weight: 1,
                    opacity: 1,
                    fillOpacity: 0.8
                }).addTo(this.map);

                marker.bindPopup(`
                    <b>${p.alias || 'Unknown'}</b><br>
                    IP: ${p.endpoint}<br>
                    Location: ${p.city}, ${p.country_code}
                `);

                bounds.push([p.lat, p.lon]);
            }
        });

        if (bounds.length > 0) {
            this.map.fitBounds(bounds, { padding: [50, 50] });
        }
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

            // Rich Tooltip (HTML)
            const tooltipContent = document.createElement('div');
            tooltipContent.className = 'p-2 text-xs font-sans';
            tooltipContent.innerHTML = `
                <div class="font-bold text-sm mb-1">${p.alias || 'Unknown'}</div>
                <div class="text-gray-400 font-mono mb-2">${p.public_key.substring(0, 12)}...</div>
                <div class="grid grid-cols-2 gap-2">
                    <div><span class="text-gray-500">IP:</span> ${p.allowed_ips ? p.allowed_ips[0] : 'N/A'}</div>
                    <div><span class="text-gray-500">Loc:</span> ${p.city || '-'}, ${p.country_code || '-'}</div>
                    <div><span class="text-emerald-500">Rx:</span> ${fmtRate(rxRate)}</div>
                    <div><span class="text-blue-500">Tx:</span> ${fmtRate(txRate)}</div>
                    <div><span class="text-gray-500">Total:</span> ${fmtBytes(p.total_rx + p.total_tx)}</div>
                    <div><span class="text-gray-500">State:</span> ${isOnline ? '<span class="text-green-500">Online</span>' : '<span class="text-gray-500">Offline</span>'}</div>
                </div>
            `;

            nodes.add({
                id: p.public_key,
                label: label,
                color: { background: color, border: '#fff', highlight: { border: '#3b82f6', background: color } },
                size: isOnline ? 20 + Math.min(totalRate, 20) : 15, // Dynamic size based on traffic
                shape: 'dot',
                font: { color: '#94a3b8', size: 12, face: 'Inter' },
                title: tooltipContent // Vis.js supports DOM elements for title
            });

            // Edge Style
            edges.add({
                from: 'server',
                to: p.public_key,
                color: { color: isOnline ? '#94a3b8' : '#e2e8f0', opacity: isOnline ? 0.6 : 0.3, highlight: '#3b82f6' },
                width: isOnline ? 1 + Math.min(totalRate / 5, 10) : 1, // Dynamic width based on traffic
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
