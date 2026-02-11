
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

        const nodes = new vis.DataSet([
            { id: 'server', label: 'Server', color: '#3b82f6', size: 30, shape: 'dot', font: { color: '#fff' } }
        ]);

        const edges = new vis.DataSet([]);

        peerData.forEach(p => {
            const color = p.is_online ? '#10b981' : '#64748b';
            nodes.add({
                id: p.public_key,
                label: p.alias || p.public_key.substring(0, 4),
                color: color,
                size: 15,
                shape: 'dot',
                font: { color: '#cbd5e1' }
            });

            edges.add({
                from: 'server',
                to: p.public_key,
                color: { color: color, opacity: 0.4 },
                width: p.is_online ? 2 : 1,
                dashes: !p.is_online
            });
        });

        const data = { nodes: nodes, edges: edges };
        const options = {
            nodes: { borderWidth: 0, shadow: true },
            edges: { smooth: { type: 'continuous' } },
            physics: {
                stabilization: false,
                barnesHut: { gravitationalConstant: -2000, springConstant: 0.04 }
            },
            interaction: { hover: true, tooltipDelay: 200 }
        };

        this.network = new vis.Network(container, data, options);
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
