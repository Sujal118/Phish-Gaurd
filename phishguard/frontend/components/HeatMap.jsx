/**
 * PhishGuard — Interactive Deception HeatMap Component
 * Uses Plotly.js to render clickable heatmap visualizations.
 */

function HeatMap({ data }) {
    const heatmapRef = React.useRef(null);
    const [selectedFlag, setSelectedFlag] = React.useState(null);

    React.useEffect(() => {
        if (!data || !heatmapRef.current) return;
        renderHeatmap();
    }, [data]);

    const renderHeatmap = () => {
        if (!data?.risk_score?.breakdown) return;

        const breakdown = data.risk_score.breakdown;
        const signals = breakdown.map(b => b.signal);
        const scores = breakdown.map(b => b.points);
        const weights = breakdown.map(b => b.weight);
        const colors = breakdown.map(b =>
            b.severity === 'high' ? '#e74c3c' :
            b.severity === 'medium' ? '#f39c12' : '#27ae60'
        );

        // Bar chart for signal breakdown
        const barTrace = {
            x: signals,
            y: scores,
            type: 'bar',
            marker: {
                color: colors,
                line: { color: 'rgba(255,255,255,0.1)', width: 1 }
            },
            text: scores.map((s, i) => `${s}/${weights[i]}`),
            textposition: 'outside',
            textfont: { color: '#f0f0f5', size: 12 },
            hovertemplate: '<b>%{x}</b><br>Score: %{y}/%{customdata}<extra></extra>',
            customdata: weights
        };

        const layout = {
            title: {
                text: 'Detection Signal Heatmap',
                font: { color: '#f0f0f5', size: 18, family: 'Inter' }
            },
            paper_bgcolor: 'transparent',
            plot_bgcolor: 'transparent',
            font: { color: '#a0a0c0', family: 'Inter' },
            xaxis: {
                tickangle: -20,
                gridcolor: 'rgba(255,255,255,0.03)'
            },
            yaxis: {
                title: 'Risk Points',
                gridcolor: 'rgba(255,255,255,0.05)',
                range: [0, 50]
            },
            margin: { t: 50, b: 120, l: 60, r: 30 },
            bargap: 0.3
        };

        Plotly.newPlot(heatmapRef.current, [barTrace], layout, {
            responsive: true,
            displayModeBar: false
        });

        // Click handler for bars
        heatmapRef.current.on('plotly_click', (eventData) => {
            const pointIndex = eventData.points[0].pointIndex;
            setSelectedFlag(breakdown[pointIndex]);
        });
    };

    if (!data) {
        return (
            <div className="text-center p-5">
                <i className="bi bi-grid-3x3" style={{ fontSize: '3rem', color: 'var(--text-muted)' }}></i>
                <h4 className="mt-3" style={{ color: 'var(--text-secondary)' }}>No Heatmap Data</h4>
                <p className="text-muted">Analyze an email first to see the interactive deception heatmap.</p>
            </div>
        );
    }

    return (
        <div className="animate-in">
            <h3 className="mb-4">
                <i className="bi bi-grid-3x3 me-2"></i>
                Interactive Deception Heatmap
            </h3>
            <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem' }}>
                Click any bar to see detailed explanation of the detection signal.
            </p>

            {/* Plotly Chart */}
            <div ref={heatmapRef} style={{ width: '100%', minHeight: '400px' }}></div>

            {/* Flag Detail Popup */}
            {selectedFlag && (
                <div className="glass-card mt-4 animate-in" style={{
                    borderColor: selectedFlag.severity === 'high' ? 'rgba(231,76,60,0.4)' :
                                selectedFlag.severity === 'medium' ? 'rgba(243,156,18,0.4)' : 'rgba(39,174,96,0.4)'
                }}>
                    <div className="d-flex justify-content-between align-items-start">
                        <div>
                            <h5>
                                <span className={`threat-badge ${selectedFlag.severity === 'high' ? 'high' : selectedFlag.severity === 'medium' ? 'medium' : 'low'}`}>
                                    {selectedFlag.severity?.toUpperCase()}
                                </span>
                                <span className="ms-2">{selectedFlag.signal}</span>
                            </h5>
                            <p className="mt-2 mb-1" style={{ color: 'var(--text-secondary)' }}>
                                {selectedFlag.details}
                            </p>
                            <p className="mb-0 text-muted">
                                Points: <strong>{selectedFlag.points}</strong> / {selectedFlag.weight}
                            </p>
                        </div>
                        <button
                            className="btn-outline"
                            onClick={() => setSelectedFlag(null)}
                            style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}
                        >
                            ✕ Close
                        </button>
                    </div>
                </div>
            )}

            {/* SPF/DKIM/DMARC Grid */}
            {data.spf && (
                <div className="mt-4">
                    <h5 style={{ color: 'var(--text-secondary)' }}>Authentication Grid</h5>
                    <div className="d-flex gap-3 mt-2">
                        <div className={`glass-card text-center flex-fill`} style={{ padding: '1rem' }}>
                            <div style={{ fontSize: '1.5rem' }}>{data.spf.spf_pass ? '✅' : '❌'}</div>
                            <div className="mt-1" style={{ fontWeight: 600 }}>SPF</div>
                            <div className="text-muted" style={{ fontSize: '0.8rem' }}>{data.spf.spf_pass ? 'PASS' : 'FAIL'}</div>
                        </div>
                        <div className="glass-card text-center flex-fill" style={{ padding: '1rem' }}>
                            <div style={{ fontSize: '1.5rem' }}>{data.parsed?.dkim_signature ? '✅' : '❌'}</div>
                            <div className="mt-1" style={{ fontWeight: 600 }}>DKIM</div>
                            <div className="text-muted" style={{ fontSize: '0.8rem' }}>{data.parsed?.dkim_signature ? 'PRESENT' : 'MISSING'}</div>
                        </div>
                        <div className="glass-card text-center flex-fill" style={{ padding: '1rem' }}>
                            <div style={{ fontSize: '1.5rem' }}>⚠️</div>
                            <div className="mt-1" style={{ fontWeight: 600 }}>DMARC</div>
                            <div className="text-muted" style={{ fontSize: '0.8rem' }}>NOT CHECKED</div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
