/**
 * PhishGuard — ScoreCard Component
 * Displays the risk score with visual ring and breakdown bars.
 */

function ScoreCard({ data }) {
    if (!data) {
        return (
            <div className="text-center p-4">
                <i className="bi bi-shield-slash" style={{ fontSize: '2rem', color: 'var(--text-muted)' }}></i>
                <p className="mt-2 text-muted">No analysis data yet. Upload an email to get started.</p>
            </div>
        );
    }

    const { total_score, band, breakdown } = data;
    const scoreClass = band?.level || 'low';
    const percentage = total_score || 0;

    return (
        <div className="animate-in">
            <h3 className="mb-4">
                <i className="bi bi-speedometer2 me-2"></i>
                Risk Assessment
            </h3>

            {/* Score Ring */}
            <div className="score-ring">
                <div className={`score-display ${scoreClass}`}>
                    {percentage}
                </div>
            </div>

            <div className="text-center mb-4">
                <span className={`threat-badge ${scoreClass}`} style={{ fontSize: '1rem', padding: '0.5rem 1.2rem' }}>
                    {band?.label || 'Unknown'}
                </span>
            </div>

            {/* Breakdown */}
            <h5 className="mb-3" style={{ color: 'var(--text-secondary)' }}>Signal Breakdown</h5>
            {breakdown && breakdown.map((item, index) => {
                const fillPct = (item.points / Math.max(item.weight, 1)) * 100 || 0;
                const fillClass = item.severity === 'high' ? 'red' :
                                  item.severity === 'medium' ? 'yellow' : 'green';
                return (
                    <div key={index} className="breakdown-bar" style={{ marginBottom: '16px' }}>
                        <div className="label" style={{ marginBottom: '6px' }}>
                            <span style={{ fontWeight: 600 }}>{item.signal}</span>
                            <span>{item.points}/{item.weight}</span>
                        </div>
                        <div className="bar" style={{ marginBottom: '6px' }}>
                            <div
                                className={`fill ${fillClass}`}
                                style={{ width: `${fillPct}%` }}
                            ></div>
                        </div>
                    </div>
                );
            })}
        </div>
    );
}
