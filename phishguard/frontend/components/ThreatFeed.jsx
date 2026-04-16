/**
 * PhishGuard — Threat Feed Component
 * Displays batch analysis results sorted by severity.
 */

function ThreatFeed({ items }) {
    if (!items || items.length === 0) {
        return (
            <div className="text-center p-5">
                <i className="bi bi-rss" style={{ fontSize: '3rem', color: 'var(--text-muted)' }}></i>
                <h4 className="mt-3" style={{ color: 'var(--text-secondary)' }}>Threat Feed</h4>
                <p className="text-muted">
                    No threat data yet. Use Batch Upload to analyze multiple emails and see them ranked here.
                </p>
            </div>
        );
    }

    // Sort by risk score (highest first)
    const sorted = [...items].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));

    return (
        <div className="animate-in">
            <h3 className="mb-3">
                <i className="bi bi-rss me-2"></i>
                Live Threat Feed
            </h3>
            <p className="text-muted mb-4">
                Emails ranked by severity — highest risk at the top.
            </p>

            <div>
                {sorted.map((item, index) => {
                    const score = item.risk_score || 0;
                    const level = score > 60 ? 'high' : score > 30 ? 'medium' : 'low';
                    const levelLabel = score > 60 ? 'HIGH' : score > 30 ? 'MEDIUM' : 'LOW';

                    return (
                        <div key={index} className="threat-item" style={{ animationDelay: `${index * 0.1}s` }}>
                            <div style={{
                                width: '40px', height: '40px',
                                borderRadius: '10px',
                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                background: level === 'high' ? 'rgba(231,76,60,0.1)' :
                                           level === 'medium' ? 'rgba(243,156,18,0.1)' : 'rgba(39,174,96,0.1)',
                                fontSize: '1.2rem',
                                flexShrink: 0
                            }}>
                                {level === 'high' ? '🔴' : level === 'medium' ? '🟡' : '🟢'}
                            </div>

                            <div style={{ flex: 1, minWidth: 0 }}>
                                <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>
                                    {item.file || item.subject || `Email #${index + 1}`}
                                </div>
                                <div className="text-muted" style={{ fontSize: '0.8rem' }}>
                                    {item.from || item.status || 'Analyzed'}
                                </div>
                            </div>

                            <div className="text-end" style={{ flexShrink: 0 }}>
                                <span className={`threat-badge ${level}`}>{levelLabel}</span>
                                {score > 0 && (
                                    <div className="mt-1" style={{
                                        fontSize: '0.85rem',
                                        fontWeight: 700,
                                        color: level === 'high' ? '#e74c3c' :
                                               level === 'medium' ? '#f39c12' : '#27ae60'
                                    }}>
                                        {score}/100
                                    </div>
                                )}
                            </div>
                        </div>
                    );
                })}
            </div>

            {/* Summary Stats */}
            <div className="d-flex gap-3 mt-4 pt-3" style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                <div className="glass-card text-center flex-fill" style={{ padding: '1rem' }}>
                    <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#e74c3c' }}>
                        {sorted.filter(i => (i.risk_score || 0) > 60).length}
                    </div>
                    <div className="text-muted" style={{ fontSize: '0.8rem' }}>High Risk</div>
                </div>
                <div className="glass-card text-center flex-fill" style={{ padding: '1rem' }}>
                    <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f39c12' }}>
                        {sorted.filter(i => (i.risk_score || 0) > 30 && (i.risk_score || 0) <= 60).length}
                    </div>
                    <div className="text-muted" style={{ fontSize: '0.8rem' }}>Medium Risk</div>
                </div>
                <div className="glass-card text-center flex-fill" style={{ padding: '1rem' }}>
                    <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#27ae60' }}>
                        {sorted.filter(i => (i.risk_score || 0) <= 30).length}
                    </div>
                    <div className="text-muted" style={{ fontSize: '0.8rem' }}>Low Risk</div>
                </div>
            </div>
        </div>
    );
}
