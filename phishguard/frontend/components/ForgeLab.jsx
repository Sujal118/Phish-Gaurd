/**
 * PhishGuard — Forge Lab Component
 * Side-by-side diff view of original vs. spoofed email.
 */

function ForgeLab({ data }) {
    if (!data || !data.forged) {
        return (
            <div className="text-center p-5">
                <i className="bi bi-hammer" style={{ fontSize: '3rem', color: 'var(--text-muted)' }}></i>
                <h4 className="mt-3" style={{ color: 'var(--text-secondary)' }}>Phishing Forge Lab</h4>
                <p className="text-muted">Upload a legitimate email to see how attackers could spoof it.</p>
            </div>
        );
    }

    const { original, forged, diff, techniques_used } = data.forged;

    return (
        <div className="animate-in">
            <h3 className="mb-2">
                <i className="bi bi-hammer me-2"></i>
                Phishing Forge Lab
            </h3>
            <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem', fontSize: '1.05rem', fontWeight: 500 }}>
                See the attacker's perspective — every change is highlighted below.
            </p>

            {/* Techniques Used */}
            {techniques_used && techniques_used.length > 0 && (
                <div className="mb-4">
                    <h5 style={{ color: 'var(--accent-danger)' }}>
                        <i className="bi bi-exclamation-triangle me-2"></i>
                        Techniques Applied ({techniques_used.length})
                    </h5>
                    <div className="mt-2">
                        {techniques_used.map((tech, i) => (
                            <div key={i} className="glass-card mb-2" style={{
                                padding: '0.75rem 1rem',
                                borderColor: 'rgba(231, 76, 60, 0.3)'
                            }}>
                                <div className="d-flex align-items-center gap-2">
                                    <span className="threat-badge high">{tech.technique}</span>
                                    <span style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                                        {tech.description}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Side-by-side Diff */}
            <div className="diff-panel">
                <div className="diff-side original">
                    <h5 style={{ color: 'var(--accent-success)', marginBottom: '1rem' }}>
                        <i className="bi bi-check-circle me-2"></i>Original Email
                    </h5>
                    <div><strong>From:</strong> {original?.from || 'N/A'}</div>
                    <div><strong>Reply-To:</strong> {original?.reply_to || '(none)'}</div>
                    <div><strong>Subject:</strong> {original?.subject || 'N/A'}</div>
                    <hr style={{ borderColor: 'rgba(39,174,96,0.2)' }} />
                    <div style={{ whiteSpace: 'pre-wrap', fontSize: '0.8rem' }}>
                        {original?.body?.substring(0, 500) || 'No body content'}
                    </div>
                </div>

                <div className="diff-side forged">
                    <h5 style={{ color: 'var(--accent-danger)', marginBottom: '1rem' }}>
                        <i className="bi bi-exclamation-triangle me-2"></i>Spoofed Version
                    </h5>
                    <div>
                        <strong>From:</strong>{' '}
                        <span className={diff?.find(d => d.field === 'from')?.changed ? 'diff-highlight' : ''}>
                            {forged?.from || 'N/A'}
                        </span>
                    </div>
                    <div>
                        <strong>Reply-To:</strong>{' '}
                        <span className={diff?.find(d => d.field === 'reply_to')?.changed ? 'diff-highlight' : ''}>
                            {forged?.reply_to || '(none)'}
                        </span>
                    </div>
                    <div>
                        <strong>Subject:</strong>{' '}
                        <span className={diff?.find(d => d.field === 'subject')?.changed ? 'diff-highlight' : ''}>
                            {forged?.subject || 'N/A'}
                        </span>
                    </div>
                    <hr style={{ borderColor: 'rgba(231,76,60,0.2)' }} />
                    <div style={{ whiteSpace: 'pre-wrap', fontSize: '0.8rem' }}>
                        {forged?.body?.substring(0, 500) || 'No body content'}
                    </div>
                </div>
            </div>

            {/* Diff Summary */}
            {diff && (
                <div className="glass-card mt-4" style={{ padding: '1rem' }}>
                    <h5 className="mb-2" style={{ color: 'var(--text-secondary)' }}>
                        <i className="bi bi-file-diff me-2"></i>Change Summary
                    </h5>
                    {diff.map((d, i) => (
                        <div key={i} className="d-flex align-items-center gap-2 mb-1" style={{ fontSize: '0.85rem' }}>
                            <span style={{ color: d.changed ? 'var(--accent-danger)' : 'var(--accent-success)' }}>
                                {d.changed ? '⚠️ CHANGED' : '✅ Unchanged'}
                            </span>
                            <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>{d.field}:</span>
                            {d.changed && (
                                <span style={{ color: 'var(--text-primary)' }}>
                                    "{d.original}" → "{d.forged}"
                                </span>
                            )}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
