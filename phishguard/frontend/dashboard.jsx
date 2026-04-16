/**
 * PhishGuard — Main Dashboard Component
 * Renders the primary UI with navigation, upload, and analysis views.
 */

const API_BASE = 'http://localhost:5000';

function App() {
    const [activeTab, setActiveTab] = React.useState('analyze');
    const [analysisResult, setAnalysisResult] = React.useState(null);
    const [forgeResult, setForgeResult] = React.useState(null);
    const [batchResults, setBatchResults] = React.useState([]);
    const [loading, setLoading] = React.useState(false);
    const [uploadedFile, setUploadedFile] = React.useState(null);

    const handleFileUpload = async (file, endpoint) => {
        setLoading(true);
        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch(`${API_BASE}${endpoint}`, {
                method: 'POST',
                body: formData
            });
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Upload failed:', error);
            return { error: 'Failed to connect to backend. Is the server running?' };
        } finally {
            setLoading(false);
        }
    };

    const onAnalyze = async (file) => {
        setUploadedFile(file);
        const result = await handleFileUpload(file, '/analyze');
        setAnalysisResult(result);
    };

    const onAnalyzeText = async (emailText) => {
        setLoading(true);
        try {
            const response = await fetch(`${API_BASE}/analyze-text`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email_text: emailText })
            });
            const data = await response.json();
            setAnalysisResult(data);
        } catch (error) {
            console.error('Analysis failed:', error);
            setAnalysisResult({ error: 'Failed to connect to backend. Is the server running?' });
        } finally {
            setLoading(false);
        }
    };

    const onForge = async (file) => {
        const result = await handleFileUpload(file, '/forge');
        setForgeResult(result);
    };

    const onBatch = async (file) => {
        const result = await handleFileUpload(file, '/batch');
        setBatchResults(result.results || []);
    };

    const tabs = [
        { id: 'analyze', label: 'Analyze Email', icon: 'bi-shield-check' },
        { id: 'heatmap', label: 'Heatmap', icon: 'bi-grid-3x3' },
        { id: 'forge', label: 'Forge Lab', icon: 'bi-hammer' },
        { id: 'batch', label: 'Batch Upload', icon: 'bi-collection' },
        { id: 'feed', label: 'Threat Feed', icon: 'bi-rss' },
    ];

    return (
        <div>
            {/* Header */}
            <header className="phishguard-header">
                <div className="d-flex justify-content-between align-items-center">
                    <div className="phishguard-logo">
                        <span className="shield-icon">🛡️</span> PhishGuard
                    </div>
                    <div className="d-flex align-items-center gap-3">
                        <span className="text-muted" style={{ fontSize: '0.85rem' }}>
                            Phishing Email Detection System
                        </span>
                        <span className="badge bg-success">v1.0</span>
                    </div>
                </div>
            </header>

            {/* Main Content */}
            <div className="dashboard-container">
                {/* Navigation Tabs */}
                <nav className="nav-tabs-custom">
                    {tabs.map(tab => (
                        <button
                            key={tab.id}
                            className={`nav-tab ${activeTab === tab.id ? 'active' : ''}`}
                            onClick={() => setActiveTab(tab.id)}
                        >
                            <i className={`bi ${tab.icon}`}></i>
                            {tab.label}
                        </button>
                    ))}
                </nav>

                {/* Tab Content */}
                <div className="animate-in">
                    {activeTab === 'analyze' && (
                        <>
                        <div className="dashboard-grid">
                            <div className="glass-card">
                                <UploadZone
                                    onUpload={onAnalyze}
                                    accept=".eml"
                                    title="Upload Email (.eml)"
                                    description="Drag & drop or click to upload a .eml file for phishing analysis"
                                    loading={loading}
                                />

                                {/* OR Divider */}
                                <div style={{
                                    display: 'flex', alignItems: 'center', gap: '16px',
                                    margin: '24px 0', padding: '0 20px'
                                }}>
                                    <div style={{ flex: 1, height: '1px', background: 'linear-gradient(to right, transparent, rgba(255,255,255,0.15), transparent)' }}></div>
                                    <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem', fontWeight: 600, letterSpacing: '2px' }}>OR</span>
                                    <div style={{ flex: 1, height: '1px', background: 'linear-gradient(to right, transparent, rgba(255,255,255,0.15), transparent)' }}></div>
                                </div>

                                {/* Paste Email Zone */}
                                <PasteZone onAnalyze={onAnalyzeText} loading={loading} />
                            </div>
                            {analysisResult && !analysisResult.error && (
                                <div className="glass-card">
                                    <ScoreCard data={analysisResult.risk_score} />
                                </div>
                            )}
                            {analysisResult && analysisResult.error && (
                                <div className="glass-card">
                                    <div className="text-center p-4">
                                        <i className="bi bi-exclamation-triangle" style={{ fontSize: '2rem', color: 'var(--accent-danger)' }}></i>
                                        <p className="mt-2">{analysisResult.error}</p>
                                    </div>
                                </div>
                            )}
                        </div>
                        {analysisResult && !analysisResult.error && (
                            <ExecutiveReport data={analysisResult} />
                        )}
                        </>
                    )}

                    {activeTab === 'heatmap' && (
                        <div className="glass-card full-width">
                            <HeatMap data={analysisResult} />
                        </div>
                    )}

                    {activeTab === 'forge' && (
                        <div>
                            <div className="glass-card mb-4">
                                <UploadZone
                                    onUpload={onForge}
                                    accept=".eml"
                                    title="Upload Email to Forge"
                                    description="Upload a legitimate .eml file to generate a spoofed variant"
                                    loading={loading}
                                />
                            </div>
                            {forgeResult && (
                                <div className="glass-card">
                                    <ForgeLab data={forgeResult} />
                                </div>
                            )}
                        </div>
                    )}

                    {activeTab === 'batch' && (
                        <div>
                            <div className="glass-card mb-4">
                                <UploadZone
                                    onUpload={onBatch}
                                    accept=".zip"
                                    title="Upload ZIP of Emails"
                                    description="Upload a .zip archive containing multiple .eml files for batch analysis"
                                    loading={loading}
                                />
                            </div>
                            {batchResults.length > 0 && (
                                <div className="glass-card">
                                    <h3 className="mb-3">
                                        <i className="bi bi-check2-all me-2"></i>
                                        Batch Results ({batchResults.length} emails)
                                    </h3>
                                    <ThreatFeed items={batchResults} />
                                </div>
                            )}
                        </div>
                    )}

                    {activeTab === 'feed' && (
                        <div className="glass-card">
                            <ThreatFeed items={batchResults} />
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

/**
 * Reusable Upload Zone Component
 */
function UploadZone({ onUpload, accept, title, description, loading }) {
    const [dragActive, setDragActive] = React.useState(false);
    const fileInputRef = React.useRef(null);

    const handleDrag = (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.type === 'dragenter' || e.type === 'dragover') {
            setDragActive(true);
        } else if (e.type === 'dragleave') {
            setDragActive(false);
        }
    };

    const handleDrop = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setDragActive(false);
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            onUpload(e.dataTransfer.files[0]);
        }
    };

    const handleChange = (e) => {
        if (e.target.files && e.target.files[0]) {
            onUpload(e.target.files[0]);
        }
    };

    return (
        <div
            className={`upload-zone ${dragActive ? 'drag-active' : ''}`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current.click()}
        >
            <input
                ref={fileInputRef}
                type="file"
                accept={accept}
                onChange={handleChange}
                style={{ display: 'none' }}
            />
            {loading ? (
                <div className="loading-pulse">
                    <i className="bi bi-arrow-repeat" style={{ fontSize: '3rem', color: 'var(--accent-primary)' }}></i>
                    <h3 className="mt-3">Analyzing...</h3>
                </div>
            ) : (
                <>
                    <i className="bi bi-cloud-arrow-up"></i>
                    <h3>{title}</h3>
                    <p>{description}</p>
                </>
            )}
        </div>
    );
}

/**
 * Paste Email Zone Component
 * Allows users to paste raw email text for analysis.
 */
function PasteZone({ onAnalyze, loading }) {
    const [emailText, setEmailText] = React.useState('');

    const handleSubmit = () => {
        if (emailText.trim()) {
            onAnalyze(emailText);
        }
    };

    const handleClear = () => {
        setEmailText('');
    };

    return (
        <div style={{ padding: '0' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
                <i className="bi bi-clipboard-data" style={{ fontSize: '1.3rem', color: 'var(--accent-primary)' }}></i>
                <h4 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600 }}>Paste Raw Email</h4>
            </div>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '12px' }}>
                Copy the entire email source (headers + body) and paste below
            </p>
            <textarea
                value={emailText}
                onChange={(e) => setEmailText(e.target.value)}
                placeholder={`Paste raw email here...\n\nExample:\nFrom: sender@example.com\nTo: you@gmail.com\nSubject: Important Notice\nDate: Wed, 16 Apr 2026 09:00:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body>Email content here...</body></html>`}
                style={{
                    width: '100%',
                    minHeight: '200px',
                    padding: '16px',
                    borderRadius: '12px',
                    border: '1px solid rgba(255,255,255,0.08)',
                    background: 'rgba(0,0,0,0.3)',
                    color: 'var(--text-primary)',
                    fontFamily: '"Fira Code", "Cascadia Code", Consolas, monospace',
                    fontSize: '0.82rem',
                    lineHeight: '1.5',
                    resize: 'vertical',
                    outline: 'none',
                    transition: 'border-color 0.3s ease, box-shadow 0.3s ease',
                    boxSizing: 'border-box'
                }}
                onFocus={(e) => {
                    e.target.style.borderColor = 'var(--accent-primary)';
                    e.target.style.boxShadow = '0 0 0 3px rgba(108,92,231,0.15)';
                }}
                onBlur={(e) => {
                    e.target.style.borderColor = 'rgba(255,255,255,0.08)';
                    e.target.style.boxShadow = 'none';
                }}
            />
            <div style={{ display: 'flex', gap: '12px', marginTop: '14px', justifyContent: 'flex-end' }}>
                {emailText && (
                    <button
                        onClick={handleClear}
                        style={{
                            padding: '10px 24px',
                            borderRadius: '8px',
                            border: '1px solid rgba(255,255,255,0.1)',
                            background: 'transparent',
                            color: 'var(--text-secondary)',
                            cursor: 'pointer',
                            fontSize: '0.9rem',
                            fontWeight: 500,
                            transition: 'all 0.2s ease'
                        }}
                    >
                        <i className="bi bi-x-lg me-2"></i>Clear
                    </button>
                )}
                <button
                    onClick={handleSubmit}
                    disabled={!emailText.trim() || loading}
                    style={{
                        padding: '10px 28px',
                        borderRadius: '8px',
                        border: 'none',
                        background: emailText.trim() ? 'linear-gradient(135deg, var(--accent-primary), var(--accent-secondary))' : 'rgba(255,255,255,0.05)',
                        color: emailText.trim() ? 'white' : 'var(--text-muted)',
                        cursor: emailText.trim() ? 'pointer' : 'not-allowed',
                        fontSize: '0.9rem',
                        fontWeight: 600,
                        transition: 'all 0.3s ease',
                        boxShadow: emailText.trim() ? '0 4px 15px rgba(108,92,231,0.3)' : 'none'
                    }}
                >
                    {loading ? (
                        <><i className="bi bi-arrow-repeat me-2" style={{ animation: 'spin 1s linear infinite' }}></i>Analyzing...</>
                    ) : (
                        <><i className="bi bi-shield-check me-2"></i>Analyze Email</>
                    )}
                </button>
            </div>
        </div>
    );
}

/**
 * Executive Report Component
 * Detailed explanation of the threat score and download report feature.
 */
function ExecutiveReport({ data }) {
    const { risk_score, parsed, spf, domain_fuzz, unicode } = data;
    const level = risk_score?.band?.level || 'low';
    
    const handleDownload = async () => {
        try {
            const response = await fetch(`${API_BASE}/report`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `PhishGuard_Report_${parsed?.subject ? parsed.subject.substring(0,20) : 'Email'}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
        } catch(err) {
            console.error('Failed to download report', err);
            alert('Failed to generate report.');
        }
    };

    let summaryText = "";
    if (level === 'high') {
        summaryText = "🚨 This email exhibits multiple high-risk indicators commonly associated with phishing attacks. Do not interact with links or attachments.";
    } else if (level === 'medium') {
        summaryText = "⚠️ This email shows some suspicious traits. Proceed with caution and verify the sender's identity.";
    } else {
        summaryText = "✅ Everything is alright. This email passed standard authentication checks and does not show typical phishing characteristics.";
    }

    return (
        <div className="glass-card full-width mt-4" style={{ animation: 'fadeInUp 0.5s ease forwards' }}>
            <div className="d-flex justify-content-between align-items-center mb-4">
                <h3 className="m-0"><i className="bi bi-file-earmark-text me-2"></i>Executive Summary Report</h3>
                <button onClick={handleDownload} style={{ padding: '10px 20px', borderRadius: '8px', border: 'none', background: 'var(--accent-primary)', color: 'white', fontWeight: 600, cursor: 'pointer', boxShadow: '0 4px 15px rgba(108,92,231,0.3)', transition: 'all 0.3s ease' }}>
                    <i className="bi bi-download me-2"></i>Download PDF Report
                </button>
            </div>
            
            <p style={{ fontSize: '1.1rem', color: level === 'high' ? '#e74c3c' : level === 'medium' ? '#f39c12' : '#27ae60', fontWeight: 600 }}>
                {summaryText}
            </p>

            {level !== 'low' && (
                <div style={{ marginTop: '24px' }}>
                    <h5 className="mb-3" style={{ color: 'var(--text-secondary)' }}>Why is this a threat?</h5>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        
                        {spf && !spf.spf_pass && (
                            <div style={{ background: 'rgba(231, 76, 60, 0.1)', padding: '16px', borderRadius: '8px', borderLeft: '4px solid #e74c3c' }}>
                                <strong><i className="bi bi-shield-x me-2"></i>Authentication Failure:</strong> The email claims to be from <code>{parsed.from_domain}</code>, but it failed Sender Policy Framework (SPF) validation. This means the actual sender is unauthorized to send emails on behalf of this domain.
                            </div>
                        )}

                        {domain_fuzz && domain_fuzz.flagged && (
                            <div style={{ background: 'rgba(231, 76, 60, 0.1)', padding: '16px', borderRadius: '8px', borderLeft: '4px solid #e74c3c' }}>
                                <strong><i className="bi bi-globe me-2"></i>Domain Impersonation (Typosquatting):</strong> The sender's domain <code>{domain_fuzz.sender_domain}</code> is highly similar to the legitimate domain <code>{domain_fuzz.closest_legit_domain}</code>. The attacker is trying to trick you into thinking this is official.
                                
                                <div style={{ marginTop: '12px', padding: '12px', background: 'rgba(0,0,0,0.3)', fontFamily: '"Fira Code", monospace', borderRadius: '6px', fontSize: '0.9rem' }}>
                                    From: &lt;<span style={{ color: '#e74c3c', backgroundColor: 'rgba(231,76,60,0.2)', padding: '2px 4px', borderRadius: '4px' }}>{domain_fuzz.sender_domain}</span>&gt;
                                </div>
                            </div>
                        )}

                        {unicode && unicode.flagged && (
                            <div style={{ background: 'rgba(243, 156, 18, 0.1)', padding: '16px', borderRadius: '8px', borderLeft: '4px solid #f39c12' }}>
                                <strong><i className="bi bi-fonts me-2"></i>Visual Deception (Unicode Confusables):</strong> The attacker is using special characters from different alphabets (like Cyrillic) that look identical to regular English letters to bypass security filters.
                                {unicode.confusables_found?.slice(0, 3).map((c, i) => (
                                    <div key={i} style={{ marginTop: '12px', padding: '12px', background: 'rgba(0,0,0,0.3)', fontFamily: '"Fira Code", monospace', borderRadius: '6px', fontSize: '0.9rem' }}>
                                        Context: "...{c.context.replace(c.character, '█')}..." 
                                        <br/>
                                        <span style={{ color: '#f39c12', marginTop: '6px', display: 'inline-block' }}>Character '{c.character}' (U+{c.character.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}) looks like '{c.looks_like}'</span>
                                    </div>
                                ))}
                            </div>
                        )}
                        
                        {parsed && parsed.reply_to_mismatch && (
                            <div style={{ background: 'rgba(243, 156, 18, 0.1)', padding: '16px', borderRadius: '8px', borderLeft: '4px solid #f39c12' }}>
                                <strong><i className="bi bi-arrow-return-left me-2"></i>Reply-To Mismatch:</strong> The "From" address and "Reply-To" address do not match. If you reply to this email, it will go to <code>{parsed.reply_to}</code>, likely the attacker's actual mailbox.
                            </div>
                        )}

                    </div>
                </div>
            )}
        </div>
    );
}

// Render the App
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
