import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import type { ReportSummary } from '../types';

export default function DashboardPage() {
  const [summary, setSummary] = useState<ReportSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchSummary = async () => {
      try {
        setLoading(true);
        const response = await api.get<ReportSummary>('/reports/summary');
        setSummary(response.data);
        setError(null);
      } catch (err: any) {
        setError(err.response?.data?.detail || 'Failed to fetch dashboard data');
      } finally {
        setLoading(false);
      }
    };

    fetchSummary();
  }, []);

  const getStatusCounts = () => {
    if (!summary) return { passed: 0, failed: 0, na: 0, exceptions: 0, not_assessed: 0 };

    return summary.asset_summaries.reduce(
      (acc, asset) => ({
        passed: acc.passed + asset.passed,
        failed: acc.failed + asset.failed,
        na: acc.na + asset.na,
        exceptions: acc.exceptions + asset.exceptions,
        not_assessed: acc.not_assessed + asset.not_assessed,
      }),
      { passed: 0, failed: 0, na: 0, exceptions: 0, not_assessed: 0 }
    );
  };

  const statusCounts = getStatusCounts();
  const totalItems = statusCounts.passed + statusCounts.failed + statusCounts.na +
                     statusCounts.exceptions + statusCounts.not_assessed;

  const getStatusPercentage = (count: number) => {
    if (totalItems === 0) return 0;
    return Math.round((count / totalItems) * 100);
  };

  if (loading) {
    return <div className="loading">Loading dashboard...</div>;
  }

  if (error) {
    return <div className="error">{error}</div>;
  }

  return (
    <div className="dashboard-page">
      <div className="page-header">
        <h1>Dashboard</h1>
        <p className="subtitle">
          Last updated: {summary ? new Date(summary.generated_at).toLocaleString('ko-KR') : '-'}
        </p>
      </div>

      {/* Summary Cards */}
      <div className="summary-cards">
        <div className="card total-assets">
          <div className="card-icon">&#128187;</div>
          <div className="card-content">
            <span className="card-value">{summary?.total_assets || 0}</span>
            <span className="card-label">Total Assets</span>
          </div>
        </div>
        <div className="card compliance-rate">
          <div className="card-icon">&#9989;</div>
          <div className="card-content">
            <span className="card-value">{summary?.overall_compliance_rate || 0}%</span>
            <span className="card-label">Compliance Rate</span>
          </div>
        </div>
        <div className="card items-checked">
          <div className="card-icon">&#128203;</div>
          <div className="card-content">
            <span className="card-value">{summary?.total_items_checked || 0}</span>
            <span className="card-label">Items Checked</span>
          </div>
        </div>
        <div className="card vulnerabilities">
          <div className="card-icon">&#9888;</div>
          <div className="card-content">
            <span className="card-value">{summary?.vulnerable_items.length || 0}</span>
            <span className="card-label">Vulnerabilities</span>
          </div>
        </div>
      </div>

      {/* Status Distribution */}
      <div className="section status-section">
        <h2>Assessment Status Distribution</h2>
        <div className="status-chart">
          <div className="status-bar">
            {statusCounts.passed > 0 && (
              <div
                className="bar-segment pass"
                style={{ width: `${getStatusPercentage(statusCounts.passed)}%` }}
                title={`Pass: ${statusCounts.passed}`}
              />
            )}
            {statusCounts.failed > 0 && (
              <div
                className="bar-segment fail"
                style={{ width: `${getStatusPercentage(statusCounts.failed)}%` }}
                title={`Fail: ${statusCounts.failed}`}
              />
            )}
            {statusCounts.na > 0 && (
              <div
                className="bar-segment na"
                style={{ width: `${getStatusPercentage(statusCounts.na)}%` }}
                title={`N/A: ${statusCounts.na}`}
              />
            )}
            {statusCounts.exceptions > 0 && (
              <div
                className="bar-segment exception"
                style={{ width: `${getStatusPercentage(statusCounts.exceptions)}%` }}
                title={`Exception: ${statusCounts.exceptions}`}
              />
            )}
            {statusCounts.not_assessed > 0 && (
              <div
                className="bar-segment not-assessed"
                style={{ width: `${getStatusPercentage(statusCounts.not_assessed)}%` }}
                title={`Not Assessed: ${statusCounts.not_assessed}`}
              />
            )}
          </div>
          <div className="status-legend">
            <div className="legend-item">
              <span className="legend-color pass"></span>
              <span>Pass ({statusCounts.passed})</span>
            </div>
            <div className="legend-item">
              <span className="legend-color fail"></span>
              <span>Fail ({statusCounts.failed})</span>
            </div>
            <div className="legend-item">
              <span className="legend-color na"></span>
              <span>N/A ({statusCounts.na})</span>
            </div>
            <div className="legend-item">
              <span className="legend-color exception"></span>
              <span>Exception ({statusCounts.exceptions})</span>
            </div>
            <div className="legend-item">
              <span className="legend-color not-assessed"></span>
              <span>Not Assessed ({statusCounts.not_assessed})</span>
            </div>
          </div>
        </div>
      </div>

      {/* Asset Summary Table */}
      <div className="section">
        <h2>Asset Summary</h2>
        {summary?.asset_summaries.length === 0 ? (
          <div className="empty-state">
            <p>No assets registered yet.</p>
            <Link to="/assets" className="btn-primary">Add Assets</Link>
          </div>
        ) : (
          <table className="asset-table">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Type</th>
                <th>Total</th>
                <th>Pass</th>
                <th>Fail</th>
                <th>N/A</th>
                <th>Exception</th>
                <th>Compliance</th>
              </tr>
            </thead>
            <tbody>
              {summary?.asset_summaries.map((asset) => (
                <tr key={asset.asset_id}>
                  <td>
                    <Link to={`/assets/${asset.asset_id}`}>{asset.asset_name}</Link>
                  </td>
                  <td>
                    <span className={`type-badge ${asset.asset_type}`}>
                      {asset.asset_type}
                    </span>
                  </td>
                  <td>{asset.total_items}</td>
                  <td className="pass">{asset.passed}</td>
                  <td className="fail">{asset.failed}</td>
                  <td>{asset.na}</td>
                  <td>{asset.exceptions}</td>
                  <td>
                    <div className="compliance-bar-container">
                      <div
                        className="compliance-bar"
                        style={{ width: `${asset.compliance_rate}%` }}
                      />
                      <span className="compliance-text">{asset.compliance_rate}%</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Vulnerabilities */}
      {summary && summary.vulnerable_items.length > 0 && (
        <div className="section">
          <h2>Recent Vulnerabilities (Top 10)</h2>
          <table className="vuln-table">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Code</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Due Date</th>
              </tr>
            </thead>
            <tbody>
              {summary.vulnerable_items.slice(0, 10).map((item, idx) => (
                <tr key={idx}>
                  <td>{item.asset_name}</td>
                  <td><code>{item.item_code}</code></td>
                  <td>{item.title}</td>
                  <td>
                    <span className={`severity-badge ${item.severity}`}>
                      {item.severity}
                    </span>
                  </td>
                  <td>{item.due_date || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {summary.vulnerable_items.length > 10 && (
            <p className="more-link">
              <Link to="/reports">View all {summary.vulnerable_items.length} vulnerabilities</Link>
            </p>
          )}
        </div>
      )}

      {/* Pending Exceptions */}
      {summary && summary.exception_items.filter(e => e.status === 'pending').length > 0 && (
        <div className="section">
          <h2>Pending Exception Requests</h2>
          <table className="exception-table">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Code</th>
                <th>Title</th>
                <th>Requested By</th>
                <th>Expires At</th>
              </tr>
            </thead>
            <tbody>
              {summary.exception_items
                .filter(e => e.status === 'pending')
                .slice(0, 5)
                .map((item, idx) => (
                  <tr key={idx}>
                    <td>{item.asset_name}</td>
                    <td><code>{item.item_code}</code></td>
                    <td>{item.title}</td>
                    <td>{item.requested_by}</td>
                    <td>{item.expires_at || '-'}</td>
                  </tr>
                ))}
            </tbody>
          </table>
          <p className="more-link">
            <Link to="/exceptions">Manage Exceptions</Link>
          </p>
        </div>
      )}

      <style>{`
        .dashboard-page {
          padding: 20px;
        }
        .page-header {
          margin-bottom: 20px;
        }
        .page-header h1 {
          margin: 0 0 5px 0;
        }
        .subtitle {
          color: #666;
          margin: 0;
        }
        .summary-cards {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 20px;
          margin-bottom: 30px;
        }
        .card {
          background: white;
          border-radius: 8px;
          padding: 20px;
          display: flex;
          align-items: center;
          gap: 15px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .card-icon {
          font-size: 32px;
        }
        .card-content {
          display: flex;
          flex-direction: column;
        }
        .card-value {
          font-size: 28px;
          font-weight: 700;
        }
        .card-label {
          color: #666;
          font-size: 14px;
        }
        .total-assets { border-left: 4px solid #1976d2; }
        .compliance-rate { border-left: 4px solid #4caf50; }
        .items-checked { border-left: 4px solid #ff9800; }
        .vulnerabilities { border-left: 4px solid #f44336; }

        .section {
          background: white;
          border-radius: 8px;
          padding: 20px;
          margin-bottom: 20px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 {
          margin: 0 0 15px 0;
          font-size: 18px;
        }

        .status-bar {
          display: flex;
          height: 24px;
          border-radius: 4px;
          overflow: hidden;
          background: #e0e0e0;
        }
        .bar-segment {
          transition: width 0.3s;
        }
        .bar-segment.pass { background: #4caf50; }
        .bar-segment.fail { background: #f44336; }
        .bar-segment.na { background: #9e9e9e; }
        .bar-segment.exception { background: #ff9800; }
        .bar-segment.not-assessed { background: #e0e0e0; }

        .status-legend {
          display: flex;
          flex-wrap: wrap;
          gap: 15px;
          margin-top: 10px;
        }
        .legend-item {
          display: flex;
          align-items: center;
          gap: 5px;
          font-size: 14px;
        }
        .legend-color {
          width: 12px;
          height: 12px;
          border-radius: 2px;
        }
        .legend-color.pass { background: #4caf50; }
        .legend-color.fail { background: #f44336; }
        .legend-color.na { background: #9e9e9e; }
        .legend-color.exception { background: #ff9800; }
        .legend-color.not-assessed { background: #e0e0e0; }

        .asset-table, .vuln-table, .exception-table {
          width: 100%;
          border-collapse: collapse;
        }
        .asset-table th, .asset-table td,
        .vuln-table th, .vuln-table td,
        .exception-table th, .exception-table td {
          padding: 10px;
          text-align: left;
          border-bottom: 1px solid #eee;
        }
        .asset-table th, .vuln-table th, .exception-table th {
          background: #f8f9fa;
          font-weight: 600;
        }
        .asset-table a, .more-link a {
          color: #1976d2;
          text-decoration: none;
        }
        .asset-table a:hover, .more-link a:hover {
          text-decoration: underline;
        }
        .pass { color: #4caf50; }
        .fail { color: #f44336; }

        .type-badge {
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 12px;
          background: #e3f2fd;
          color: #1565c0;
        }

        .compliance-bar-container {
          position: relative;
          width: 100px;
          height: 20px;
          background: #e0e0e0;
          border-radius: 4px;
          overflow: hidden;
        }
        .compliance-bar {
          position: absolute;
          top: 0;
          left: 0;
          height: 100%;
          background: #4caf50;
          transition: width 0.3s;
        }
        .compliance-text {
          position: absolute;
          width: 100%;
          text-align: center;
          line-height: 20px;
          font-size: 12px;
          font-weight: 600;
          color: #333;
        }

        .severity-badge {
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 12px;
        }
        .severity-badge.high {
          background: #ffebee;
          color: #c62828;
        }
        .severity-badge.medium {
          background: #fff3e0;
          color: #ef6c00;
        }
        .severity-badge.low {
          background: #e8f5e9;
          color: #2e7d32;
        }

        .empty-state {
          text-align: center;
          padding: 40px;
          color: #666;
        }
        .btn-primary {
          display: inline-block;
          background: #1976d2;
          color: white;
          padding: 8px 16px;
          border-radius: 4px;
          text-decoration: none;
          margin-top: 10px;
        }
        .more-link {
          text-align: center;
          margin-top: 10px;
        }
        code {
          background: #f5f5f5;
          padding: 2px 6px;
          border-radius: 4px;
          font-family: monospace;
        }
        .loading, .error {
          text-align: center;
          padding: 40px;
        }
        .error {
          color: #c62828;
        }
      `}</style>
    </div>
  );
}
