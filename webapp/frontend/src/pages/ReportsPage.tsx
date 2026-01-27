import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { reportsApi, assetsApi } from '../services/api';
import type { ReportSummary, Asset } from '../types';
import StatusBadge from '../components/StatusBadge';

function ReportsPage() {
  const [selectedAssetId, setSelectedAssetId] = useState<number | undefined>(undefined);
  const [downloading, setDownloading] = useState(false);

  const { data: assets } = useQuery({
    queryKey: ['assets-list'],
    queryFn: () => assetsApi.list({ size: 100 }),
  });

  const { data: report, isLoading } = useQuery({
    queryKey: ['report', selectedAssetId],
    queryFn: () => reportsApi.getSummary({ asset_id: selectedAssetId }),
  });

  const handleDownloadPdf = async () => {
    setDownloading(true);
    try {
      const blob = await reportsApi.downloadPdf({ asset_id: selectedAssetId });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnerability_report_${new Date().toISOString().split('T')[0]}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Download failed:', error);
    } finally {
      setDownloading(false);
    }
  };

  const handleDownloadCsv = async () => {
    setDownloading(true);
    try {
      const blob = await reportsApi.downloadCsv({ asset_id: selectedAssetId });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnerability_report_${new Date().toISOString().split('T')[0]}.csv`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Download failed:', error);
    } finally {
      setDownloading(false);
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleDateString();
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Reports</h1>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            className="btn btn-primary"
            onClick={handleDownloadPdf}
            disabled={downloading}
          >
            {downloading ? 'Downloading...' : 'Download PDF'}
          </button>
          <button
            className="btn btn-secondary"
            onClick={handleDownloadCsv}
            disabled={downloading}
          >
            Download CSV
          </button>
        </div>
      </div>

      <div className="filters">
        <div className="filter-group">
          <label>Filter by Asset:</label>
          <select
            className="form-select"
            value={selectedAssetId || ''}
            onChange={(e) => setSelectedAssetId(e.target.value ? parseInt(e.target.value) : undefined)}
            style={{ width: '250px' }}
          >
            <option value="">All Assets</option>
            {assets?.items.map((asset: Asset) => (
              <option key={asset.id} value={asset.id}>{asset.name}</option>
            ))}
          </select>
        </div>
      </div>

      {isLoading ? (
        <div className="loading">Loading report...</div>
      ) : report ? (
        <>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-value">{report.total_assets}</div>
              <div className="stat-label">Total Assets</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{report.total_items_checked}</div>
              <div className="stat-label">Items Checked</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: report.overall_compliance_rate >= 80 ? 'var(--success)' : 'var(--danger)' }}>
                {report.overall_compliance_rate}%
              </div>
              <div className="stat-label">Compliance Rate</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--danger)' }}>
                {report.vulnerable_items.length}
              </div>
              <div className="stat-label">Vulnerabilities</div>
            </div>
          </div>

          {/* Asset Summaries */}
          <div className="card" style={{ marginBottom: '1rem' }}>
            <div className="card-header">Asset Summary</div>
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th>Type</th>
                    <th>Total</th>
                    <th>Pass</th>
                    <th>Fail</th>
                    <th>Exception</th>
                    <th>Compliance</th>
                  </tr>
                </thead>
                <tbody>
                  {report.asset_summaries.map((summary) => (
                    <tr key={summary.asset_id}>
                      <td>{summary.asset_name}</td>
                      <td>{summary.asset_type}</td>
                      <td>{summary.total_items}</td>
                      <td style={{ color: 'var(--success)' }}>{summary.passed}</td>
                      <td style={{ color: 'var(--danger)' }}>{summary.failed}</td>
                      <td style={{ color: 'var(--warning)' }}>{summary.exceptions}</td>
                      <td>
                        <span style={{ color: summary.compliance_rate >= 80 ? 'var(--success)' : 'var(--danger)' }}>
                          {summary.compliance_rate}%
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Vulnerable Items */}
          <div className="card" style={{ marginBottom: '1rem' }}>
            <div className="card-header" style={{ color: 'var(--danger)' }}>
              Vulnerable Items ({report.vulnerable_items.length})
            </div>
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th>Code</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Assessor</th>
                    <th>Due Date</th>
                  </tr>
                </thead>
                <tbody>
                  {report.vulnerable_items.map((item, index) => (
                    <tr key={index}>
                      <td>{item.asset_name}</td>
                      <td>{item.item_code}</td>
                      <td>{item.title.substring(0, 60)}{item.title.length > 60 ? '...' : ''}</td>
                      <td><StatusBadge status={item.severity} type="severity" /></td>
                      <td>{item.assessor || '-'}</td>
                      <td>{formatDate(item.due_date)}</td>
                    </tr>
                  ))}
                  {report.vulnerable_items.length === 0 && (
                    <tr>
                      <td colSpan={6} className="empty-state">No vulnerabilities found</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Exception Items */}
          <div className="card">
            <div className="card-header" style={{ color: 'var(--warning)' }}>
              Exception Items ({report.exception_items.length})
            </div>
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th>Code</th>
                    <th>Reason</th>
                    <th>Status</th>
                    <th>Approver</th>
                    <th>Expires</th>
                  </tr>
                </thead>
                <tbody>
                  {report.exception_items.map((item, index) => (
                    <tr key={index}>
                      <td>{item.asset_name}</td>
                      <td>{item.item_code}</td>
                      <td>{item.reason.substring(0, 50)}{item.reason.length > 50 ? '...' : ''}</td>
                      <td><StatusBadge status={item.status} type="approval" /></td>
                      <td>{item.approver || '-'}</td>
                      <td>{formatDate(item.expires_at)}</td>
                    </tr>
                  ))}
                  {report.exception_items.length === 0 && (
                    <tr>
                      <td colSpan={6} className="empty-state">No exceptions</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
}

export default ReportsPage;
