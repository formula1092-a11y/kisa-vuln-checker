import { useState, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { checklistApi } from '../services/api';
import type { ChecklistItem } from '../types';
import Modal from '../components/Modal';
import StatusBadge from '../components/StatusBadge';

function ChecklistPage() {
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [typeFilter, setTypeFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedItem, setSelectedItem] = useState<ChecklistItem | null>(null);
  const [importResult, setImportResult] = useState<{ total: number; imported: number; skipped: number; errors: string[] } | null>(null);

  const { data: items, isLoading } = useQuery({
    queryKey: ['checklist', typeFilter, severityFilter, searchTerm],
    queryFn: () => checklistApi.list({
      asset_type: typeFilter || undefined,
      severity: severityFilter || undefined,
      search: searchTerm || undefined,
    }),
  });

  const importCsvMutation = useMutation({
    mutationFn: checklistApi.importCsv,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['checklist'] });
      setImportResult(data);
    },
  });

  const importJsonMutation = useMutation({
    mutationFn: checklistApi.importJson,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['checklist'] });
      setImportResult(data);
    },
  });

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.name.endsWith('.csv')) {
      importCsvMutation.mutate(file);
    } else if (file.name.endsWith('.json')) {
      importJsonMutation.mutate(file);
    } else {
      alert('Please select a CSV or JSON file');
    }

    e.target.value = '';
  };

  const handleDownloadTemplate = async (type: 'csv' | 'json') => {
    try {
      const response = await fetch(`/api/checklist/template/${type}`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
      });

      if (type === 'csv') {
        const text = await response.text();
        const blob = new Blob([text], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'checklist_template.csv';
        a.click();
        window.URL.revokeObjectURL(url);
      } else {
        const data = await response.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'checklist_template.json';
        a.click();
        window.URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error('Download failed:', error);
    }
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Checklist Items</h1>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            accept=".csv,.json"
            style={{ display: 'none' }}
          />
          <button
            className="btn btn-primary"
            onClick={() => fileInputRef.current?.click()}
          >
            Import CSV/JSON
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => handleDownloadTemplate('csv')}
          >
            CSV Template
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => handleDownloadTemplate('json')}
          >
            JSON Template
          </button>
        </div>
      </div>

      {importResult && (
        <div className={`alert ${importResult.imported > 0 ? 'alert-success' : 'alert-error'}`}>
          <strong>Import Result:</strong> {importResult.imported} imported, {importResult.skipped} skipped out of {importResult.total}
          {importResult.errors.length > 0 && (
            <ul style={{ marginTop: '0.5rem', marginBottom: 0 }}>
              {importResult.errors.map((err, i) => (
                <li key={i}>{err}</li>
              ))}
            </ul>
          )}
          <button
            onClick={() => setImportResult(null)}
            style={{ float: 'right', background: 'none', border: 'none', cursor: 'pointer' }}
          >
            ×
          </button>
        </div>
      )}

      <div className="filters">
        <input
          type="text"
          className="form-input"
          placeholder="Search by code or title..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{ width: '250px' }}
        />
        <select
          className="form-select"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          style={{ width: '150px' }}
        >
          <option value="">All Types</option>
          <option value="windows">Windows</option>
          <option value="unix">Unix</option>
          <option value="network">Network</option>
          <option value="database">Database</option>
          <option value="web">Web</option>
        </select>
        <select
          className="form-select"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          style={{ width: '150px' }}
        >
          <option value="">All Severity</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      <div className="card">
        <div className="table-container">
          {isLoading ? (
            <div className="loading">Loading...</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Code</th>
                  <th>Title</th>
                  <th>Type</th>
                  <th>Severity</th>
                  <th>Reference</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {items?.map((item: ChecklistItem) => (
                  <tr key={item.id}>
                    <td><strong>{item.item_code}</strong></td>
                    <td style={{ maxWidth: '400px' }}>{item.title}</td>
                    <td>{item.asset_type}</td>
                    <td><StatusBadge status={item.severity} type="severity" /></td>
                    <td>{item.reference || '-'}</td>
                    <td>
                      <button
                        className="btn btn-sm btn-secondary"
                        onClick={() => setSelectedItem(item)}
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}
                {items?.length === 0 && (
                  <tr>
                    <td colSpan={6} className="empty-state">
                      No checklist items found. Import items using CSV or JSON.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <Modal
        isOpen={!!selectedItem}
        onClose={() => setSelectedItem(null)}
        title={`${selectedItem?.item_code} - ${selectedItem?.title}`}
        footer={
          <button className="btn btn-secondary" onClick={() => setSelectedItem(null)}>
            Close
          </button>
        }
      >
        {selectedItem && (
          <div>
            <div className="form-group">
              <label className="form-label">Asset Type</label>
              <p>{selectedItem.asset_type}</p>
            </div>
            <div className="form-group">
              <label className="form-label">Severity</label>
              <p><StatusBadge status={selectedItem.severity} type="severity" /></p>
            </div>
            <div className="form-group">
              <label className="form-label">Description</label>
              <p style={{ whiteSpace: 'pre-wrap' }}>{selectedItem.description || '-'}</p>
            </div>
            <div className="form-group">
              <label className="form-label">Check Method</label>
              <p style={{ whiteSpace: 'pre-wrap' }}>{selectedItem.check_method || '-'}</p>
            </div>
            <div className="form-group">
              <label className="form-label">Pass Criteria</label>
              <p style={{ whiteSpace: 'pre-wrap', color: '#166534' }}>{selectedItem.pass_criteria || '-'}</p>
            </div>
            <div className="form-group">
              <label className="form-label">Fail Criteria</label>
              <p style={{ whiteSpace: 'pre-wrap', color: '#991b1b' }}>{selectedItem.fail_criteria || '-'}</p>
            </div>
            <div className="form-group">
              <label className="form-label">Remediation</label>
              <p style={{ whiteSpace: 'pre-wrap' }}>{selectedItem.remediation || '-'}</p>
            </div>
            <div className="form-group">
              <label className="form-label">Reference</label>
              <p>{selectedItem.reference || '-'}</p>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

export default ChecklistPage;
