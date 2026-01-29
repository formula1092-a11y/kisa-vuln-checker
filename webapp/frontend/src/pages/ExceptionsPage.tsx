import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { exceptionsApi } from '../services/api';
import type { ExceptionWithAssessment, ExceptionDecision } from '../types';
import { useAuth } from '../hooks/useAuth';
import Modal from '../components/Modal';
import StatusBadge from '../components/StatusBadge';

function ExceptionsPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState('pending');
  const [selectedItem, setSelectedItem] = useState<ExceptionWithAssessment | null>(null);

  const { data: exceptions, isLoading } = useQuery({
    queryKey: ['exceptions', statusFilter],
    queryFn: () => exceptionsApi.list({ status_filter: statusFilter || undefined }),
  });

  const decideMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: ExceptionDecision }) =>
      exceptionsApi.decide(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['exceptions'] });
      setSelectedItem(null);
    },
  });

  const handleDecide = (status: 'approved' | 'rejected') => {
    if (!selectedItem) return;

    const note = (document.getElementById('decision_note') as HTMLTextAreaElement)?.value;
    decideMutation.mutate({
      id: selectedItem.id,
      data: { status, decision_note: note || undefined },
    });
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleDateString();
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Exception Approvals</h1>
      </div>

      <div className="tabs">
        <button
          className={`tab ${statusFilter === 'pending' ? 'active' : ''}`}
          onClick={() => setStatusFilter('pending')}
        >
          Pending
        </button>
        <button
          className={`tab ${statusFilter === 'approved' ? 'active' : ''}`}
          onClick={() => setStatusFilter('approved')}
        >
          Approved
        </button>
        <button
          className={`tab ${statusFilter === 'rejected' ? 'active' : ''}`}
          onClick={() => setStatusFilter('rejected')}
        >
          Rejected
        </button>
        <button
          className={`tab ${statusFilter === '' ? 'active' : ''}`}
          onClick={() => setStatusFilter('')}
        >
          All
        </button>
      </div>

      <div className="card">
        <div className="table-container">
          {isLoading ? (
            <div className="loading">Loading...</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>Item</th>
                  <th>Reason</th>
                  <th>Requested By</th>
                  <th>Status</th>
                  <th>Expires</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {exceptions?.map((item: ExceptionWithAssessment) => (
                  <tr key={item.id}>
                    <td>
                      <Link to={`/assets/${item.asset_id}`}>{item.asset_name}</Link>
                    </td>
                    <td>
                      <strong>{item.checklist_item_code}</strong>
                      <br />
                      <span style={{ fontSize: '0.75rem', color: '#6b7280' }}>
                        {item.checklist_item_title?.substring(0, 50)}...
                      </span>
                    </td>
                    <td style={{ maxWidth: '200px' }}>
                      {item.reason.substring(0, 100)}{item.reason.length > 100 ? '...' : ''}
                    </td>
                    <td>{item.requested_by}</td>
                    <td>
                      <StatusBadge status={item.status} type="approval" />
                    </td>
                    <td>{formatDate(item.expires_at)}</td>
                    <td>
                      <button
                        className="btn btn-sm btn-secondary"
                        onClick={() => setSelectedItem(item)}
                      >
                        {item.status === 'pending' && user?.role === 'admin' ? 'Review' : 'View'}
                      </button>
                    </td>
                  </tr>
                ))}
                {exceptions?.length === 0 && (
                  <tr>
                    <td colSpan={7} className="empty-state">
                      No exception requests found
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
        title="Exception Request"
        footer={
          selectedItem?.status === 'pending' && user?.role === 'admin' ? (
            <>
              <button className="btn btn-secondary" onClick={() => setSelectedItem(null)}>
                Cancel
              </button>
              <button className="btn btn-danger" onClick={() => handleDecide('rejected')}>
                Reject
              </button>
              <button className="btn btn-success" onClick={() => handleDecide('approved')}>
                Approve
              </button>
            </>
          ) : (
            <button className="btn btn-secondary" onClick={() => setSelectedItem(null)}>
              Close
            </button>
          )
        }
      >
        {selectedItem && (
          <div>
            <div className="form-group">
              <label className="form-label">Asset</label>
              <p>{selectedItem.asset_name}</p>
            </div>
            <div className="form-group">
              <label className="form-label">Item</label>
              <p>
                <strong>{selectedItem.checklist_item_code}</strong> - {selectedItem.checklist_item_title}
              </p>
            </div>
            <div className="form-group">
              <label className="form-label">Reason</label>
              <p style={{ whiteSpace: 'pre-wrap' }}>{selectedItem.reason}</p>
            </div>
            <div className="form-group">
              <label className="form-label">Requested By</label>
              <p>{selectedItem.requested_by} on {formatDate(selectedItem.created_at)}</p>
            </div>
            <div className="form-group">
              <label className="form-label">Expires At</label>
              <p>{formatDate(selectedItem.expires_at)}</p>
            </div>
            <div className="form-group">
              <label className="form-label">Status</label>
              <p>
                <StatusBadge status={selectedItem.status} type="approval" />
                {selectedItem.approver && (
                  <span> by {selectedItem.approver} on {formatDate(selectedItem.decided_at)}</span>
                )}
              </p>
            </div>
            {selectedItem.decision_note && (
              <div className="form-group">
                <label className="form-label">Decision Note</label>
                <p>{selectedItem.decision_note}</p>
              </div>
            )}
            {selectedItem.status === 'pending' && user?.role === 'admin' && (
              <div className="form-group">
                <label className="form-label">Decision Note (Optional)</label>
                <textarea
                  id="decision_note"
                  className="form-textarea"
                  placeholder="Add a note about your decision..."
                />
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}

export default ExceptionsPage;
