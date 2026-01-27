import { useState, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { assetsApi, assessmentsApi, exceptionsApi } from '../services/api';
import type { Assessment, AssessmentStatus, AssessmentUpdate } from '../types';
import Modal from '../components/Modal';
import StatusBadge from '../components/StatusBadge';

function AssetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const assetId = parseInt(id!, 10);
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [selectedAssessment, setSelectedAssessment] = useState<Assessment | null>(null);
  const [showExceptionModal, setShowExceptionModal] = useState(false);
  const [statusFilter, setStatusFilter] = useState('');

  const { data: asset, isLoading: assetLoading } = useQuery({
    queryKey: ['asset', assetId],
    queryFn: () => assetsApi.get(assetId),
  });

  const { data: assessments, isLoading: assessmentsLoading } = useQuery({
    queryKey: ['assessments', assetId, statusFilter],
    queryFn: () => assessmentsApi.list({ asset_id: assetId, status_filter: statusFilter || undefined }),
  });

  const initMutation = useMutation({
    mutationFn: () => assetsApi.initializeAssessments(assetId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assessments', assetId] });
      queryClient.invalidateQueries({ queryKey: ['asset', assetId] });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: AssessmentUpdate }) =>
      assessmentsApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assessments', assetId] });
      queryClient.invalidateQueries({ queryKey: ['asset', assetId] });
    },
  });

  const uploadMutation = useMutation({
    mutationFn: ({ id, file }: { id: number; file: File }) =>
      assessmentsApi.uploadEvidence(id, file),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['assessments', assetId] });
      setSelectedAssessment(data);
    },
  });

  const deleteEvidenceMutation = useMutation({
    mutationFn: ({ id, index }: { id: number; index: number }) =>
      assessmentsApi.deleteEvidence(id, index),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assessments', assetId] });
      if (selectedAssessment) {
        assessmentsApi.get(selectedAssessment.id).then(setSelectedAssessment);
      }
    },
  });

  const createExceptionMutation = useMutation({
    mutationFn: exceptionsApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assessments', assetId] });
      setShowExceptionModal(false);
      setSelectedAssessment(null);
    },
  });

  const handleStatusChange = (assessmentId: number, status: AssessmentStatus) => {
    updateMutation.mutate({ id: assessmentId, data: { status } });
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && selectedAssessment) {
      uploadMutation.mutate({ id: selectedAssessment.id, file });
    }
  };

  const handleSaveAssessment = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!selectedAssessment) return;

    const formData = new FormData(e.currentTarget);
    const data: AssessmentUpdate = {
      evidence_note: formData.get('evidence_note') as string || undefined,
      assessor: formData.get('assessor') as string || undefined,
      remediation_plan: formData.get('remediation_plan') as string || undefined,
      due_date: formData.get('due_date') as string || undefined,
    };
    updateMutation.mutate({ id: selectedAssessment.id, data });
    setSelectedAssessment(null);
  };

  const handleCreateException = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!selectedAssessment) return;

    const formData = new FormData(e.currentTarget);
    createExceptionMutation.mutate({
      assessment_id: selectedAssessment.id,
      reason: formData.get('reason') as string,
      expires_at: formData.get('expires_at') as string || undefined,
    });
  };

  if (assetLoading) return <div className="loading">Loading...</div>;
  if (!asset) return <div className="empty-state">Asset not found</div>;

  return (
    <div>
      <div className="page-header">
        <div>
          <Link to="/assets" style={{ fontSize: '0.875rem' }}>← Back to Assets</Link>
          <h1 className="page-title">{asset.name}</h1>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {(!assessments || assessments.length === 0) && (
            <button className="btn btn-primary" onClick={() => initMutation.mutate()}>
              Initialize Assessments
            </button>
          )}
          {assessments && assessments.some((a: Assessment) => a.status === 'fail' && a.remediation_command) && (
            <button
              className="btn btn-success"
              onClick={() => window.open(`/api/assessments/remediation-script/${assetId}`, '_blank')}
            >
              Download Fix Script
            </button>
          )}
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-value">{asset.asset_type}</div>
          <div className="stat-label">Type</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{asset.environment}</div>
          <div className="stat-label">Environment</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{asset.pass_count || 0}</div>
          <div className="stat-label">Passed</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{asset.fail_count || 0}</div>
          <div className="stat-label">Failed</div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: '1rem' }}>
        <div className="card-header">Asset Details</div>
        <div className="card-body">
          <p><strong>Owner:</strong> {asset.owner || '-'}</p>
          <p><strong>IP Address:</strong> {asset.ip_address || '-'}</p>
          <p><strong>Hostname:</strong> {asset.hostname || '-'}</p>
          <p><strong>Notes:</strong> {asset.notes || '-'}</p>
        </div>
      </div>

      <div className="card">
        <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>Assessments</span>
          <select
            className="form-select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            style={{ width: '150px' }}
          >
            <option value="">All Status</option>
            <option value="not_assessed">Not Assessed</option>
            <option value="pass">Pass</option>
            <option value="fail">Fail</option>
            <option value="na">N/A</option>
            <option value="exception">Exception</option>
          </select>
        </div>
        <div className="table-container">
          {assessmentsLoading ? (
            <div className="loading">Loading...</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Code</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {assessments?.map((assessment: Assessment) => (
                  <tr key={assessment.id}>
                    <td>{assessment.checklist_item?.item_code}</td>
                    <td style={{ maxWidth: '300px' }}>
                      {assessment.checklist_item?.title}
                    </td>
                    <td>
                      <StatusBadge status={assessment.checklist_item?.severity || 'medium'} type="severity" />
                    </td>
                    <td>
                      <select
                        className="form-select"
                        value={assessment.status}
                        onChange={(e) => handleStatusChange(assessment.id, e.target.value as AssessmentStatus)}
                        style={{ width: '130px' }}
                      >
                        <option value="not_assessed">Not Assessed</option>
                        <option value="pass">Pass</option>
                        <option value="fail">Fail</option>
                        <option value="na">N/A</option>
                        <option value="exception" disabled={!assessment.exception_approval || assessment.exception_approval.status !== 'approved'}>
                          Exception
                        </option>
                      </select>
                    </td>
                    <td>
                      <button
                        className="btn btn-sm btn-secondary"
                        onClick={() => setSelectedAssessment(assessment)}
                      >
                        Details
                      </button>
                      {' '}
                      {assessment.status === 'fail' && !assessment.exception_approval && (
                        <button
                          className="btn btn-sm btn-secondary"
                          onClick={() => {
                            setSelectedAssessment(assessment);
                            setShowExceptionModal(true);
                          }}
                        >
                          Request Exception
                        </button>
                      )}
                      {assessment.exception_approval && (
                        <StatusBadge status={assessment.exception_approval.status} type="approval" />
                      )}
                    </td>
                  </tr>
                ))}
                {assessments?.length === 0 && (
                  <tr>
                    <td colSpan={5} className="empty-state">
                      No assessments. Click "Initialize Assessments" to start.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Assessment Detail Modal */}
      <Modal
        isOpen={!!selectedAssessment && !showExceptionModal}
        onClose={() => setSelectedAssessment(null)}
        title={`${selectedAssessment?.checklist_item?.item_code} - ${selectedAssessment?.checklist_item?.title}`}
        footer={
          <>
            <button className="btn btn-secondary" onClick={() => setSelectedAssessment(null)}>
              Close
            </button>
            <button type="submit" form="assessment-form" className="btn btn-primary">
              Save
            </button>
          </>
        }
      >
        {selectedAssessment && (
          <form id="assessment-form" onSubmit={handleSaveAssessment}>
            <div className="form-group">
              <label className="form-label">Check Method</label>
              <p style={{ fontSize: '0.875rem', color: '#4b5563' }}>
                {selectedAssessment.checklist_item?.check_method || '-'}
              </p>
            </div>
            <div className="form-group">
              <label className="form-label">Pass Criteria</label>
              <p style={{ fontSize: '0.875rem', color: '#166534' }}>
                {selectedAssessment.checklist_item?.pass_criteria || '-'}
              </p>
            </div>
            <div className="form-group">
              <label className="form-label">Fail Criteria</label>
              <p style={{ fontSize: '0.875rem', color: '#991b1b' }}>
                {selectedAssessment.checklist_item?.fail_criteria || '-'}
              </p>
            </div>
            {selectedAssessment.check_command && (
              <div className="form-group">
                <label className="form-label">Check Command</label>
                <pre style={{ fontSize: '0.75rem', background: '#f3f4f6', padding: '0.5rem', borderRadius: '0.25rem', overflow: 'auto' }}>
                  {selectedAssessment.check_command}
                </pre>
              </div>
            )}
            {selectedAssessment.remediation_command && (
              <div className="form-group">
                <label className="form-label">Remediation Command</label>
                <pre style={{ fontSize: '0.75rem', background: '#fef3c7', padding: '0.5rem', borderRadius: '0.25rem', overflow: 'auto' }}>
                  {selectedAssessment.remediation_command}
                </pre>
                <button
                  type="button"
                  className="btn btn-sm btn-secondary"
                  style={{ marginTop: '0.5rem' }}
                  onClick={() => navigator.clipboard.writeText(selectedAssessment.remediation_command || '')}
                >
                  Copy Command
                </button>
              </div>
            )}
            <hr style={{ margin: '1rem 0' }} />
            <div className="form-group">
              <label className="form-label">Assessor</label>
              <input
                type="text"
                name="assessor"
                className="form-input"
                defaultValue={selectedAssessment.assessor || ''}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Evidence Note</label>
              <textarea
                name="evidence_note"
                className="form-textarea"
                defaultValue={selectedAssessment.evidence_note || ''}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Remediation Plan</label>
              <textarea
                name="remediation_plan"
                className="form-textarea"
                defaultValue={selectedAssessment.remediation_plan || ''}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Due Date</label>
              <input
                type="date"
                name="due_date"
                className="form-input"
                defaultValue={selectedAssessment.due_date?.split('T')[0] || ''}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Evidence Files</label>
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileUpload}
                style={{ display: 'none' }}
              />
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => fileInputRef.current?.click()}
              >
                Upload File
              </button>
              <div className="file-list">
                {selectedAssessment.evidence_paths?.map((path, index) => (
                  <div key={index} className="file-item">
                    <span>{path.split('/').pop()}</span>
                    <button
                      type="button"
                      className="btn btn-sm btn-danger"
                      onClick={() => deleteEvidenceMutation.mutate({ id: selectedAssessment.id, index })}
                    >
                      Delete
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </form>
        )}
      </Modal>

      {/* Exception Request Modal */}
      <Modal
        isOpen={showExceptionModal}
        onClose={() => {
          setShowExceptionModal(false);
          setSelectedAssessment(null);
        }}
        title="Request Exception"
        footer={
          <>
            <button className="btn btn-secondary" onClick={() => {
              setShowExceptionModal(false);
              setSelectedAssessment(null);
            }}>
              Cancel
            </button>
            <button type="submit" form="exception-form" className="btn btn-primary">
              Submit Request
            </button>
          </>
        }
      >
        <form id="exception-form" onSubmit={handleCreateException}>
          <div className="form-group">
            <label className="form-label">Item</label>
            <p>{selectedAssessment?.checklist_item?.item_code} - {selectedAssessment?.checklist_item?.title}</p>
          </div>
          <div className="form-group">
            <label className="form-label">Reason *</label>
            <textarea
              name="reason"
              className="form-textarea"
              required
              placeholder="Explain why this item should be exempted..."
            />
          </div>
          <div className="form-group">
            <label className="form-label">Expires At</label>
            <input
              type="date"
              name="expires_at"
              className="form-input"
            />
          </div>
        </form>
      </Modal>
    </div>
  );
}

export default AssetDetailPage;
