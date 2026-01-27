import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { assetsApi } from '../services/api';
import type { Asset, AssetCreate, AssetType, Environment, Criticality } from '../types';
import Modal from '../components/Modal';
import StatusBadge from '../components/StatusBadge';

function AssetsPage() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('');

  const { data, isLoading } = useQuery({
    queryKey: ['assets', searchTerm, typeFilter],
    queryFn: () => assetsApi.list({ search: searchTerm || undefined, asset_type: typeFilter || undefined }),
  });

  const createMutation = useMutation({
    mutationFn: assetsApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assets'] });
      setShowCreateModal(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: assetsApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assets'] });
    },
  });

  const handleCreate = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const data: AssetCreate = {
      name: formData.get('name') as string,
      asset_type: formData.get('asset_type') as AssetType,
      owner: formData.get('owner') as string || undefined,
      environment: formData.get('environment') as Environment,
      criticality: formData.get('criticality') as Criticality,
      ip_address: formData.get('ip_address') as string || undefined,
      hostname: formData.get('hostname') as string || undefined,
      notes: formData.get('notes') as string || undefined,
    };
    createMutation.mutate(data);
  };

  const handleDelete = (id: number, name: string) => {
    if (confirm(`Delete asset "${name}"?`)) {
      deleteMutation.mutate(id);
    }
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Assets</h1>
        <button className="btn btn-primary" onClick={() => setShowCreateModal(true)}>
          + New Asset
        </button>
      </div>

      <div className="filters">
        <input
          type="text"
          className="form-input"
          placeholder="Search assets..."
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
      </div>

      <div className="card">
        <div className="table-container">
          {isLoading ? (
            <div className="loading">Loading...</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Environment</th>
                  <th>Criticality</th>
                  <th>Owner</th>
                  <th>Assessments</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {data?.items.map((asset: Asset) => (
                  <tr key={asset.id}>
                    <td>
                      <Link to={`/assets/${asset.id}`}>{asset.name}</Link>
                    </td>
                    <td>{asset.asset_type}</td>
                    <td>{asset.environment}</td>
                    <td>
                      <StatusBadge status={asset.criticality} type="severity" />
                    </td>
                    <td>{asset.owner || '-'}</td>
                    <td>
                      {asset.assessment_count ? (
                        <span>
                          <span style={{ color: 'var(--success)' }}>{asset.pass_count} pass</span>
                          {' / '}
                          <span style={{ color: 'var(--danger)' }}>{asset.fail_count} fail</span>
                          {' / '}
                          {asset.assessment_count} total
                        </span>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td>
                      <Link to={`/assets/${asset.id}`} className="btn btn-sm btn-secondary">
                        View
                      </Link>
                      {' '}
                      <button
                        className="btn btn-sm btn-danger"
                        onClick={() => handleDelete(asset.id, asset.name)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
                {data?.items.length === 0 && (
                  <tr>
                    <td colSpan={7} className="empty-state">
                      No assets found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <Modal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="New Asset"
        footer={
          <>
            <button className="btn btn-secondary" onClick={() => setShowCreateModal(false)}>
              Cancel
            </button>
            <button type="submit" form="create-form" className="btn btn-primary">
              Create
            </button>
          </>
        }
      >
        <form id="create-form" onSubmit={handleCreate}>
          <div className="form-group">
            <label className="form-label">Name *</label>
            <input type="text" name="name" className="form-input" required />
          </div>
          <div className="form-group">
            <label className="form-label">Type *</label>
            <select name="asset_type" className="form-select" required>
              <option value="windows">Windows</option>
              <option value="unix">Unix</option>
              <option value="network">Network</option>
              <option value="database">Database</option>
              <option value="web">Web</option>
              <option value="other">Other</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Environment</label>
            <select name="environment" className="form-select">
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="development">Development</option>
              <option value="test">Test</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Criticality</label>
            <select name="criticality" className="form-select">
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Owner</label>
            <input type="text" name="owner" className="form-input" />
          </div>
          <div className="form-group">
            <label className="form-label">IP Address</label>
            <input type="text" name="ip_address" className="form-input" />
          </div>
          <div className="form-group">
            <label className="form-label">Hostname</label>
            <input type="text" name="hostname" className="form-input" />
          </div>
          <div className="form-group">
            <label className="form-label">Notes</label>
            <textarea name="notes" className="form-textarea" />
          </div>
        </form>
      </Modal>
    </div>
  );
}

export default AssetsPage;
