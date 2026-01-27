import { useState, useEffect } from 'react';
import { useAuth } from '../hooks/useAuth';
import api from '../services/api';
import type { UserProfile, UserCreate, UserUpdate, PasswordReset, PaginatedResponse } from '../types';
import Modal from '../components/Modal';

const ROLES = [
  { value: 'admin', label: 'Administrator' },
  { value: 'auditor', label: 'Auditor' },
  { value: 'user', label: 'User' },
];

export default function UsersPage() {
  const { user } = useAuth();
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Modal states
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState<UserProfile | null>(null);

  // Form states
  const [createForm, setCreateForm] = useState<UserCreate>({
    username: '',
    password: '',
    email: '',
    full_name: '',
    role: 'user',
  });
  const [editForm, setEditForm] = useState<UserUpdate>({});
  const [passwordForm, setPasswordForm] = useState<PasswordReset>({ new_password: '' });

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams({
        page: page.toString(),
        size: '20',
      });
      if (search) params.set('search', search);
      if (roleFilter) params.set('role', roleFilter);

      const response = await api.get<PaginatedResponse<UserProfile>>(`/users?${params}`);
      setUsers(response.data.items);
      setTotal(response.data.total);
      setError(null);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to fetch users');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, [page, search, roleFilter]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.post('/users', createForm);
      setShowCreateModal(false);
      setCreateForm({ username: '', password: '', email: '', full_name: '', role: 'user' });
      fetchUsers();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create user');
    }
  };

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedUser) return;
    try {
      await api.put(`/users/${selectedUser.id}`, editForm);
      setShowEditModal(false);
      setSelectedUser(null);
      fetchUsers();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to update user');
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedUser) return;
    try {
      await api.post(`/users/${selectedUser.id}/reset-password`, passwordForm);
      setShowPasswordModal(false);
      setSelectedUser(null);
      setPasswordForm({ new_password: '' });
      alert('Password reset successfully');
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to reset password');
    }
  };

  const handleDelete = async (userId: number, username: string) => {
    if (!confirm(`Delete user "${username}"?`)) return;
    try {
      await api.delete(`/users/${userId}`);
      fetchUsers();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to delete user');
    }
  };

  const openEditModal = (u: UserProfile) => {
    setSelectedUser(u);
    setEditForm({
      email: u.email || '',
      full_name: u.full_name || '',
      role: u.role,
      is_active: u.is_active,
    });
    setShowEditModal(true);
  };

  const openPasswordModal = (u: UserProfile) => {
    setSelectedUser(u);
    setPasswordForm({ new_password: '' });
    setShowPasswordModal(true);
  };

  if (user?.role !== 'admin') {
    return (
      <div className="error-container">
        <h2>Access Denied</h2>
        <p>Admin access required to manage users.</p>
      </div>
    );
  }

  return (
    <div className="users-page">
      <div className="page-header">
        <h1>User Management</h1>
        <button className="btn-primary" onClick={() => setShowCreateModal(true)}>
          + New User
        </button>
      </div>

      <div className="filters">
        <input
          type="text"
          placeholder="Search users..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="search-input"
        />
        <select
          value={roleFilter}
          onChange={(e) => setRoleFilter(e.target.value)}
          className="role-filter"
        >
          <option value="">All Roles</option>
          {ROLES.map((r) => (
            <option key={r.value} value={r.value}>{r.label}</option>
          ))}
        </select>
      </div>

      {loading ? (
        <div className="loading">Loading...</div>
      ) : error ? (
        <div className="error">{error}</div>
      ) : (
        <>
          <table className="users-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Full Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Last Login</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td>{u.username}</td>
                  <td>{u.full_name || '-'}</td>
                  <td>{u.email || '-'}</td>
                  <td>
                    <span className={`role-badge role-${u.role}`}>
                      {ROLES.find(r => r.value === u.role)?.label || u.role}
                    </span>
                  </td>
                  <td>
                    <span className={`status-badge ${u.is_active ? 'active' : 'inactive'}`}>
                      {u.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td>
                    {u.last_login
                      ? new Date(u.last_login).toLocaleString('ko-KR')
                      : 'Never'
                    }
                  </td>
                  <td className="actions">
                    <button
                      className="btn-sm btn-edit"
                      onClick={() => openEditModal(u)}
                    >
                      Edit
                    </button>
                    <button
                      className="btn-sm btn-password"
                      onClick={() => openPasswordModal(u)}
                    >
                      Reset PW
                    </button>
                    {u.username !== user?.username && (
                      <button
                        className="btn-sm btn-delete"
                        onClick={() => handleDelete(u.id, u.username)}
                      >
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="pagination">
            <span>Total: {total} users</span>
            <div className="pagination-controls">
              <button
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
              >
                Prev
              </button>
              <span>Page {page}</span>
              <button
                disabled={users.length < 20}
                onClick={() => setPage(page + 1)}
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}

      {/* Create User Modal */}
      <Modal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Create New User"
      >
        <form onSubmit={handleCreate} className="user-form">
          <div className="form-group">
            <label>Username *</label>
            <input
              type="text"
              value={createForm.username}
              onChange={(e) => setCreateForm({ ...createForm, username: e.target.value })}
              required
              minLength={3}
            />
          </div>
          <div className="form-group">
            <label>Password *</label>
            <input
              type="password"
              value={createForm.password}
              onChange={(e) => setCreateForm({ ...createForm, password: e.target.value })}
              required
              minLength={6}
            />
          </div>
          <div className="form-group">
            <label>Full Name</label>
            <input
              type="text"
              value={createForm.full_name || ''}
              onChange={(e) => setCreateForm({ ...createForm, full_name: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label>Email</label>
            <input
              type="email"
              value={createForm.email || ''}
              onChange={(e) => setCreateForm({ ...createForm, email: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label>Role</label>
            <select
              value={createForm.role}
              onChange={(e) => setCreateForm({ ...createForm, role: e.target.value as any })}
            >
              {ROLES.map((r) => (
                <option key={r.value} value={r.value}>{r.label}</option>
              ))}
            </select>
          </div>
          <div className="form-actions">
            <button type="button" className="btn-cancel" onClick={() => setShowCreateModal(false)}>
              Cancel
            </button>
            <button type="submit" className="btn-primary">
              Create User
            </button>
          </div>
        </form>
      </Modal>

      {/* Edit User Modal */}
      <Modal
        isOpen={showEditModal}
        onClose={() => setShowEditModal(false)}
        title={`Edit User: ${selectedUser?.username}`}
      >
        <form onSubmit={handleEdit} className="user-form">
          <div className="form-group">
            <label>Full Name</label>
            <input
              type="text"
              value={editForm.full_name || ''}
              onChange={(e) => setEditForm({ ...editForm, full_name: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label>Email</label>
            <input
              type="email"
              value={editForm.email || ''}
              onChange={(e) => setEditForm({ ...editForm, email: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label>Role</label>
            <select
              value={editForm.role}
              onChange={(e) => setEditForm({ ...editForm, role: e.target.value as any })}
            >
              {ROLES.map((r) => (
                <option key={r.value} value={r.value}>{r.label}</option>
              ))}
            </select>
          </div>
          <div className="form-group checkbox">
            <label>
              <input
                type="checkbox"
                checked={editForm.is_active}
                onChange={(e) => setEditForm({ ...editForm, is_active: e.target.checked })}
              />
              Active
            </label>
          </div>
          <div className="form-actions">
            <button type="button" className="btn-cancel" onClick={() => setShowEditModal(false)}>
              Cancel
            </button>
            <button type="submit" className="btn-primary">
              Save Changes
            </button>
          </div>
        </form>
      </Modal>

      {/* Reset Password Modal */}
      <Modal
        isOpen={showPasswordModal}
        onClose={() => setShowPasswordModal(false)}
        title={`Reset Password: ${selectedUser?.username}`}
      >
        <form onSubmit={handleResetPassword} className="user-form">
          <div className="form-group">
            <label>New Password *</label>
            <input
              type="password"
              value={passwordForm.new_password}
              onChange={(e) => setPasswordForm({ new_password: e.target.value })}
              required
              minLength={6}
            />
          </div>
          <div className="form-actions">
            <button type="button" className="btn-cancel" onClick={() => setShowPasswordModal(false)}>
              Cancel
            </button>
            <button type="submit" className="btn-primary">
              Reset Password
            </button>
          </div>
        </form>
      </Modal>

      <style>{`
        .users-page {
          padding: 20px;
        }
        .page-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
        }
        .page-header h1 {
          margin: 0;
        }
        .filters {
          display: flex;
          gap: 10px;
          margin-bottom: 20px;
        }
        .search-input {
          padding: 8px 12px;
          border: 1px solid #ddd;
          border-radius: 4px;
          width: 250px;
        }
        .role-filter {
          padding: 8px 12px;
          border: 1px solid #ddd;
          border-radius: 4px;
        }
        .users-table {
          width: 100%;
          border-collapse: collapse;
          margin-bottom: 20px;
        }
        .users-table th,
        .users-table td {
          padding: 12px;
          text-align: left;
          border-bottom: 1px solid #eee;
        }
        .users-table th {
          background: #f8f9fa;
          font-weight: 600;
        }
        .role-badge {
          padding: 4px 8px;
          border-radius: 4px;
          font-size: 12px;
          font-weight: 500;
        }
        .role-admin {
          background: #e3f2fd;
          color: #1565c0;
        }
        .role-auditor {
          background: #fff3e0;
          color: #ef6c00;
        }
        .role-user {
          background: #e8f5e9;
          color: #2e7d32;
        }
        .status-badge {
          padding: 4px 8px;
          border-radius: 4px;
          font-size: 12px;
        }
        .status-badge.active {
          background: #e8f5e9;
          color: #2e7d32;
        }
        .status-badge.inactive {
          background: #ffebee;
          color: #c62828;
        }
        .actions {
          display: flex;
          gap: 5px;
        }
        .btn-sm {
          padding: 4px 8px;
          border: none;
          border-radius: 4px;
          cursor: pointer;
          font-size: 12px;
        }
        .btn-edit {
          background: #e3f2fd;
          color: #1565c0;
        }
        .btn-password {
          background: #fff3e0;
          color: #ef6c00;
        }
        .btn-delete {
          background: #ffebee;
          color: #c62828;
        }
        .btn-primary {
          background: #1976d2;
          color: white;
          border: none;
          padding: 8px 16px;
          border-radius: 4px;
          cursor: pointer;
        }
        .btn-cancel {
          background: #f5f5f5;
          color: #333;
          border: none;
          padding: 8px 16px;
          border-radius: 4px;
          cursor: pointer;
        }
        .pagination {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .pagination-controls {
          display: flex;
          gap: 10px;
          align-items: center;
        }
        .pagination button {
          padding: 6px 12px;
          border: 1px solid #ddd;
          background: white;
          border-radius: 4px;
          cursor: pointer;
        }
        .pagination button:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }
        .user-form {
          display: flex;
          flex-direction: column;
          gap: 15px;
        }
        .form-group {
          display: flex;
          flex-direction: column;
          gap: 5px;
        }
        .form-group.checkbox {
          flex-direction: row;
          align-items: center;
        }
        .form-group.checkbox label {
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .form-group label {
          font-weight: 500;
        }
        .form-group input,
        .form-group select {
          padding: 8px 12px;
          border: 1px solid #ddd;
          border-radius: 4px;
        }
        .form-actions {
          display: flex;
          justify-content: flex-end;
          gap: 10px;
          margin-top: 10px;
        }
        .error-container {
          text-align: center;
          padding: 40px;
        }
        .loading {
          text-align: center;
          padding: 40px;
          color: #666;
        }
        .error {
          color: #c62828;
          padding: 20px;
          background: #ffebee;
          border-radius: 4px;
        }
      `}</style>
    </div>
  );
}
