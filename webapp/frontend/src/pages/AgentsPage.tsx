import { useState, useEffect } from 'react';
import api from '../services/api';

interface Agent {
  id: string;
  name: string;
  filename: string;
  platform: string;
  description: string;
  usage: string;
  requirements: string;
}

function AgentsPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [viewContent, setViewContent] = useState<{ agent: Agent; content: string } | null>(null);

  useEffect(() => {
    fetchAgents();
  }, []);

  const fetchAgents = async () => {
    try {
      const response = await api.get('/downloads/agents');
      setAgents(response.data.agents);
    } catch (error) {
      console.error('Failed to fetch agents:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (agent: Agent) => {
    try {
      const response = await api.get(`/downloads/agents/${agent.id}`, {
        responseType: 'blob',
      });

      const blob = new Blob([response.data]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = agent.filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Failed to download agent:', error);
      alert('다운로드에 실패했습니다.');
    }
  };

  const handleView = async (agent: Agent) => {
    try {
      const response = await api.get(`/downloads/agents/${agent.id}/view`);
      setViewContent({ agent, content: response.data });
    } catch (error) {
      console.error('Failed to view agent:', error);
      alert('스크립트 조회에 실패했습니다.');
    }
  };

  const closeView = () => {
    setViewContent(null);
  };

  if (loading) {
    return <div className="loading">Loading...</div>;
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Agent Downloads</h1>
        <p>취약점 점검 에이전트 스크립트를 다운로드하세요.</p>
      </div>

      <div className="agents-grid">
        {agents.length === 0 ? (
          <div className="empty-state">
            <p>사용 가능한 에이전트가 없습니다.</p>
          </div>
        ) : (
          agents.map((agent) => (
            <div key={agent.id} className="agent-card">
              <div className="agent-header">
                <div className="agent-icon">
                  {agent.platform === 'Windows' ? '🪟' : '🐧'}
                </div>
                <div>
                  <h3>{agent.name}</h3>
                  <span className="platform-badge">{agent.platform}</span>
                </div>
              </div>

              <p className="agent-description">{agent.description}</p>

              <div className="agent-details">
                <div className="detail-item">
                  <strong>Filename:</strong>
                  <code>{agent.filename}</code>
                </div>
                <div className="detail-item">
                  <strong>Requirements:</strong>
                  <span>{agent.requirements}</span>
                </div>
                <div className="detail-item">
                  <strong>Usage:</strong>
                  <code className="usage-code">{agent.usage}</code>
                </div>
              </div>

              <div className="agent-actions">
                <button
                  className="btn btn-primary"
                  onClick={() => handleDownload(agent)}
                >
                  Download
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={() => handleView(agent)}
                >
                  View Script
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="info-section">
        <h2>Usage Guide</h2>
        <div className="usage-guide">
          <div className="guide-item">
            <h4>Windows Server</h4>
            <ol>
              <li>PowerShell을 관리자 권한으로 실행</li>
              <li>스크립트 실행 정책 설정: <code>Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass</code></li>
              <li>스크립트 실행: <code>.\check-windows.ps1 -ServerUrl "http://SERVER:8000" -AssetName "MyServer"</code></li>
            </ol>
          </div>
          <div className="guide-item">
            <h4>Linux/Unix Server</h4>
            <ol>
              <li>스크립트에 실행 권한 부여: <code>chmod +x check-unix.sh</code></li>
              <li>root 권한으로 실행: <code>sudo ./check-unix.sh -s "http://SERVER:8000" -n "MyServer"</code></li>
            </ol>
          </div>
        </div>
      </div>

      {viewContent && (
        <div className="modal-overlay" onClick={closeView}>
          <div className="modal-content script-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{viewContent.agent.filename}</h3>
              <button className="close-btn" onClick={closeView}>&times;</button>
            </div>
            <div className="script-content">
              <pre><code>{viewContent.content}</code></pre>
            </div>
            <div className="modal-footer">
              <button className="btn btn-primary" onClick={() => handleDownload(viewContent.agent)}>
                Download
              </button>
              <button className="btn btn-secondary" onClick={closeView}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      <style>{`
        .agents-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
          gap: 1.5rem;
          margin-bottom: 2rem;
        }

        .agent-card {
          background: white;
          border-radius: 8px;
          padding: 1.5rem;
          box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .agent-header {
          display: flex;
          align-items: center;
          gap: 1rem;
          margin-bottom: 1rem;
        }

        .agent-icon {
          font-size: 2.5rem;
        }

        .agent-header h3 {
          margin: 0 0 0.25rem 0;
        }

        .platform-badge {
          display: inline-block;
          background: #e3f2fd;
          color: #1976d2;
          padding: 0.25rem 0.5rem;
          border-radius: 4px;
          font-size: 0.75rem;
          font-weight: 500;
        }

        .agent-description {
          color: #666;
          margin-bottom: 1rem;
        }

        .agent-details {
          background: #f5f5f5;
          border-radius: 4px;
          padding: 1rem;
          margin-bottom: 1rem;
        }

        .detail-item {
          margin-bottom: 0.5rem;
        }

        .detail-item:last-child {
          margin-bottom: 0;
        }

        .detail-item strong {
          display: inline-block;
          width: 100px;
          color: #333;
        }

        .detail-item code {
          background: #e0e0e0;
          padding: 0.125rem 0.375rem;
          border-radius: 3px;
          font-size: 0.85rem;
        }

        .usage-code {
          display: block;
          margin-top: 0.25rem;
          word-break: break-all;
        }

        .agent-actions {
          display: flex;
          gap: 0.5rem;
        }

        .info-section {
          background: white;
          border-radius: 8px;
          padding: 1.5rem;
          box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .info-section h2 {
          margin-top: 0;
          margin-bottom: 1rem;
        }

        .usage-guide {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          gap: 1.5rem;
        }

        .guide-item {
          background: #f5f5f5;
          border-radius: 4px;
          padding: 1rem;
        }

        .guide-item h4 {
          margin-top: 0;
          margin-bottom: 0.75rem;
          color: #333;
        }

        .guide-item ol {
          margin: 0;
          padding-left: 1.25rem;
        }

        .guide-item li {
          margin-bottom: 0.5rem;
        }

        .guide-item code {
          background: #e0e0e0;
          padding: 0.125rem 0.375rem;
          border-radius: 3px;
          font-size: 0.85rem;
          word-break: break-all;
        }

        .modal-overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0, 0, 0, 0.5);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1000;
        }

        .script-modal {
          width: 90%;
          max-width: 900px;
          max-height: 80vh;
          background: white;
          border-radius: 8px;
          display: flex;
          flex-direction: column;
        }

        .modal-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 1rem 1.5rem;
          border-bottom: 1px solid #eee;
        }

        .modal-header h3 {
          margin: 0;
        }

        .close-btn {
          background: none;
          border: none;
          font-size: 1.5rem;
          cursor: pointer;
          color: #666;
        }

        .script-content {
          flex: 1;
          overflow: auto;
          padding: 1rem;
          background: #1e1e1e;
        }

        .script-content pre {
          margin: 0;
        }

        .script-content code {
          color: #d4d4d4;
          font-family: 'Consolas', 'Monaco', monospace;
          font-size: 0.85rem;
          white-space: pre;
        }

        .modal-footer {
          display: flex;
          justify-content: flex-end;
          gap: 0.5rem;
          padding: 1rem 1.5rem;
          border-top: 1px solid #eee;
        }

        .empty-state {
          grid-column: 1 / -1;
          text-align: center;
          padding: 3rem;
          color: #666;
        }
      `}</style>
    </div>
  );
}

export default AgentsPage;
