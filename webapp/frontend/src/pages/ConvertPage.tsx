import { useState, useRef } from 'react';
import api from '../services/api';

interface PreviewResult {
  filename: string;
  total_items: number;
  windows_items: number;
  unix_items: number;
  windows_codes: string[];
  unix_codes: string[];
}

export default function ConvertPage() {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<PreviewResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [converting, setConverting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [target, setTarget] = useState<'all' | 'windows' | 'unix'>('all');
  const [selectedCodes, setSelectedCodes] = useState<string[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (!selectedFile) return;

    if (!selectedFile.name.toLowerCase().endsWith('.pdf')) {
      setError('PDF 파일만 업로드 가능합니다.');
      return;
    }

    setFile(selectedFile);
    setError(null);
    setPreview(null);
    setSelectedCodes([]);

    // Preview PDF contents
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const response = await api.post<PreviewResult>('/convert/pdf/preview', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });

      setPreview(response.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'PDF 미리보기 실패');
    } finally {
      setLoading(false);
    }
  };

  const handleConvert = async () => {
    if (!file) return;

    setConverting(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const params = new URLSearchParams();
      params.set('target', target);
      if (selectedCodes.length > 0) {
        params.set('codes', selectedCodes.join(','));
      }

      const response = await api.post(`/convert/pdf?${params}`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        responseType: 'blob',
      });

      // Download CSV
      const blob = new Blob([response.data], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;

      // Get filename from header or generate
      const contentDisposition = response.headers['content-disposition'];
      let filename = 'vuln_checklist.csv';
      if (contentDisposition) {
        const match = contentDisposition.match(/filename=(.+)/);
        if (match) filename = match[1];
      }

      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      // Get items count from header
      const itemsCount = response.headers['x-items-count'];
      alert(`변환 완료! ${itemsCount || ''}개 항목이 CSV로 저장되었습니다.`);
    } catch (err: any) {
      if (err.response?.data instanceof Blob) {
        const text = await err.response.data.text();
        try {
          const json = JSON.parse(text);
          setError(json.detail || '변환 실패');
        } catch {
          setError('변환 실패');
        }
      } else {
        setError(err.response?.data?.detail || '변환 실패');
      }
    } finally {
      setConverting(false);
    }
  };

  const toggleCode = (code: string) => {
    setSelectedCodes((prev) =>
      prev.includes(code) ? prev.filter((c) => c !== code) : [...prev, code]
    );
  };

  const selectAllCodes = (type: 'windows' | 'unix') => {
    if (!preview) return;
    const codes = type === 'windows' ? preview.windows_codes : preview.unix_codes;
    setSelectedCodes((prev) => {
      const newCodes = new Set(prev);
      codes.forEach((c) => newCodes.add(c));
      return Array.from(newCodes);
    });
  };

  const clearCodes = (type: 'windows' | 'unix') => {
    if (!preview) return;
    const codes = type === 'windows' ? preview.windows_codes : preview.unix_codes;
    setSelectedCodes((prev) => prev.filter((c) => !codes.includes(c)));
  };

  const reset = () => {
    setFile(null);
    setPreview(null);
    setError(null);
    setSelectedCodes([]);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className="convert-page">
      <div className="page-header">
        <h1>PDF to CSV Converter</h1>
        <p className="subtitle">
          KISA 취약점 점검 가이드 PDF를 CSV로 변환합니다.
        </p>
      </div>

      {/* Upload Section */}
      <div className="upload-section">
        <div
          className={`dropzone ${file ? 'has-file' : ''}`}
          onClick={() => fileInputRef.current?.click()}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".pdf"
            onChange={handleFileSelect}
            style={{ display: 'none' }}
          />
          {file ? (
            <div className="file-info">
              <span className="file-icon">&#128196;</span>
              <span className="file-name">{file.name}</span>
              <span className="file-size">
                ({(file.size / 1024 / 1024).toFixed(2)} MB)
              </span>
              <button
                className="btn-reset"
                onClick={(e) => {
                  e.stopPropagation();
                  reset();
                }}
              >
                X
              </button>
            </div>
          ) : (
            <div className="upload-prompt">
              <span className="upload-icon">&#128228;</span>
              <p>PDF 파일을 클릭하여 선택하거나 드래그하세요</p>
              <p className="hint">KISA 취약점 점검 가이드 PDF</p>
            </div>
          )}
        </div>
      </div>

      {loading && (
        <div className="loading-section">
          <div className="spinner"></div>
          <p>PDF 분석 중...</p>
        </div>
      )}

      {error && <div className="error-message">{error}</div>}

      {/* Preview Section */}
      {preview && (
        <div className="preview-section">
          <h2>PDF 분석 결과</h2>
          <div className="preview-summary">
            <div className="summary-card">
              <span className="summary-value">{preview.total_items}</span>
              <span className="summary-label">전체 항목</span>
            </div>
            <div className="summary-card windows">
              <span className="summary-value">{preview.windows_items}</span>
              <span className="summary-label">Windows</span>
            </div>
            <div className="summary-card unix">
              <span className="summary-value">{preview.unix_items}</span>
              <span className="summary-label">Unix</span>
            </div>
          </div>

          {/* Target Selection */}
          <div className="target-section">
            <h3>변환 대상</h3>
            <div className="target-options">
              <label className={target === 'all' ? 'selected' : ''}>
                <input
                  type="radio"
                  name="target"
                  value="all"
                  checked={target === 'all'}
                  onChange={() => setTarget('all')}
                />
                전체 ({preview.total_items})
              </label>
              <label className={target === 'windows' ? 'selected' : ''}>
                <input
                  type="radio"
                  name="target"
                  value="windows"
                  checked={target === 'windows'}
                  onChange={() => setTarget('windows')}
                />
                Windows ({preview.windows_items})
              </label>
              <label className={target === 'unix' ? 'selected' : ''}>
                <input
                  type="radio"
                  name="target"
                  value="unix"
                  checked={target === 'unix'}
                  onChange={() => setTarget('unix')}
                />
                Unix ({preview.unix_items})
              </label>
            </div>
          </div>

          {/* Item Code Selection */}
          <div className="codes-section">
            <h3>
              항목 선택
              <span className="selected-count">
                ({selectedCodes.length > 0 ? `${selectedCodes.length}개 선택됨` : '전체'})
              </span>
            </h3>

            {preview.windows_items > 0 && (target === 'all' || target === 'windows') && (
              <div className="code-group">
                <div className="code-group-header">
                  <span>Windows ({preview.windows_items})</span>
                  <div className="code-actions">
                    <button onClick={() => selectAllCodes('windows')}>전체 선택</button>
                    <button onClick={() => clearCodes('windows')}>선택 해제</button>
                  </div>
                </div>
                <div className="code-list">
                  {preview.windows_codes.map((code) => (
                    <label
                      key={code}
                      className={`code-item ${selectedCodes.includes(code) ? 'selected' : ''}`}
                    >
                      <input
                        type="checkbox"
                        checked={selectedCodes.includes(code)}
                        onChange={() => toggleCode(code)}
                      />
                      {code}
                    </label>
                  ))}
                </div>
              </div>
            )}

            {preview.unix_items > 0 && (target === 'all' || target === 'unix') && (
              <div className="code-group">
                <div className="code-group-header">
                  <span>Unix ({preview.unix_items})</span>
                  <div className="code-actions">
                    <button onClick={() => selectAllCodes('unix')}>전체 선택</button>
                    <button onClick={() => clearCodes('unix')}>선택 해제</button>
                  </div>
                </div>
                <div className="code-list">
                  {preview.unix_codes.map((code) => (
                    <label
                      key={code}
                      className={`code-item ${selectedCodes.includes(code) ? 'selected' : ''}`}
                    >
                      <input
                        type="checkbox"
                        checked={selectedCodes.includes(code)}
                        onChange={() => toggleCode(code)}
                      />
                      {code}
                    </label>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Convert Button */}
          <div className="convert-action">
            <button
              className="btn-convert"
              onClick={handleConvert}
              disabled={converting}
            >
              {converting ? (
                <>
                  <span className="spinner-sm"></span>
                  변환 중...
                </>
              ) : (
                <>CSV로 변환</>
              )}
            </button>
          </div>
        </div>
      )}

      <style>{`
        .convert-page {
          padding: 20px;
          max-width: 900px;
          margin: 0 auto;
        }
        .page-header {
          margin-bottom: 30px;
        }
        .page-header h1 {
          margin: 0 0 5px 0;
        }
        .subtitle {
          color: #666;
          margin: 0;
        }
        .upload-section {
          margin-bottom: 20px;
        }
        .dropzone {
          border: 2px dashed #ccc;
          border-radius: 8px;
          padding: 40px;
          text-align: center;
          cursor: pointer;
          transition: all 0.2s;
          background: #fafafa;
        }
        .dropzone:hover {
          border-color: #1976d2;
          background: #f0f7ff;
        }
        .dropzone.has-file {
          border-color: #4caf50;
          background: #f1f8e9;
        }
        .upload-icon {
          font-size: 48px;
          display: block;
          margin-bottom: 10px;
        }
        .upload-prompt p {
          margin: 5px 0;
        }
        .hint {
          color: #999;
          font-size: 14px;
        }
        .file-info {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 10px;
        }
        .file-icon {
          font-size: 32px;
        }
        .file-name {
          font-weight: 600;
        }
        .file-size {
          color: #666;
        }
        .btn-reset {
          background: #f44336;
          color: white;
          border: none;
          border-radius: 50%;
          width: 24px;
          height: 24px;
          cursor: pointer;
          font-size: 12px;
        }
        .loading-section {
          text-align: center;
          padding: 40px;
        }
        .spinner {
          width: 40px;
          height: 40px;
          border: 4px solid #f3f3f3;
          border-top: 4px solid #1976d2;
          border-radius: 50%;
          animation: spin 1s linear infinite;
          margin: 0 auto 10px;
        }
        .spinner-sm {
          display: inline-block;
          width: 16px;
          height: 16px;
          border: 2px solid #fff;
          border-top: 2px solid transparent;
          border-radius: 50%;
          animation: spin 1s linear infinite;
          margin-right: 8px;
        }
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        .error-message {
          background: #ffebee;
          color: #c62828;
          padding: 15px;
          border-radius: 4px;
          margin-bottom: 20px;
        }
        .preview-section {
          background: white;
          border-radius: 8px;
          padding: 20px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .preview-section h2 {
          margin: 0 0 20px 0;
        }
        .preview-summary {
          display: flex;
          gap: 15px;
          margin-bottom: 25px;
        }
        .summary-card {
          flex: 1;
          background: #f5f5f5;
          padding: 15px;
          border-radius: 8px;
          text-align: center;
        }
        .summary-card.windows {
          background: #e3f2fd;
        }
        .summary-card.unix {
          background: #fff3e0;
        }
        .summary-value {
          display: block;
          font-size: 32px;
          font-weight: 700;
        }
        .summary-label {
          color: #666;
          font-size: 14px;
        }
        .target-section {
          margin-bottom: 25px;
        }
        .target-section h3 {
          margin: 0 0 10px 0;
          font-size: 16px;
        }
        .target-options {
          display: flex;
          gap: 15px;
        }
        .target-options label {
          padding: 10px 20px;
          border: 1px solid #ddd;
          border-radius: 4px;
          cursor: pointer;
          transition: all 0.2s;
        }
        .target-options label:hover {
          border-color: #1976d2;
        }
        .target-options label.selected {
          background: #e3f2fd;
          border-color: #1976d2;
          color: #1565c0;
        }
        .target-options input {
          margin-right: 8px;
        }
        .codes-section {
          margin-bottom: 25px;
        }
        .codes-section h3 {
          margin: 0 0 15px 0;
          font-size: 16px;
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .selected-count {
          font-weight: normal;
          color: #666;
          font-size: 14px;
        }
        .code-group {
          margin-bottom: 20px;
        }
        .code-group-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 10px;
          font-weight: 600;
        }
        .code-actions {
          display: flex;
          gap: 10px;
        }
        .code-actions button {
          background: none;
          border: 1px solid #ddd;
          padding: 4px 10px;
          border-radius: 4px;
          cursor: pointer;
          font-size: 12px;
        }
        .code-actions button:hover {
          background: #f5f5f5;
        }
        .code-list {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
        }
        .code-item {
          padding: 6px 12px;
          border: 1px solid #ddd;
          border-radius: 4px;
          cursor: pointer;
          font-size: 13px;
          transition: all 0.2s;
        }
        .code-item:hover {
          border-color: #1976d2;
        }
        .code-item.selected {
          background: #e3f2fd;
          border-color: #1976d2;
        }
        .code-item input {
          display: none;
        }
        .convert-action {
          text-align: center;
          padding-top: 20px;
          border-top: 1px solid #eee;
        }
        .btn-convert {
          background: #1976d2;
          color: white;
          border: none;
          padding: 12px 40px;
          border-radius: 4px;
          font-size: 16px;
          font-weight: 600;
          cursor: pointer;
          display: inline-flex;
          align-items: center;
        }
        .btn-convert:hover {
          background: #1565c0;
        }
        .btn-convert:disabled {
          background: #ccc;
          cursor: not-allowed;
        }
      `}</style>
    </div>
  );
}
