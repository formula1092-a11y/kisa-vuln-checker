import { useState, useRef } from 'react';

interface UploadResult {
  success: boolean;
  asset_id: number;
  processed: number;
  created: number;
  updated: number;
  errors: string[];
}

function UploadPage() {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<UploadResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      if (!selectedFile.name.endsWith('.json')) {
        setError('JSON 파일만 업로드 가능합니다.');
        setFile(null);
        return;
      }
      setFile(selectedFile);
      setError(null);
      setResult(null);
    }
  };

  const handleUpload = async () => {
    if (!file) return;

    setUploading(true);
    setError(null);
    setResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/agent/upload', {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Upload failed');
      }

      setResult(data);
      setFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) {
      if (!droppedFile.name.endsWith('.json')) {
        setError('JSON 파일만 업로드 가능합니다.');
        return;
      }
      setFile(droppedFile);
      setError(null);
      setResult(null);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Report Upload</h1>
        <p>에이전트가 생성한 JSON 파일을 업로드하여 점검 결과를 등록합니다.</p>
      </div>

      <div className="upload-section">
        <div
          className="upload-dropzone"
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onClick={() => fileInputRef.current?.click()}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            accept=".json"
            style={{ display: 'none' }}
          />
          <div className="dropzone-content">
            <div className="dropzone-icon">📁</div>
            <p>클릭하거나 파일을 드래그하여 업로드</p>
            <p className="dropzone-hint">kisa-report.json 파일</p>
          </div>
        </div>

        {file && (
          <div className="selected-file">
            <span className="file-name">{file.name}</span>
            <span className="file-size">({(file.size / 1024).toFixed(1)} KB)</span>
          </div>
        )}

        {error && (
          <div className="upload-error">
            {error}
          </div>
        )}

        <button
          className="btn btn-primary upload-btn"
          onClick={handleUpload}
          disabled={!file || uploading}
        >
          {uploading ? 'Uploading...' : 'Upload'}
        </button>

        {result && (
          <div className={`upload-result ${result.success ? 'success' : 'warning'}`}>
            <h3>{result.success ? 'Upload Success' : 'Upload Completed with Warnings'}</h3>
            <div className="result-details">
              <div className="result-item">
                <span className="label">Asset ID:</span>
                <span className="value">{result.asset_id}</span>
              </div>
              <div className="result-item">
                <span className="label">Processed:</span>
                <span className="value">{result.processed}</span>
              </div>
              <div className="result-item">
                <span className="label">Created:</span>
                <span className="value">{result.created}</span>
              </div>
              <div className="result-item">
                <span className="label">Updated:</span>
                <span className="value">{result.updated}</span>
              </div>
            </div>
            {result.errors.length > 0 && (
              <div className="result-errors">
                <h4>Errors:</h4>
                <ul>
                  {result.errors.map((err, idx) => (
                    <li key={idx}>{err}</li>
                  ))}
                </ul>
              </div>
            )}
            <a href={`/assets/${result.asset_id}`} className="btn btn-secondary">
              View Asset
            </a>
          </div>
        )}
      </div>

      <div className="upload-help">
        <h3>사용 방법</h3>
        <ol>
          <li>
            원격 서버에서 에이전트 스크립트 실행:
            <code>powershell -ExecutionPolicy Bypass -File .\check-windows.ps1 -ServerUrl "http://서버IP:8000" -AssetName "서버명"</code>
          </li>
          <li>
            네트워크 연결 실패 시 생성된 JSON 파일 위치:
            <code>C:\Users\사용자\AppData\Local\Temp\kisa-report.json</code>
          </li>
          <li>해당 파일을 이 페이지에서 업로드</li>
        </ol>
      </div>
    </div>
  );
}

export default UploadPage;
