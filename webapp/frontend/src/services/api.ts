import axios, { AxiosError } from 'axios';
import type {
  Asset, AssetCreate, Assessment, AssessmentUpdate,
  ChecklistItem, ExceptionWithAssessment, ExceptionCreate, ExceptionDecision,
  ReportSummary, LoginRequest, TokenResponse, PaginatedResponse
} from '../types';

const API_BASE = '/api';

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor to handle auth errors
api.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Auth API
export const authApi = {
  login: async (data: LoginRequest): Promise<TokenResponse> => {
    const response = await api.post<TokenResponse>('/auth/login', data);
    return response.data;
  },
  me: async () => {
    const response = await api.get('/auth/me');
    return response.data;
  },
};

// Assets API
export const assetsApi = {
  list: async (params?: { page?: number; size?: number; asset_type?: string; search?: string }): Promise<PaginatedResponse<Asset>> => {
    const response = await api.get<PaginatedResponse<Asset>>('/assets', { params });
    return response.data;
  },
  get: async (id: number): Promise<Asset> => {
    const response = await api.get<Asset>(`/assets/${id}`);
    return response.data;
  },
  create: async (data: AssetCreate): Promise<Asset> => {
    const response = await api.post<Asset>('/assets', data);
    return response.data;
  },
  update: async (id: number, data: Partial<AssetCreate>): Promise<Asset> => {
    const response = await api.put<Asset>(`/assets/${id}`, data);
    return response.data;
  },
  delete: async (id: number): Promise<void> => {
    await api.delete(`/assets/${id}`);
  },
  initializeAssessments: async (id: number): Promise<{ message: string; total_items: number }> => {
    const response = await api.post(`/assets/${id}/initialize-assessments`);
    return response.data;
  },
  downloadRemediationScript: async (id: number): Promise<Blob> => {
    const response = await api.get(`/assets/${id}/remediation-script`, {
      responseType: 'blob',
    });
    return response.data;
  },
};

// Checklist API
export const checklistApi = {
  list: async (params?: { asset_type?: string; severity?: string; search?: string }): Promise<ChecklistItem[]> => {
    const response = await api.get<ChecklistItem[]>('/checklist', { params });
    return response.data;
  },
  get: async (id: number): Promise<ChecklistItem> => {
    const response = await api.get<ChecklistItem>(`/checklist/${id}`);
    return response.data;
  },
  importCsv: async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await api.post('/checklist/import/csv', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  },
  importJson: async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await api.post('/checklist/import/json', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  },
};

// Assessments API
export const assessmentsApi = {
  list: async (params?: { asset_id?: number; status_filter?: string }): Promise<Assessment[]> => {
    const response = await api.get<Assessment[]>('/assessments', { params });
    return response.data;
  },
  get: async (id: number): Promise<Assessment> => {
    const response = await api.get<Assessment>(`/assessments/${id}`);
    return response.data;
  },
  update: async (id: number, data: AssessmentUpdate): Promise<Assessment> => {
    const response = await api.put<Assessment>(`/assessments/${id}`, data);
    return response.data;
  },
  uploadEvidence: async (id: number, file: File): Promise<Assessment> => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await api.post<Assessment>(`/assessments/${id}/evidence`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  },
  deleteEvidence: async (id: number, index: number): Promise<void> => {
    await api.delete(`/assessments/${id}/evidence/${index}`);
  },
  downloadEvidence: (id: number, index: number): string => {
    const token = localStorage.getItem('token');
    return `${API_BASE}/assessments/${id}/evidence/${index}?token=${token}`;
  },
};

// Exceptions API
export const exceptionsApi = {
  list: async (params?: { status_filter?: string }): Promise<ExceptionWithAssessment[]> => {
    const response = await api.get<ExceptionWithAssessment[]>('/exceptions', { params });
    return response.data;
  },
  get: async (id: number): Promise<ExceptionWithAssessment> => {
    const response = await api.get<ExceptionWithAssessment>(`/exceptions/${id}`);
    return response.data;
  },
  create: async (data: ExceptionCreate): Promise<ExceptionWithAssessment> => {
    const response = await api.post<ExceptionWithAssessment>('/exceptions', data);
    return response.data;
  },
  decide: async (id: number, data: ExceptionDecision): Promise<ExceptionWithAssessment> => {
    const response = await api.put<ExceptionWithAssessment>(`/exceptions/${id}/decide`, data);
    return response.data;
  },
  delete: async (id: number): Promise<void> => {
    await api.delete(`/exceptions/${id}`);
  },
};

// Reports API
export const reportsApi = {
  getSummary: async (params?: { asset_id?: number }): Promise<ReportSummary> => {
    const response = await api.get<ReportSummary>('/reports/summary', { params });
    return response.data;
  },
  downloadPdf: async (params?: { asset_id?: number }): Promise<Blob> => {
    const response = await api.get('/reports/pdf', {
      params,
      responseType: 'blob',
    });
    return response.data;
  },
  downloadCsv: async (params?: { asset_id?: number }): Promise<Blob> => {
    const response = await api.get('/reports/csv', {
      params,
      responseType: 'blob',
    });
    return response.data;
  },
};

export default api;
