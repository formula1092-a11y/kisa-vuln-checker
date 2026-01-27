// Asset types
export type AssetType = 'windows' | 'unix' | 'network' | 'database' | 'web' | 'other';
export type Environment = 'production' | 'staging' | 'development' | 'test';
export type Criticality = 'critical' | 'high' | 'medium' | 'low';

export interface Asset {
  id: number;
  name: string;
  asset_type: AssetType;
  owner: string | null;
  environment: Environment;
  criticality: Criticality;
  ip_address: string | null;
  hostname: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
  assessment_count?: number;
  pass_count?: number;
  fail_count?: number;
}

export interface AssetCreate {
  name: string;
  asset_type: AssetType;
  owner?: string;
  environment?: Environment;
  criticality?: Criticality;
  ip_address?: string;
  hostname?: string;
  notes?: string;
}

// Checklist types
export type Severity = 'high' | 'medium' | 'low';

export interface ChecklistItem {
  id: number;
  item_code: string;
  asset_type: string;
  category: string | null;
  subcategory: string | null;
  title: string;
  description: string | null;
  check_method: string | null;
  pass_criteria: string | null;
  fail_criteria: string | null;
  severity: Severity;
  remediation: string | null;
  reference: string | null;
}

// Assessment types
export type AssessmentStatus = 'not_assessed' | 'pass' | 'fail' | 'na' | 'exception';

export interface Assessment {
  id: number;
  asset_id: number;
  checklist_item_id: number;
  status: AssessmentStatus;
  evidence_paths: string[];
  evidence_note: string | null;
  check_command: string | null;
  remediation_command: string | null;
  assessor: string | null;
  remediation_plan: string | null;
  due_date: string | null;
  created_at: string;
  updated_at: string;
  checklist_item?: ChecklistItem;
  exception_approval?: ExceptionApproval;
}

export interface AssessmentUpdate {
  status?: AssessmentStatus;
  evidence_note?: string;
  assessor?: string;
  remediation_plan?: string;
  due_date?: string;
}

// Exception types
export type ApprovalStatus = 'pending' | 'approved' | 'rejected';

export interface ExceptionApproval {
  id: number;
  assessment_id: number;
  reason: string;
  requested_by: string;
  approver: string | null;
  status: ApprovalStatus;
  expires_at: string | null;
  decided_at: string | null;
  decision_note: string | null;
  created_at: string;
}

export interface ExceptionWithAssessment extends ExceptionApproval {
  asset_id?: number;
  asset_name?: string;
  checklist_item_code?: string;
  checklist_item_title?: string;
}

export interface ExceptionCreate {
  assessment_id: number;
  reason: string;
  expires_at?: string;
}

export interface ExceptionDecision {
  status: 'approved' | 'rejected';
  decision_note?: string;
}

// Report types
export interface AssetSummary {
  asset_id: number;
  asset_name: string;
  asset_type: string;
  total_items: number;
  passed: number;
  failed: number;
  na: number;
  exceptions: number;
  not_assessed: number;
  compliance_rate: number;
}

export interface ReportSummary {
  generated_at: string;
  total_assets: number;
  total_items_checked: number;
  overall_compliance_rate: number;
  asset_summaries: AssetSummary[];
  vulnerable_items: VulnerableItem[];
  exception_items: ExceptionItem[];
}

export interface VulnerableItem {
  asset_name: string;
  item_code: string;
  title: string;
  severity: string;
  assessor: string | null;
  due_date: string | null;
  remediation_plan: string | null;
}

export interface ExceptionItem {
  asset_name: string;
  item_code: string;
  title: string;
  reason: string;
  requested_by: string;
  approver: string | null;
  status: string;
  expires_at: string | null;
}

// Auth types
export interface LoginRequest {
  username: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  username: string;
  role: string;
}

export interface User {
  username: string;
  role: string;
}

// User management types
export type UserRole = 'admin' | 'auditor' | 'user';

export interface UserProfile {
  id: number;
  username: string;
  email: string | null;
  full_name: string | null;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_login: string | null;
}

export interface UserCreate {
  username: string;
  password: string;
  email?: string;
  full_name?: string;
  role?: UserRole;
}

export interface UserUpdate {
  email?: string;
  full_name?: string;
  role?: UserRole;
  is_active?: boolean;
}

export interface PasswordChange {
  current_password: string;
  new_password: string;
}

export interface PasswordReset {
  new_password: string;
}

// List response types
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
}
