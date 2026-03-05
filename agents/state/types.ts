/**
 * Pipeline State Types
 * 
 * These types are used by the node functions. The actual LangGraph state
 * uses Annotations but these provide the interface for node implementations.
 */

// Technique extracted from threat intel
export interface Technique {
  id: string;
  name: string;
  tactic: string;
  confidence: number;
  context: string;
}

// Coverage gap identified
export interface Gap {
  technique_id: string;
  technique_name: string;
  priority: 'high' | 'medium' | 'low';
  reason: string;
  data_source_available: boolean;
  existing_coverage?: number;
}

// Detection created
export interface Detection {
  id: string;
  name: string;
  technique_id: string;
  file_path: string;
  status: 'draft' | 'validated' | 'failed';
  search?: string;
  data_source?: string[];
  security_domain?: string;
  asset_type?: string;
  validation_result?: {
    passed: boolean;
    event_count: number;
    error?: string;
  };
  qa_status?: 'pass' | 'fail' | 'needs_improvement';
  qa_issues?: string[];
  fp_risk?: 'low' | 'medium' | 'high' | 'critical';
  fp_recommendations?: string[];
}

// Atomic test executed
export interface AtomicTest {
  technique_id: string;
  test_name: string;
  execution_status: 'pending' | 'running' | 'completed' | 'failed';
  output?: string;
  error?: string;
}

// PR staged
export interface PR {
  repo: string;
  url?: string;
  number?: number;
  status: 'draft' | 'staged' | 'merged' | 'failed' | 'pending';
  branch?: string;
  is_draft?: boolean;
}

// Full pipeline state
export interface PipelineState {
  input_type: 'threat_report' | 'technique' | 'cisa_alert' | 'manual';
  input_content: string;
  input_url?: string;
  techniques: Technique[];
  gaps: Gap[];
  detections: Detection[];
  atomic_tests: AtomicTest[];
  attack_data_paths: string[];
  prs: PR[];
  workflow_id: string;
  current_step: string;
  errors: string[];
  warnings: string[];
  started_at: string;
  completed_at?: string;
  requires_approval: boolean;
  approval_reason?: string;
  approved?: boolean;
}
