export type NavigationTab =
  | 'overview'
  | 'traffic'
  | 'threats'
  | 'alerts'
  | 'incidents'
  | 'rules'
  | 'replay'
  | 'reports';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type IncidentStatusType =
  | 'OPEN'
  | 'ACKNOWLEDGED'
  | 'INVESTIGATING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'FALSE_POSITIVE'
  | 'UNREVIEWED'
  | 'CONFIRMED'
  | 'MITIGATED'
  | 'DISMISSED';

export interface RelatedAlertItem {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: SeverityLevel;
  confidence: number;
  source_ip: string;
  destination_ip: string;
  evidence: string;
  timestamp: string;
}

export interface CyberIncident {
  id: string;
  alert_id?: string;
  title: string;
  severity: SeverityLevel;
  status: IncidentStatusType;
  source_ip: string;
  target_asset: string;
  attack_vector: string;
  confidence: number;
  risk_score: number;
  summary?: string;
  assigned_to?: string;
  rule_ids?: string[];
  alert_count?: number;
  evidence_summary?: string;
  related_alerts?: RelatedAlertItem[];
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
}


export interface AnomalyEvent {
  id: string;
  severity: SeverityLevel;
  event: string;
  ip: string;
  asset: string;
  timestamp: string;
  status: 'UNREVIEWED' | 'CONFIRMED' | 'MITIGATED' | 'DISMISSED';
  confidence: number;
  payloadSnippet: string;
  geoOrigin: string;
  cveId?: string;
  attackVector?: string;
}

export interface TrafficPoint {
  time: string;
  throughputGbps: number;
  activeFlows: number;
  threatRequests: number;
  synPackets: number;
}

export interface SecurityRule {
  id: string;
  name: string;
  pattern: string;
  action: 'BLOCK' | 'RATE_LIMIT' | 'CHALLENGE' | 'LOG';
  status: 'ACTIVE' | 'PAUSED';
  matchesCount: number;
  priority: number;
  category: string;
  lastTriggered: string;
}

export interface ThreatVector {
  origin: string;
  target: string;
  originCode: string;
  targetCode: string;
  riskScore: number;
  riskLabel: string;
  attackType: string;
  isIsolated: boolean;
}

export interface Operator {
  id: string;
  name: string;
  role: string;
  initials: string;
  avatarColor: string;
  shift: string;
}

export interface ChatMessage {
  id: string;
  sender: 'bot' | 'user';
  text: string;
  timestamp: string;
  confidence?: number;
}
