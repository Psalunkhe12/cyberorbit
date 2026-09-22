export type NavigationTab =
  | 'overview'
  | 'traffic'
  | 'threats'
  | 'alerts'
  | 'rules'
  | 'replay'
  | 'reports';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

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
