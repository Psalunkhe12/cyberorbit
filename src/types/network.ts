export interface NetworkEvent {
    id: string;
    timestamp: string;

    source_ip: string | null;
    source_port: number | null;

    destination_ip: string | null;
    destination_port: number | null;

    protocol: string | null;

    event_type: string | null;

    bytes_in: number;
    bytes_out: number;

    packets_in: number;
    packets_out: number;

    duration: number | null;

    application: string | null;

    source: string | null;

    raw_event: Record<string, unknown> | null;

    created_at: string;
}

export interface TrafficMetric {
    id: string;
    timestamp: string;

    throughput_mbps: number;
    packets_per_second: number;

    active_connections: number;

    inbound_bytes: number;
    outbound_bytes: number;

    inbound_packets: number;
    outbound_packets: number;

    threat_count: number;

    source: string | null;

    created_at: string;
}