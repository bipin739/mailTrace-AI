export type InfrastructureRole =
  | 'earliest_node'
  | 'relay_node'
  | 'indicator_ip'
  | 'dns_resolution'
  | 'unknown';

export interface InfrastructureMapNode {
  id: string;
  ip: string;
  role: InfrastructureRole;
  role_label: string;
  latitude: number;
  longitude: number;
  city?: string;
  region?: string;
  country?: string;
  country_code?: string;
  asn?: string;
  asn_org?: string;
  organization?: string;
  is_earliest: boolean;
  hop_number?: number;
  transmission_order?: number;
  infrastructure_type?: string;
  is_hosting?: boolean;
  is_proxy_vpn_tor?: boolean;
}

export interface InvestigationMapData {
  nodes: InfrastructureMapNode[];
  route_path: [number, number][]; // Sequential coordinates for observed infrastructure route
  earliest_node?: InfrastructureMapNode;
  total_public_ips: number;
  total_geolocated: number;
}
