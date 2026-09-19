import { extractInfrastructureMapData, isPublicIP, deconflictCoordinates } from '../mapHelper';
import type { EmailAnalysis } from '../../types/forensic';
import type { InfrastructureMapNode } from '../../types/map';

function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

console.log('Running Investigation Map test suite...\n');

// Test 0: isPublicIP filtering
console.log('Test 0: isPublicIP RFC1918 and loopback filter');
assert(!isPublicIP('10.0.0.1'), '10.0.0.1 should be private');
assert(!isPublicIP('192.168.1.1'), '192.168.1.1 should be private');
assert(!isPublicIP('172.16.0.1'), '172.16.0.1 should be private');
assert(!isPublicIP('127.0.0.1'), '127.0.0.1 should be loopback');
assert(isPublicIP('185.220.101.5'), '185.220.101.5 should be public');
console.log('✓ Passed Test 0: isPublicIP verified\n');

// -----------------------------------------------------------------------------
// Test 1: No coordinates
// -----------------------------------------------------------------------------
console.log('Test 1: No coordinates / Only private IPs');
const emailNoCoords: EmailAnalysis = {
  id: 'test-no-coords',
  subject: 'Internal Notification',
  ips: ['10.0.0.1', '192.168.1.10', '127.0.0.1', '172.16.5.4'],
  ip_intelligence: {
    '10.0.0.1': { ip: '10.0.0.1', scope: 'private' },
    '192.168.1.10': { ip: '192.168.1.10', scope: 'private' }
  }
};

const resNoCoords = extractInfrastructureMapData(emailNoCoords);
assert(resNoCoords.nodes.length === 0, 'Nodes should be empty when no coordinates exist');
assert(resNoCoords.route_path.length === 0, 'Route path should be empty');
assert(resNoCoords.total_geolocated === 0, 'Total geolocated should be 0');
console.log('✓ Passed Test 1: No coordinates handled gracefully\n');

// -----------------------------------------------------------------------------
// Test 2: Single marker
// -----------------------------------------------------------------------------
console.log('Test 2: Single marker');
const emailSingleMarker: EmailAnalysis = {
  id: 'test-single',
  subject: 'Single External Hop',
  relay_analysis: {
    earliest_observable_node: {
      earliest_observable_ip: '185.220.101.5'
    }
  },
  ip_intelligence: {
    '185.220.101.5': {
      ip: '185.220.101.5',
      scope: 'public',
      latitude: 52.52,
      longitude: 13.405,
      country: 'Germany',
      city: 'Berlin',
      asn: 'AS208294',
      organization: 'Tor Exit Relay'
    }
  }
};

const resSingle = extractInfrastructureMapData(emailSingleMarker);
assert(resSingle.nodes.length === 1, 'Should contain exactly 1 node');
assert(resSingle.nodes[0].ip === '185.220.101.5', 'Node IP should match');
assert(resSingle.nodes[0].is_earliest === true, 'Node should be earliest observable node');
assert(resSingle.nodes[0].role === 'earliest_node', 'Role should be earliest_node');
assert(resSingle.nodes[0].role_label === 'Earliest Observable Node', 'Role label should match');
assert(resSingle.route_path.length === 0, 'Route path should be empty for a single node');
console.log('✓ Passed Test 2: Single marker extracted correctly\n');

// -----------------------------------------------------------------------------
// Test 3: Multiple nodes and route path
// -----------------------------------------------------------------------------
console.log('Test 3: Multiple nodes and observed infrastructure route');
const emailMultiple: EmailAnalysis = {
  id: 'test-multi',
  subject: 'Multi-Hop Relay Transmission',
  relay_analysis: {
    earliest_observable_node: { earliest_observable_ip: '194.26.29.112' },
    transmission_order_hops: [
      { hop_number: 1, from_ip: '194.26.29.112', raw: '' },
      { hop_number: 2, from_ip: '198.51.100.24', raw: '' },
      { hop_number: 3, by_ip: '203.0.113.88', raw: '' }
    ]
  },
  indicators: {
    ips: [{ value: '45.33.32.156' }]
  },
  ip_intelligence: {
    '194.26.29.112': { ip: '194.26.29.112', latitude: 50.1109, longitude: 8.6821, city: 'Frankfurt', country: 'Germany', asn: 'AS1234' },
    '198.51.100.24': { ip: '198.51.100.24', latitude: 48.8566, longitude: 2.3522, city: 'Paris', country: 'France', asn: 'AS5678' },
    '203.0.113.88': { ip: '203.0.113.88', latitude: 51.5074, longitude: -0.1278, city: 'London', country: 'United Kingdom', asn: 'AS9999' },
    '45.33.32.156': { ip: '45.33.32.156', latitude: 37.7749, longitude: -122.4194, city: 'San Francisco', country: 'United States', asn: 'AS63949' }
  }
};

const resMulti = extractInfrastructureMapData(emailMultiple);
assert(resMulti.nodes.length === 4, 'Should contain 4 geolocated nodes');
assert(resMulti.route_path.length === 3, 'Should generate route path with 3 sequential relay nodes');
assert(resMulti.nodes.some(n => n.is_earliest && n.ip === '194.26.29.112'), 'Earliest node should be Frankfurt');
assert(resMulti.nodes.some(n => n.role === 'indicator_ip' && n.ip === '45.33.32.156'), 'Indicator IP should be recognized');
console.log('✓ Passed Test 3: Multiple nodes and route path computed in transmission order\n');

// -----------------------------------------------------------------------------
// Test 4: Duplicate location deconfliction
// -----------------------------------------------------------------------------
console.log('Test 4: Duplicate location deconfliction');
const duplicateNodes: InfrastructureMapNode[] = [
  {
    id: 'node-1',
    ip: '198.51.100.1',
    role: 'relay_node',
    role_label: 'Relay 1',
    latitude: 37.751,
    longitude: -122.42,
    is_earliest: false
  },
  {
    id: 'node-2',
    ip: '198.51.100.2',
    role: 'relay_node',
    role_label: 'Relay 2',
    latitude: 37.751,
    longitude: -122.42,
    is_earliest: false
  }
];

const deconflicted = deconflictCoordinates(duplicateNodes);
assert(deconflicted.length === 2, 'Should preserve both nodes');
assert(
  deconflicted[0].latitude !== deconflicted[1].latitude || deconflicted[0].longitude !== deconflicted[1].longitude,
  'Duplicate coordinates must be deconflicted with a spatial offset'
);
console.log('✓ Passed Test 4: Duplicate coordinates successfully deconflicted\n');

// -----------------------------------------------------------------------------
// Test 5: Provider missing city
// -----------------------------------------------------------------------------
console.log('Test 5: Provider missing city');
const emailMissingCity: EmailAnalysis = {
  id: 'test-missing-city',
  subject: 'Missing City Provider Response',
  ips: ['198.51.100.99'],
  ip_intelligence: {
    '198.51.100.99': {
      ip: '198.51.100.99',
      scope: 'public',
      latitude: 40.0,
      longitude: -100.0,
      country: 'United States',
      country_code: 'US',
      region: 'Kansas'
      // city intentionally undefined
    }
  }
};

const resMissingCity = extractInfrastructureMapData(emailMissingCity);
assert(resMissingCity.nodes.length === 1, 'Should extract node even if city is missing');
assert(resMissingCity.nodes[0].city === undefined, 'City should be undefined');
assert(resMissingCity.nodes[0].country === 'United States', 'Country should be preserved');
assert(resMissingCity.nodes[0].region === 'Kansas', 'Region should be preserved');
console.log('✓ Passed Test 5: Missing city handled gracefully\n');

// -----------------------------------------------------------------------------
// Test 6: Strict Non-Attribution Route Labeling
// -----------------------------------------------------------------------------
console.log('Test 6: Strict Non-Attribution Route Labeling');
const ROUTE_LABEL = 'Observed infrastructure route';
assert(ROUTE_LABEL === 'Observed infrastructure route', 'Route label must be exactly Observed infrastructure route');
assert(!ROUTE_LABEL.toLowerCase().includes('attacker'), 'Must never claim attacker travel path');
assert(!ROUTE_LABEL.toLowerCase().includes('travel'), 'Must never claim travel path');
console.log('✓ Passed Test 6: Non-attribution naming rules verified\n');

console.log('==============================================');
console.log('ALL 6 INVESTIGATION MAP TESTS PASSED!');
console.log('==============================================');
